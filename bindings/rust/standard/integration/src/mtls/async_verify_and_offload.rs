// Copyright Amazon.com, Inc. or its affiliates.
// SPDX-License-Identifier: Apache-2.0

// mTLS async verify + async offload test:
// - rustls client (TLS 1.3)
// - s2n-tls server (TLS 1.3)
// - async certificate validation callback
// - async offload operation (pkey verify)

use super::*;
use s2n_tls_sys::{
    s2n_async_offload_op, s2n_async_offload_op_perform, s2n_async_offload_op_type,
    s2n_config_set_async_offload_callback,
};
use std::ffi::c_void;

/// A wrapper around a raw pointer to `s2n_async_offload_op` that can be sent across threads.
///
/// This is used in tests to simulate async offload operations where the operation
/// is deferred and performed on a different thread or after some async operation.
struct SendableAsyncOffloadOp(*mut s2n_async_offload_op);

// SAFETY: The pointer is owned by s2n-tls and remains valid for the duration of the
// pending async offload operation (until perform() is called, or freed).
// The test mimics the intended usage pattern where an application hands off the pointer
// to a worker thread that later performs the operation.
unsafe impl Send for SendableAsyncOffloadOp {}

struct AsyncOffloadCtx {
    invoked: Arc<AtomicU64>,
    sender: Sender<SendableAsyncOffloadOp>,
}

// Thread-local storage for the async offload context
thread_local! {
    static ASYNC_OFFLOAD_CTX: std::cell::RefCell<Option<AsyncOffloadCtx>> =
        std::cell::RefCell::new(None);
}

// C-style async offload callback
unsafe extern "C" fn test_async_offload_cb(
    _conn: *mut s2n_connection,
    op: *mut s2n_async_offload_op,
    _ctx: *mut c_void,
) -> i32 {
    ASYNC_OFFLOAD_CTX.with(|ctx_cell| {
        let ctx_ref = ctx_cell.borrow();
        if let Some(ctx) = ctx_ref.as_ref() {
            ctx.invoked.fetch_add(1, Ordering::SeqCst);
            ctx.sender
                .send(SendableAsyncOffloadOp(op))
                .expect("send async offload op");
        }
    });

    s2n_status_code::SUCCESS
}

/// Registers an async pkey verify offload callback and returns (invoked_counter, op_receiver).
fn register_async_pkey_verify_offload(
    s2n_cfg: &mut S2NConfig,
) -> (Arc<AtomicU64>, Receiver<SendableAsyncOffloadOp>) {
    let invoked = Arc::new(AtomicU64::new(0));
    let (tx, rx) = std::sync::mpsc::channel();

    let ctx = AsyncOffloadCtx {
        invoked: Arc::clone(&invoked),
        sender: tx,
    };

    // Store the context in thread-local storage
    ASYNC_OFFLOAD_CTX.with(|cell| {
        *cell.borrow_mut() = Some(ctx);
    });

    // SAFETY: Register the callback with s2n-tls
    unsafe {
        let raw = raw_config(s2n_cfg);
        let allowed_types = s2n_async_offload_op_type::OFFLOAD_PKEY_VERIFY;

        let result = s2n_config_set_async_offload_callback(
            raw,
            allowed_types,
            Some(test_async_offload_cb),
            std::ptr::null_mut(),
        );
        assert_eq!(
            result,
            s2n_status_code::SUCCESS,
            "s2n_config_set_async_offload_callback failed"
        );
    }

    (invoked, rx)
}

/// Drives a full TLS 1.3 mTLS handshake with:
/// - async cert validation (server validating client cert)
/// - async offload for pkey verify (server verifying client CertificateVerify)
fn test_async_verify_and_offload(
    client_cfg: &RustlsConfig,
    server_cfg: &S2NConfig,
    cert_invoked: Arc<AtomicU64>,
    cert_rx: Receiver<SendableCertValidationInfo>,
    offload_invoked: Arc<AtomicU64>,
    offload_rx: Receiver<SendableAsyncOffloadOp>,
) {
    let mut pair =
        TlsConnPair::<RustlsConnection, S2NConnection>::from_configs(client_cfg, server_cfg);

    // 1) ClientHello
    pair.client.handshake().unwrap();

    // 2) Server flight (ServerHello, EncryptedExtensions, CertificateRequest,
    //    Certificate, CertificateVerify, Finished)
    pair.server.handshake().unwrap();

    // 3) Client processes server flight, sends client Certificate, CertificateVerify, Finished
    pair.client.handshake().unwrap();

    // 4) Server processes client Certificate -> async cert validation fires
    assert_eq!(cert_invoked.load(Ordering::SeqCst), 0);
    assert_eq!(offload_invoked.load(Ordering::SeqCst), 0);

    let _ = pair.server.handshake();
    assert_eq!(cert_invoked.load(Ordering::SeqCst), 1);

    // Accept the async cert decision
    let cert_ptr = cert_rx.recv().expect("recv CertValidationInfo ptr").0;
    unsafe {
        let rc = s2n_cert_validation_accept(cert_ptr);
        assert_eq!(rc, 0, "s2n_cert_validation_accept failed");
    }

    // 5) Continue server handshake: async offload for pkey verify fires
    let _ = pair.server.handshake();
    assert_eq!(offload_invoked.load(Ordering::SeqCst), 1);

    // Perform the async pkey verify operation
    let SendableAsyncOffloadOp(offload_op_ptr) =
        offload_rx.recv().expect("recv async offload op pointer");
    unsafe {
        let rc = s2n_async_offload_op_perform(offload_op_ptr);
        assert_eq!(rc, 0, "s2n_async_offload_op_perform failed");
    }

    // 6) Finish handshake + verify data path
    pair.handshake().unwrap();
    pair.round_trip_assert(10).unwrap();
    pair.shutdown().unwrap();
}

// rustls client, s2n server with async cert verify + async pkey verify offload (TLS 1.3 only)
#[test]
fn s2n_server_async_verify_and_offload() {
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let client = rustls_mtls_client(SigType::Rsa2048, &rustls::version::TLS13);

            let (server, cert_invoked, cert_rx, offload_invoked, offload_rx) = {
                let builder = s2n_mtls_base_builder(SigType::Rsa2048);
                let mut s2n_cfg = S2NConfig::from(builder.build().unwrap());

                let (cert_invoked, cert_rx) = register_async_cert_callback(&mut s2n_cfg);
                let (offload_invoked, offload_rx) =
                    register_async_pkey_verify_offload(&mut s2n_cfg);

                (s2n_cfg, cert_invoked, cert_rx, offload_invoked, offload_rx)
            };

            test_async_verify_and_offload(
                &client,
                &server,
                cert_invoked,
                cert_rx,
                offload_invoked,
                offload_rx,
            );
        },
    );
}
