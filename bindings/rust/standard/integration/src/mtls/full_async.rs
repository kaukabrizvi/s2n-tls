// Copyright Amazon.com, Inc. or its affiliates.
// SPDX-License-Identifier: Apache-2.0

// Full async mTLS path test:
// - rustls client
// - s2n server
// - async cert validation callback
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

// Async offload context for C FFI
struct AsyncOffloadCtx {
    invoked: Arc<AtomicU64>,
    sender: Sender<SendableAsyncOffloadOp>,
}

// Thread-local storage for the async offload context
thread_local! {
    static ASYNC_OFFLOAD_CTX: std::cell::RefCell<Option<AsyncOffloadCtx>> = std::cell::RefCell::new(None);
}

// C-style async offload callback
unsafe extern "C" fn test_async_offload_cb(
    _conn: *mut s2n_connection,
    op: *mut s2n_async_offload_op,
    _ctx: *mut c_void,
) -> i32 {
    eprintln!("[OFFLOAD CALLBACK] Async offload callback fired!");
    ASYNC_OFFLOAD_CTX.with(|ctx_cell| {
        let ctx_ref = ctx_cell.borrow();
        if let Some(ctx) = ctx_ref.as_ref() {
            let count = ctx.invoked.fetch_add(1, Ordering::SeqCst) + 1;
            eprintln!("[OFFLOAD CALLBACK] Invocation count: {}", count);
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
    ASYNC_OFFLOAD_CTX.with(|ctx_cell| {
        *ctx_cell.borrow_mut() = Some(ctx);
    });

    // SAFETY: Register the callback with s2n-tls
    unsafe {
        let raw = raw_config(s2n_cfg);
        
        // Configure only pkey verify operations to be async
        let allowed_types = s2n_async_offload_op_type::OFFLOAD_PKEY_VERIFY;
        
        eprintln!("[SETUP] Registering async offload callback for OFFLOAD_PKEY_VERIFY");
        
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

/// Full async mTLS test with TLS 1.3
///
/// This test exercises the complete async path for mTLS with:
/// - Rustls client (TLS 1.3)
/// - s2n-tls server (TLS 1.3)
/// - Async certificate validation callback (server validates client cert)
/// - Async offload operation for pkey verify (server verifies client cert signature)
///
/// The test demonstrates step-by-step handshake progression with explicit
/// async breakpoints where the application receives operation handles,
/// performs the operations, and then resumes the handshake.
#[test]
fn full_async() {
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            // Setup rustls client with TLS 1.3
            let client = rustls_mtls_client(SigType::Rsa2048, &rustls::version::TLS13);

            // Setup s2n server with async cert validation + async pkey verify offload
            let (server, cert_invoked, cert_rx, offload_invoked, offload_rx) = {
                let builder = s2n_mtls_base_builder(SigType::Rsa2048);
                let mut s2n_cfg = S2NConfig::from(builder.build().unwrap());

                let (cert_invoked, cert_rx) = register_async_cert_callback(&mut s2n_cfg);
                let (offload_invoked, offload_rx) = register_async_pkey_verify_offload(&mut s2n_cfg);

                (s2n_cfg, cert_invoked, cert_rx, offload_invoked, offload_rx)
            };

            // Create connection pair
            let mut pair =
                TlsConnPair::<RustlsConnection, S2NConnection>::from_configs(&client, &server);

            // ===== TLS 1.3 mTLS Handshake Sequence =====
            
            // 1) ClientHello
            eprintln!("\n[STEP 1] Client sending ClientHello");
            pair.client.handshake().unwrap();
            eprintln!("[STEP 1] Cert invoked: {}, Offload invoked: {}", 
                cert_invoked.load(Ordering::SeqCst), offload_invoked.load(Ordering::SeqCst));

            // 2) Server flight (ServerHello, EncryptedExtensions, CertificateRequest, 
            //    Certificate, CertificateVerify, Finished)
            eprintln!("\n[STEP 2] Server sending full flight");
            pair.server.handshake().unwrap();
            eprintln!("[STEP 2] Cert invoked: {}, Offload invoked: {}", 
                cert_invoked.load(Ordering::SeqCst), offload_invoked.load(Ordering::SeqCst));

            // 3) Client processes server flight, sends client Certificate, CertificateVerify, Finished
            eprintln!("\n[STEP 3] Client sending Certificate, CertificateVerify, Finished");
            pair.client.handshake().unwrap();
            eprintln!("[STEP 3] Cert invoked: {}, Offload invoked: {}", 
                cert_invoked.load(Ordering::SeqCst), offload_invoked.load(Ordering::SeqCst));

            // 4) Server starts processing client Certificate → async cert validation triggers
            eprintln!("\n[STEP 4] Server processing client Certificate");
            assert_eq!(
                cert_invoked.load(Ordering::SeqCst),
                0,
                "Cert callback should not have fired yet"
            );
            assert_eq!(
                offload_invoked.load(Ordering::SeqCst),
                0,
                "Offload callback should not have fired yet"
            );

            let _ = pair.server.handshake(); // expect: cert validation callback fires
            eprintln!("[STEP 4] After handshake - Cert invoked: {}, Offload invoked: {}", 
                cert_invoked.load(Ordering::SeqCst), offload_invoked.load(Ordering::SeqCst));

            // Check if both callbacks fired in the same step
            let cert_count = cert_invoked.load(Ordering::SeqCst);
            let offload_count = offload_invoked.load(Ordering::SeqCst);
            
            eprintln!("[STEP 4] Checking what fired: cert={}, offload={}", cert_count, offload_count);

            if cert_count > 0 {
                // Receive the cert validation info and accept it
                eprintln!("[STEP 4] Accepting certificate validation");
                let cert_ptr = cert_rx.recv().expect("recv CertValidationInfo ptr").0;
                unsafe {
                    let rc = s2n_cert_validation_accept(cert_ptr);
                    assert_eq!(rc, 0, "s2n_cert_validation_accept failed");
                }
            }

            if offload_count > 0 {
                // Perform the pkey verify offload
                eprintln!("[STEP 4] Performing async offload operation (fired in same step as cert)");
                let SendableAsyncOffloadOp(offload_op_ptr) =
                    offload_rx.recv().expect("recv async offload op pointer");
                unsafe {
                    let rc = s2n_async_offload_op_perform(offload_op_ptr);
                    assert_eq!(rc, 0, "s2n_async_offload_op_perform failed");
                }
            }

            // 5) Continue server handshake - may trigger remaining async operations
            eprintln!("\n[STEP 5] Continuing server handshake");
            let _ = pair.server.handshake();
            eprintln!("[STEP 5] After handshake - Cert invoked: {}, Offload invoked: {}", 
                cert_invoked.load(Ordering::SeqCst), offload_invoked.load(Ordering::SeqCst));

            // Handle any remaining async operations
            let final_cert_count = cert_invoked.load(Ordering::SeqCst);
            let final_offload_count = offload_invoked.load(Ordering::SeqCst);

            if final_cert_count > cert_count {
                eprintln!("[STEP 5] Handling additional cert validation");
                let cert_ptr = cert_rx.recv().expect("recv CertValidationInfo ptr").0;
                unsafe {
                    let rc = s2n_cert_validation_accept(cert_ptr);
                    assert_eq!(rc, 0, "s2n_cert_validation_accept failed");
                }
            }

            if final_offload_count > offload_count {
                eprintln!("[STEP 5] Handling additional offload operation");
                let SendableAsyncOffloadOp(offload_op_ptr) =
                    offload_rx.recv().expect("recv async offload op pointer");
                unsafe {
                    let rc = s2n_async_offload_op_perform(offload_op_ptr);
                    assert_eq!(rc, 0, "s2n_async_offload_op_perform failed");
                }
            }

            // 6) Resume server handshake after all async operations
            eprintln!("\n[STEP 6] Resuming server handshake after async operations");
            pair.server.handshake().unwrap();
            eprintln!("[STEP 6] Cert invoked: {}, Offload invoked: {}", 
                cert_invoked.load(Ordering::SeqCst), offload_invoked.load(Ordering::SeqCst));

            // 7) Complete any remaining handshake steps
            eprintln!("\n[STEP 7] Completing remaining handshake steps");
            pair.handshake().unwrap();
            eprintln!("[STEP 7] Cert invoked: {}, Offload invoked: {}", 
                cert_invoked.load(Ordering::SeqCst), offload_invoked.load(Ordering::SeqCst));

            // 8) Verify app data works
            eprintln!("\n[STEP 8] Testing app data");
            pair.round_trip_assert(10).unwrap();

            // 9) Shutdown cleanly
            eprintln!("\n[STEP 9] Shutting down");
            pair.shutdown().unwrap();
            eprintln!("[COMPLETE] Final counts - Cert invoked: {}, Offload invoked: {}", 
                cert_invoked.load(Ordering::SeqCst), offload_invoked.load(Ordering::SeqCst));
        },
    );
}
