// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! FFI bindings for s2n-tls-metrics-subscriber.
//!
//! Exposes the [`AggregatedMetricsSubscriber`] with an async Kinesis Data
//! Firehose exporter to C callers.
//!
//! ## Lifecycle
//!
//! ```text
//! 1. s2n_metric_emitter_new        → create the Firehose emitter (starts tokio runtime)
//! 2. s2n_metric_subscriber_new     → create a subscriber bound to one s2n_config
//! 3. s2n_metric_subscriber_attach  → wire the subscriber into an s2n_config
//! 4. (handshakes happen – metrics are collected automatically)
//! 5. s2n_metric_subscriber_finish_record → flush the current aggregation window
//! 6. s2n_metric_subscriber_free    → destroy subscriber
//! 7. s2n_metric_emitter_free       → destroy emitter (flushes remaining records)
//! ```

use std::ffi::c_void;
use std::ptr::NonNull;
use std::slice;

use s2n_tls::connection::Connection;
use s2n_tls::events::{EventSubscriber, HandshakeEvent};
use s2n_tls_metrics_subscriber::{AggregatedMetricsSubscriber, Attribution, FirehoseEmitter};

// ---------------------------------------------------------------------------
// Emitter (Firehose + tokio runtime)
// ---------------------------------------------------------------------------

/// Bundles a tokio runtime with the [`FirehoseEmitter`] so that C callers do
/// not need to manage an async runtime themselves.
struct EmitterHandle {
    /// Kept alive to keep the tokio runtime running for the background Firehose task.
    #[allow(dead_code)]
    runtime: tokio::runtime::Runtime,
    emitter: FirehoseEmitter,
}

/// Create a new Firehose emitter.
///
/// This spins up a tokio multi-thread runtime and initialises the AWS SDK
/// Firehose client.  The returned handle must eventually be freed with
/// [`s2n_metric_emitter_free`].
///
/// Returns `NULL` on failure.
#[unsafe(no_mangle)]
pub extern "C" fn s2n_metric_emitter_new() -> *mut c_void {
    // The multi-thread runtime is required here: its worker threads continue
    // polling spawned tasks (like the background Firehose flusher) even after
    // `block_on` returns.  A current-thread runtime would NOT work because
    // nothing would drive the spawned task after `block_on` completes.
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return std::ptr::null_mut();
    };
    let emitter = runtime.block_on(FirehoseEmitter::initialize());
    let handle = Box::new(EmitterHandle { runtime, emitter });
    Box::into_raw(handle) as *mut c_void
}

/// Free an emitter previously created by [`s2n_metric_emitter_new`].
///
/// This triggers a graceful shutdown: the background Firehose task will flush
/// any buffered records before the runtime is dropped.
///
/// # Safety
/// `emitter` must be a pointer returned by `s2n_metric_emitter_new` and must
/// not have been freed already.  All subscribers sharing this emitter should
/// have been freed (or at least had `finish_record` called) before this.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn s2n_metric_emitter_free(emitter: *mut c_void) {
    if emitter.is_null() {
        return;
    }
    unsafe {
        let handle = Box::from_raw(emitter as *mut EmitterHandle);
        // Drop the emitter first so the background task's mpsc Receiver sees
        // the channel close, then shut down the runtime with a generous timeout
        // so the final flush can complete.
        drop(handle.emitter);
        handle.runtime.shutdown_timeout(std::time::Duration::from_secs(30));
    }
}

// ---------------------------------------------------------------------------
// Subscriber
// ---------------------------------------------------------------------------

type Subscriber = AggregatedMetricsSubscriber<FirehoseEmitter>;

/// Create a new aggregated metric subscriber.
///
/// `service` / `resource` are UTF-8 strings (pointer + length, no NUL
/// terminator required).  `emitter` must be a live handle returned by
/// [`s2n_metric_emitter_new`].
///
/// Returns `NULL` on failure.
///
/// # Safety
/// * `emitter` must be a valid pointer from `s2n_metric_emitter_new`.
/// * `service` and `resource` must point to valid memory of the given lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn s2n_metric_subscriber_new(
    emitter: *mut c_void,
    service: *const u8,
    service_len: usize,
    resource: *const u8,
    resource_len: usize,
) -> *mut c_void {
    if emitter.is_null() || service.is_null() || resource.is_null() {
        return std::ptr::null_mut();
    }

    let (handle, service_str, resource_str) = unsafe {
        let handle = &*(emitter as *const EmitterHandle);
        let service_str =
            match std::str::from_utf8(slice::from_raw_parts(service, service_len)) {
                Ok(s) => s,
                Err(_) => return std::ptr::null_mut(),
            };
        let resource_str =
            match std::str::from_utf8(slice::from_raw_parts(resource, resource_len)) {
                Ok(s) => s,
                Err(_) => return std::ptr::null_mut(),
            };
        (handle, service_str, resource_str)
    };

    let mut attribution = Attribution::default();
    attribution.service = service_str.to_owned();
    attribution.resource = resource_str.to_owned();

    let subscriber = Subscriber::new(attribution, handle.emitter.clone());
    Box::into_raw(Box::new(subscriber)) as *mut c_void
}

/// Free a subscriber previously created by [`s2n_metric_subscriber_new`].
///
/// # Safety
/// `subscriber` must be a pointer returned by `s2n_metric_subscriber_new` and
/// must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn s2n_metric_subscriber_free(subscriber: *mut c_void) {
    if !subscriber.is_null() {
        unsafe {
            drop(Box::from_raw(subscriber as *mut Subscriber));
        }
    }
}

// ---------------------------------------------------------------------------
// Attach subscriber to an s2n_config
// ---------------------------------------------------------------------------

/// The C callback registered with `s2n_config_set_handshake_event`.
///
/// `subscriber_ptr` is the `void *` set via `s2n_config_set_subscriber` and
/// points to a live `Subscriber`.
unsafe extern "C" fn on_handshake_event_cb(
    conn_ptr: *mut s2n_tls_sys::s2n_connection,
    subscriber_ptr: *mut c_void,
    event_ptr: *mut s2n_tls_sys::s2n_event_handshake,
) {
    if conn_ptr.is_null() || subscriber_ptr.is_null() || event_ptr.is_null() {
        return;
    }

    unsafe {
        let subscriber = &*(subscriber_ptr as *const Subscriber);

        // Construct the Rust wrapper types from the raw C pointers.
        //
        // Connection is `struct Connection { connection: NonNull<s2n_connection> }`
        // HandshakeEvent is a newtype around `&s2n_event_handshake`.
        //
        // We construct a Connection that we must NOT drop (it doesn't own the
        // pointer), so we wrap it in ManuallyDrop.
        let conn_nn = NonNull::new_unchecked(conn_ptr);
        let conn = std::mem::ManuallyDrop::new(
            std::mem::transmute::<NonNull<s2n_tls_sys::s2n_connection>, Connection>(conn_nn),
        );
        let event: HandshakeEvent<'_> = std::mem::transmute(&*event_ptr);

        subscriber.on_handshake_event(&conn, &event);
    }
}

/// Attach a metric subscriber to an `s2n_config`.
///
/// This sets the subscriber pointer and the handshake-event callback on the
/// config so that every completed handshake is recorded.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
/// * `config` must be a valid `s2n_config *`.
/// * `subscriber` must be a valid pointer from `s2n_metric_subscriber_new`.
/// * The subscriber must outlive the config.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn s2n_metric_subscriber_attach(
    config: *mut s2n_tls_sys::s2n_config,
    subscriber: *mut c_void,
) -> libc::c_int {
    if config.is_null() || subscriber.is_null() {
        return -1;
    }

    unsafe {
        let rc = s2n_tls_sys::s2n_config_set_subscriber(config, subscriber);
        if rc != 0 {
            return rc;
        }

        s2n_tls_sys::s2n_config_set_handshake_event(config, Some(on_handshake_event_cb))
    }
}

// ---------------------------------------------------------------------------
// Record management
// ---------------------------------------------------------------------------

/// Finish the current aggregation window and export the record.
///
/// This rotates the internal record and sends the completed record to the
/// Firehose exporter.  It blocks until all in-flight updates are drained.
///
/// # Safety
/// `subscriber` must be a valid pointer from `s2n_metric_subscriber_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn s2n_metric_subscriber_finish_record(subscriber: *mut c_void) {
    if subscriber.is_null() {
        return;
    }
    unsafe {
        let sub = &*(subscriber as *const Subscriber);
        sub.finish_record();
    }
}
