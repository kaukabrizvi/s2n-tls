// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
    mpsc::{self, Receiver, Sender},
};
use std::time::{Duration, Instant};

use crate::{condensed::Attribution, record::{FrozenHandshakeRecord, HandshakeRecordInProgress, MetricRecord}};
use arc_swap::ArcSwap;
use s2n_tls::events::EventSubscriber;

const DEFAULT_EXPORT_INTERVAL: Duration = Duration::from_secs(3600);

/// Monotonic millisecond clock rooted at a process-wide epoch.
///
/// We store deadlines as `u64` milliseconds relative to a fixed [`Instant`] so
/// that the hot-path time check is a single `AtomicU64::load(Relaxed)`.
fn epoch() -> Instant {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn now_ms() -> u64 {
    epoch().elapsed().as_millis() as u64
}

#[derive(Debug)]
struct ExportPipeline<S> {
    metric_receiver: Receiver<FrozenHandshakeRecord>,
    sink: S,
}

/// The AggregatedMetricSubscriber can be used to aggregate events over some period
/// of time, and then export them using an [`TelemetrySink`].
///
/// When an `export_interval` is configured (default: 1 hour), the subscriber
/// will passively flush the current record from within the `on_handshake_event`
/// callback once the interval has elapsed.  No background threads are used —
/// the flush piggybacks on the next handshake after the deadline.
#[derive(Debug, Clone)]
pub struct AggregatedMetricsSubscriber<S> {
    inner: Arc<MetricSubscriberInner<S>>,
}

/// The [`s2n_tls::events::EventSubscriber`] may be invoked concurrently, which
/// means that multiple threads might be incrementing the current record. To handle
/// this and ensure that the `HandshakeRecordInProgress` is never flushed while
/// an update is in progress we use an [`arc_swap::ArcSwap`].
///
/// ArcSwap is basically an `Atomic<Arc<HandshakeRecordInProgress>>`
///
/// We use this as a relatively intuitive form of synchronization. Once there
/// are no references to the HandshakeRecordInProgress (e.g. no threads updating
/// it) then its `drop` implementation will write it to the channel, where it can
/// then be read by the export pipeline.
#[derive(Debug)]
struct MetricSubscriberInner<S> {
    /// This contains information about the item that is producing the metric records
    /// Generally this will have a 1 to 1 correlation with an s2n-tls config
    attribution: Attribution,
    current_record: ArcSwap<HandshakeRecordInProgress>,
    /// This handle is not directly used, but is used when constructing new
    /// HandshakeRecordInProgress items.
    tx_handle: Sender<FrozenHandshakeRecord>,

    // the mutex is necessary because s2n-tls callbacks must be Send + Sync
    export_pipeline: Mutex<ExportPipeline<S>>,

    /// Milliseconds (relative to [`epoch()`]) at which the current aggregation
    /// window expires.  Checked with a `Relaxed` load on every handshake event;
    /// only the thread that wins the `compare_exchange` actually performs the
    /// flush.
    deadline_ms: AtomicU64,
    export_interval: Duration,
}

impl<S: TelemetrySink + Send + Sync> AggregatedMetricsSubscriber<S> {
    pub fn new(attribution: Attribution, sink: S) -> Self {
        Self::new_with_interval(attribution, sink, DEFAULT_EXPORT_INTERVAL)
    }

    pub fn new_with_interval(attribution: Attribution, sink: S, export_interval: Duration) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();

        let record = HandshakeRecordInProgress::new(tx.clone());

        let export_pipe = ExportPipeline {
            metric_receiver: rx,
            sink,
        };
        let deadline_ms = now_ms() + export_interval.as_millis() as u64;
        let inner = MetricSubscriberInner {
            attribution,
            current_record: ArcSwap::new(Arc::new(record)),
            tx_handle: tx,
            export_pipeline: Mutex::new(export_pipe),
            deadline_ms: AtomicU64::new(deadline_ms),
            export_interval,
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Check if the export interval has elapsed and, if so, flush the record.
    ///
    /// Only one thread will win the atomic compare-exchange and perform the
    /// actual flush.  All other concurrent callers observe the updated deadline
    /// and return immediately.
    fn maybe_flush(&self) {
        let now = now_ms();
        let deadline = self.inner.deadline_ms.load(Ordering::Relaxed);
        if now < deadline {
            return;
        }
        // Try to claim the flush.  Exactly one thread succeeds.
        if self.inner.deadline_ms.compare_exchange(
            deadline,
            now + self.inner.export_interval.as_millis() as u64,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ).is_ok() {
            self.finish_record();
        }
    }

    /// Finish aggregation of the record and export it.
    ///
    /// Note that this method will block until all other in-flight updates of the
    /// metric record are complete. This is generally very fast because updates
    /// only consist of atomic integer updates, but latency-sensitive applications
    /// should avoid calling this method in a tokio runtime, and using `spawn_blocking`
    /// instead.
    pub fn finish_record(&self) {
        let export_pipeline = self.inner.export_pipeline.lock().unwrap();
        let new_record = Arc::new(HandshakeRecordInProgress::new(self.inner.tx_handle.clone()));

        let old_record = self.inner.current_record.swap(new_record);
        // On drop, the record will be "frozen" and written to the channel
        // This might not happen immediately because other threads might also hold
        // a reference to the metric record
        drop(old_record);

        // This will block the thread until the record is received.
        let handshake = export_pipeline.metric_receiver.recv().unwrap();
        let mut record = MetricRecord::new(handshake);
        record.set_attribution(self.inner.attribution.clone());
        export_pipeline.sink.sink(record);
    }
}

impl<S: TelemetrySink + Send + Sync + 'static> EventSubscriber for AggregatedMetricsSubscriber<S> {
    fn on_handshake_event(
        &self,
        connection: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        // Flush before loading the current record — this ensures we don't hold
        // an Arc to the old record while finish_record tries to drain it.
        self.maybe_flush();

        let current_record = self.inner.current_record.load_full();
        let res = current_record.update(connection, event);
        // we never expect this to fail, but if it fails in production there is
        // no meaningful way to communicate that failure.
        debug_assert!(res.is_ok());
    }
}

pub trait TelemetrySink {
    /// export a record to some sink.
    ///
    /// This might append it to some background IO (e.g. tracing_subscriber) or
    /// directly buffer content to be further processed (e.g. converted to EMF).
    fn sink(&self, metric_record: MetricRecord);
}

impl TelemetrySink for mpsc::Sender<MetricRecord> {
    fn sink(&self, metric_record: MetricRecord) {
        self.send(metric_record).unwrap()
    }
}

#[cfg(test)]
mod tests {

    use std::sync::mpsc::Receiver;
    use std::time::Duration;

    use s2n_tls::security::DEFAULT_TLS13;
    use s2n_tls::testing::{build_config, config_builder};

    use crate::{
        AggregatedMetricsSubscriber, MetricRecord,
        test_utils::{ARBITRARY_POLICY_1, TEST_ATTRIBUTION, TestEndpoint},
    };

    #[test]
    fn record_is_exported() {
        let endpoint = TestEndpoint::<Receiver<MetricRecord>>::new();
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        assert!(endpoint.exporter.try_recv().is_err());
        endpoint.subscriber.finish_record();
        endpoint.exporter.recv().unwrap();
    }

    /// Ensure that the `finish_record` method won't complete until no other threads
    /// hold a reference to the record-in-progress.
    ///
    /// This test could have a "false negative", e.g. it might succeed even if the
    /// system isn't operating correctly, but this is acceptable given the relative
    /// simplicity of the synchronization, as well as the repeated runs of this
    /// test across CI/development.
    #[test]
    fn export_blocking() {
        let endpoint = TestEndpoint::<Receiver<MetricRecord>>::new();
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        // hold a reference to the current record being updated.
        let current_record = endpoint.subscriber.inner.current_record.load_full();

        let handle = std::thread::spawn(move || {
            endpoint.subscriber.finish_record();
        });

        assert!(!handle.is_finished());
        drop(current_record);
        handle.join().unwrap();
    }

    /// Records are automatically flushed to the sink when the export interval
    /// elapses, triggered passively from the handshake callback.
    #[test]
    fn auto_flush() {
        let (tx, rx) = std::sync::mpsc::channel();
        let subscriber = AggregatedMetricsSubscriber::new_with_interval(
            TEST_ATTRIBUTION.clone(),
            tx,
            Duration::from_millis(1),
        );

        let server_config = {
            let mut config = config_builder(&DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber.clone()).unwrap();
            config.build().unwrap()
        };
        let client_config = build_config(&DEFAULT_TLS13).unwrap();

        // Do a handshake, then sleep past the interval.
        let mut pair = s2n_tls::testing::TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();

        std::thread::sleep(Duration::from_millis(5));

        // This handshake should trigger an auto-flush of the previous window.
        let mut pair = s2n_tls::testing::TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();

        // We never called finish_record(), but the sink should have a record.
        let record = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(record.attribution().unwrap().service, "Testing");
    }
}
