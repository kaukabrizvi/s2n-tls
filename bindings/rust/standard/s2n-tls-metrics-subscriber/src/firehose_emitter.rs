use std::{sync::Arc, time::Duration};

use aws_config::Region;
use aws_sdk_firehose::{Client, primitives::Blob};
use tokio::task::JoinHandle;

use crate::{
    MetricRecord, condensed::Attribution, record::FrozenHandshakeRecord, subscriber::Exporter,
};

/// The FirehoseEmitter is used to enqueue records to be exported to DataFirehose.
/// 
/// Note that [`Exporter::export`] just appends to the queue, and does not actually
/// make the network calls. MetricRecords are batched together and dumped to Firehose
/// once every hour or when shutdown is called.
#[derive(Debug, Clone)]
pub struct FirehoseEmitter {
    handle: Arc<AsyncHandle>,
}

impl FirehoseEmitter {
    pub async fn initialize() -> Self {
        let (emitter, tx) = BackgroundEmitter::initialize().await;
        let handle = AsyncHandle {
            background_exporter: emitter,
            record_buffer: tx,
        };
        Self {
            handle: Arc::new(handle),
        }
    }
}

impl Exporter for FirehoseEmitter {
    fn export(&self, metric_record: MetricRecord) {
        let _ = self.handle.record_buffer.try_send(metric_record);
    }
}

#[derive(Debug)]
struct AsyncHandle {
    /// This is a tokio task responsible for periodically flushing the records to kinesis
    background_exporter: BackgroundEmitter,
    
    record_buffer: tokio::sync::mpsc::Sender<MetricRecord>,
}

#[derive(Debug)]
struct BackgroundEmitter {
    /// sending "true" to this channel will cause the async background emitter
    /// to shutdown
    shutdown_send: tokio::sync::watch::Sender<bool>,
    firehose_task: JoinHandle<()>,
}

impl BackgroundEmitter {
    // const EMIT_FREQUENCY: Duration = Duration::from_hours(1);
    const EMIT_FREQUENCY: Duration = Duration::from_secs(15);
    const CHANNEL_CAPACITY: usize = 1_024;

    pub async fn initialize() -> (Self, tokio::sync::mpsc::Sender<MetricRecord>) {
        let shared_config = aws_config::from_env()
            .region(Region::new("us-west-2"))
            .load()
            .await;

        let client = Client::new(&shared_config);
        let (shutdown_send, mut shutdown_signal) = tokio::sync::watch::channel(false);
        let (record_tx, mut record_rx) = tokio::sync::mpsc::channel(Self::CHANNEL_CAPACITY);
        println!("background emitter about to be launched");
        let firehose_task = tokio::spawn(async move {
            println!("launched firehose taks");
            // not doing jitter rn
            let mut per_hour = tokio::time::interval(Self::EMIT_FREQUENCY);
            let mut shutdown = false;

            loop {
                // check if the last loop had us shutting down
                if shutdown {
                    break;
                }
                // continue when an hour has elapsed or we need to shutdown
                shutdown = tokio::select! {
                    _ = shutdown_signal.changed() => true,
                    _ = per_hour.tick() => false
                };
                println!("finished poll");

                // gather all of the available records from the buffer
                let to_export = {
                    let mut buffer = Vec::new();
                    while let Ok(record) = record_rx.try_recv() {
                        buffer.push(record);
                    }
                    buffer
                };
                if to_export.is_empty() {
                    continue;
                }
                println!("exporting: {to_export:?}");

                let records = to_export
                    .into_iter()
                    .map(|record| {
                        let json = serde_json::to_string(&record).unwrap();
                        let record = aws_sdk_firehose::types::Record::builder()
                            .data(Blob::new(json))
                            .build()
                            .unwrap();
                        record
                    })
                    .collect();

                client
                    .put_record_batch()
                    .delivery_stream_name(
                        "TlsKinesisProtocol-TlsKinesisProtocolStream-hhSb973DLXju",
                    )
                    .set_records(Some(records))
                    .send()
                    .await
                    .unwrap();
            }
        });
        let value = Self {
            shutdown_send,
            firehose_task,
        };
        (value, record_tx)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::Ordering,
        time::{Duration, Instant},
    };

    use crate::{AggregatedMetricsSubscriber, firehose_emitter};

    use super::*;
    use rand::RngExt;
    use s2n_tls::{
        security::{self, DEFAULT, DEFAULT_TLS13, Policy},
        testing::{TestPair, build_config, config_builder},
    };

    // #[test]
    // fn event_emissions() {
    //     let subscriber = TestSubscriber::default();
    //     let invoked = subscriber.invoked.clone();
    //     let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
    //     server_config.set_event_subscriber(subscriber).unwrap();
    //     let server_config = server_config.build().unwrap();

    //     let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     assert_eq!(invoked.load(Ordering::Relaxed), 1);

    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     assert_eq!(invoked.load(Ordering::Relaxed), 2);
    //     assert!(false);
    // }

    // #[test]
    // fn logging_events() {
    //     let subscriber = RollingFileExporter::service_metrics_init();
    //     let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
    //     server_config.set_event_subscriber(subscriber).unwrap();
    //     let server_config = server_config.build().unwrap();

    //     let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();

    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();

    //     assert!(false);
    // }

    // #[tokio::test]
    // async fn cloudwatch_events() {
    //     let subscriber = CloudWatchExporter::initialize().await;
    //     let subscriber_handle = subscriber.clone();
    //     let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
    //     server_config
    //         .set_event_subscriber(subscriber_handle)
    //         .unwrap();
    //     let server_config = server_config.build().unwrap();

    //     let client_configs = [
    //         build_config(&security::DEFAULT_TLS13).unwrap(),
    //         build_config(&security::DEFAULT_TLS13).unwrap(),
    //         build_config(&Policy::from_version("default_pq").unwrap()).unwrap(),
    //     ];

    //     let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     subscriber.try_write().await;

    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     subscriber.try_write().await;

    //     let tls12_client_config = build_config(&security::DEFAULT).unwrap();
    //     let mut test_pair = TestPair::from_configs(&tls12_client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     subscriber.try_write().await;

    //     std::thread::sleep(Duration::from_secs(1));
    //     assert!(false);
    // }

    // #[tokio::test]
    // async fn cloudwatch_emission() {
    //     let config = aws_config::load_from_env().await;
    //     let client = aws_sdk_cloudwatchlogs::Client::new(&config);
    //     client.put_log_events().
    // }

    struct TestEndpoint {
        config: s2n_tls::config::Config,
        subscriber: AggregatedMetricsSubscriber<FirehoseEmitter>,
    }

    impl TestEndpoint {
        async fn initialize(resource: &str, policy: &Policy, emitter: &FirehoseEmitter) -> Self {
            let mut attribution = Attribution::default();
            attribution.service = "LLB/frontend".to_owned();
            attribution.resource = resource.to_owned();
            attribution.certificate = Some(format!("{resource}-cert"));

            let subscriber = AggregatedMetricsSubscriber::new(attribution, emitter.clone());

            let config = {
                let mut config = config_builder(policy).unwrap();
                config.set_event_subscriber(subscriber.clone()).unwrap();
                config.build().unwrap()
            };

            Self {
                config,
                subscriber,
            }
        }

        fn client_handshake(&self, client_policy: &Policy) {
            let client_config = build_config(client_policy).unwrap();
            let mut pair = TestPair::from_configs(&client_config, &self.config);
            pair.handshake();
        }
    }

    // /// Emit EMF records to obtain
    // /// 1. aggregate platform metrics
    // /// 2. with optional resource-level information available through cloudwatch
    // ///    insights.
    // ///
    // /// This results in a single e.g. TLS_AES_128_GCM_SHA256 counter for aggregate
    // /// platform traffic, but per-resource breakdowns can still be accomplished
    // /// through a cloudwatch insights query
    // ///
    // /// https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format.html
    // ///
    // /// LogGroup: GatewayServicesLogs
    // /// LogStream: GatewayService<INSTANCE_ID>
    // ///
    // /// CloudWatch Namespace: tls/s2n-tls
    // /// CloudWatch Dimensions: "application" -> "test_server"
    // ///
    // #[tokio::test]
    // async fn platform_metrics_with_per_resource_visibility() {
    //     // tracing_subscriber::fmt()
    //     //     .with_max_level(tracing::level_filters::LevelFilter::DEBUG)
    //     //     .with_writer(std::io::stderr)
    //     //     .with_ansi(false)
    //     //     .init();

    //     let rsa_kx_policy = Policy::from_version("20150214").unwrap();
    //     let tls12_ecdhe_policy = Policy::from_version("20190214").unwrap();

    //     let mut kitten = TestEndpoint::initialize("kitten", &rsa_kx_policy).await;
    //     let mut puppy = TestEndpoint::initialize("puppy", &DEFAULT).await;
    //     let mut cub = TestEndpoint::initialize("cub", &DEFAULT_TLS13).await;

    //     {
    //         puppy.client_handshake(&DEFAULT);
    //         puppy.client_handshake(&DEFAULT_TLS13);
    //         puppy.client_handshake(&tls12_ecdhe_policy);

    //         puppy.subscriber.finish_record();
    //         let sent = puppy.exporter.try_write().await;
    //         assert!(sent);
    //     }

    //     {
    //         kitten.client_handshake(&rsa_kx_policy);
    //         kitten.client_handshake(&DEFAULT);
    //         kitten.client_handshake(&DEFAULT_TLS13);

    //         kitten.subscriber.finish_record();
    //         let sent = kitten.exporter.try_write().await;
    //         assert!(sent);
    //     }

    //     {
    //         cub.client_handshake(&tls12_ecdhe_policy);
    //         cub.client_handshake(&tls12_ecdhe_policy);
    //         cub.client_handshake(&DEFAULT);

    //         cub.subscriber.finish_record();
    //         let sent = cub.exporter.try_write().await;
    //         assert!(sent);
    //     }
    // }

    #[tokio::test]
    async fn fake_traffic() {
        // tracing_subscriber::fmt()
        //     .with_max_level(tracing::level_filters::LevelFilter::DEBUG)
        //     .with_writer(std::io::stderr)
        //     .with_ansi(false)
        //     .init();

        const FAKE_TRAFFIC_LENGTH: Duration = Duration::from_secs(60 * 5);
        const AGGREGATION: Duration = Duration::from_secs(1);

        let rsa_kx_policy = Policy::from_version("20150214").unwrap();
        let tls12_ecdhe_policy = Policy::from_version("20190214").unwrap();

        let firehose_emitter = FirehoseEmitter::initialize().await;

        let kitten = TestEndpoint::initialize("kitten", &rsa_kx_policy, &firehose_emitter).await;
        let puppy = TestEndpoint::initialize("puppy", &DEFAULT, &firehose_emitter).await;
        let cub = TestEndpoint::initialize("cub", &DEFAULT_TLS13, &firehose_emitter).await;

        let mut endpoints = [kitten, puppy, cub];
        let clients = [
            &rsa_kx_policy,
            &tls12_ecdhe_policy,
            &DEFAULT,
            &DEFAULT_TLS13,
        ];

        let mut sent = 0;
                
        let mut rng = rand::rng();

        let start = Instant::now();
        while start.elapsed() < FAKE_TRAFFIC_LENGTH {
            let aggregation = Instant::now();
            while aggregation.elapsed() < AGGREGATION {
                // Choose a random endpoint
                let endpoint_idx = rng.random_range(0..endpoints.len());
                // Choose a random policy
                let policy_idx = rng.random_range(0..clients.len());

                // Perform handshake with the selected endpoint and policy
                endpoints[endpoint_idx].client_handshake(clients[policy_idx]);
                tokio::task::yield_now().await;

            }

            for e in &mut endpoints {
                e.subscriber.finish_record();
                // e.exporter.try_write().await;
                sent += 1;
            }
            tokio::task::yield_now().await;
            println!("sent: {sent}");
        }
    }
}
