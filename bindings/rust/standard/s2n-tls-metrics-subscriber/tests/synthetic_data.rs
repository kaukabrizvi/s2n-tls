// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration test: CBOR → DuckDB (direct insert) → aggregation queries.
//!
//! 1. Generate CBOR metric records from real TLS handshakes
//! 2. Decode and INSERT each record directly into a DuckDB table
//! 3. Run aggregation queries to verify results

use duckdb::Connection;
use rand::RngExt;
use s2n_tls::{
    security::{DEFAULT_TLS13, Policy},
    testing::config_builder,
};
use s2n_tls_metrics_subscriber::{AggregatedMetricsSubscriber, Attribution, MetricRecord};
use std::sync::mpsc;

const NUM_RESOURCES: usize = 50;
const HOSTS_PER_RESOURCE: usize = 2;
const MIN_HANDSHAKES_PER_RECORD: usize = 1;
const MAX_HANDSHAKES_PER_RECORD: usize = 20;
const CLIENT_POLICIES: &[&str] = &["20240503", "20190214"];

/// Array fields: (json_field_name, array_length).
const ARRAY_FIELDS: &[(&str, usize)] = &[
    ("negotiated_protocols", 5),
    ("negotiated_ciphers", 37),
    ("negotiated_groups", 8),
    ("negotiated_signatures", 20),
    ("supported_protocols", 5),
    ("supported_ciphers", 37),
    ("supported_groups", 8),
    ("supported_signatures", 20),
];

const SCALAR_FIELDS: &[&str] = &[
    "handshake_count",
    "sslv2_client_hello",
    "handshake_duration_us",
    "handshake_compute_us",
];

struct Endpoint {
    server_config: s2n_tls::config::Config,
    subscriber: AggregatedMetricsSubscriber<mpsc::Sender<MetricRecord>>,
    rx: mpsc::Receiver<MetricRecord>,
}

impl Endpoint {
    fn new(attribution: Attribution) -> Self {
        let (tx, rx) = mpsc::channel();
        let subscriber = AggregatedMetricsSubscriber::new(attribution, tx);
        let server_config = {
            let mut config = config_builder(&DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber.clone()).unwrap();
            config.build().unwrap()
        };
        Self { server_config, subscriber, rx }
    }

    fn generate_record(
        &self,
        count: usize,
        client_configs: &[s2n_tls::config::Config],
        rng: &mut impl rand::Rng,
    ) -> MetricRecord {
        for _ in 0..count {
            let config = &client_configs[rng.random_range(0..client_configs.len())];
            let mut pair =
                s2n_tls::testing::TestPair::from_configs(config, &self.server_config);
            pair.handshake().unwrap();
        }
        self.subscriber.finish_record();
        self.rx.recv().unwrap()
    }

    fn set_attribution(&mut self, attribution: Attribution) {
        *self = Self::new(attribution);
    }
}

/// Build the CREATE TABLE DDL.
fn create_table_sql() -> String {
    let mut cols = vec![
        "service TEXT NOT NULL".to_owned(),
        "resource TEXT NOT NULL".to_owned(),
        "certificate TEXT".to_owned(),
        "s2n_version TEXT NOT NULL".to_owned(),
        "security_policy TEXT NOT NULL".to_owned(),
    ];
    for &name in SCALAR_FIELDS {
        cols.push(format!("{name} UBIGINT NOT NULL"));
    }
    for &(name, len) in ARRAY_FIELDS {
        for i in 0..len {
            cols.push(format!("{name}_{i} UBIGINT NOT NULL"));
        }
    }
    format!("CREATE TABLE metrics_raw ({})", cols.join(", "))
}

/// Build a parameterized INSERT statement.
fn insert_sql() -> String {
    let num_attribution = 5;
    let num_scalars = SCALAR_FIELDS.len();
    let num_array_elems: usize = ARRAY_FIELDS.iter().map(|(_, len)| len).sum();
    let total = num_attribution + num_scalars + num_array_elems;
    let placeholders: Vec<&str> = vec!["?"; total];
    format!(
        "INSERT INTO metrics_raw VALUES ({})",
        placeholders.join(", ")
    )
}

/// Insert a single MetricRecord into the database.
fn insert_record(stmt: &mut duckdb::Statement, record: &MetricRecord) {
    let json = record.to_json_value();
    let hs = &json["handshake"];
    let attr = record.attribution().unwrap();

    let mut params: Vec<Box<dyn duckdb::ToSql>> = Vec::new();

    // Attribution
    params.push(Box::new(attr.service.clone()));
    params.push(Box::new(attr.resource.clone()));
    params.push(Box::new(attr.certificate.clone()));
    params.push(Box::new(attr.s2n_version.clone()));
    params.push(Box::new(attr.security_policy.clone()));

    // Scalars
    for &field in SCALAR_FIELDS {
        params.push(Box::new(hs[field].as_u64().unwrap_or(0)));
    }

    // Array elements
    for &(field, len) in ARRAY_FIELDS {
        let arr = hs[field].as_array();
        for i in 0..len {
            let val = arr.and_then(|a| a.get(i)).and_then(|v| v.as_u64()).unwrap_or(0);
            params.push(Box::new(val));
        }
    }

    let param_refs: Vec<&dyn duckdb::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    stmt.execute(param_refs.as_slice()).unwrap();
}

fn generate_cbor_records() -> Vec<Vec<u8>> {
    let mut rng = rand::rng();

    let client_configs: Vec<s2n_tls::config::Config> = CLIENT_POLICIES
        .iter()
        .map(|v| {
            let policy = Policy::from_version(v).unwrap();
            let builder = config_builder(&policy).unwrap();
            builder.build().unwrap()
        })
        .collect();

    let mut pool: Vec<Endpoint> = (0..HOSTS_PER_RESOURCE)
        .map(|_| Endpoint::new(Attribution::default()))
        .collect();

    let mut cbor_records = Vec::with_capacity(NUM_RESOURCES * HOSTS_PER_RESOURCE);

    for resource_idx in 0..NUM_RESOURCES {
        let attribution = Attribution {
            service: format!("service-{}", resource_idx % 10),
            resource: format!(
                "arn:aws:elasticloadbalancing:us-west-2:111122223333:listener/app/svc-{resource_idx}/abc{resource_idx:04x}/def"
            ),
            certificate: Some(format!(
                "arn:aws:acm:us-west-2:111122223333:certificate/cert-{resource_idx}"
            )),
            s2n_version: "1.5.0".to_owned(),
            security_policy: "20240503".to_owned(),
        };

        for endpoint in &mut pool {
            endpoint.set_attribution(attribution.clone());
            let handshake_count =
                rng.random_range(MIN_HANDSHAKES_PER_RECORD..=MAX_HANDSHAKES_PER_RECORD);
            let record = endpoint.generate_record(handshake_count, &client_configs, &mut rng);
            cbor_records.push(record.to_cbor());
        }
    }

    eprintln!("generated {} CBOR records", cbor_records.len());
    cbor_records
}

#[test]
fn cbor_to_duckdb() {
    let cbor_records = generate_cbor_records();

    // Create an in-memory DuckDB and insert all records
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(&create_table_sql()).unwrap();

    let sql = insert_sql();
    let mut stmt = db.prepare(&sql).unwrap();
    for cbor in &cbor_records {
        let record = MetricRecord::from_cbor(cbor).unwrap();
        insert_record(&mut stmt, &record);
    }
    drop(stmt);

    // Verify raw row count
    let total_rows: u64 = db
        .query_row("SELECT COUNT(*) FROM metrics_raw", [], |row| row.get(0))
        .unwrap();
    assert_eq!(total_rows, (NUM_RESOURCES * HOSTS_PER_RESOURCE) as u64);
    eprintln!("inserted {total_rows} rows");

    // Verify distinct resources
    let num_resources: u64 = db
        .query_row(
            "SELECT COUNT(DISTINCT resource) FROM metrics_raw",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(num_resources, NUM_RESOURCES as u64);

    // Aggregate by resource
    let mut stmt = db
        .prepare(
            "SELECT resource, SUM(handshake_count) as total_hs \
             FROM metrics_raw \
             GROUP BY resource \
             ORDER BY total_hs DESC \
             LIMIT 5",
        )
        .unwrap();

    eprintln!("\ntop 5 resources by handshake count:");
    let top: Vec<(String, u64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for (resource, total) in &top {
        eprintln!("  {resource}: {total} handshakes");
        assert!(*total >= HOSTS_PER_RESOURCE as u64);
    }
    drop(stmt);

    // Aggregate by service
    let mut stmt = db
        .prepare(
            "SELECT service, \
                    COUNT(DISTINCT resource) as num_resources, \
                    SUM(handshake_count) as total_hs \
             FROM metrics_raw \
             GROUP BY service \
             ORDER BY service",
        )
        .unwrap();

    eprintln!("\nper-service summary:");
    let by_service: Vec<(String, u64, u64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for (service, num_resources, total_hs) in &by_service {
        eprintln!("  {service}: {num_resources} resources, {total_hs} handshakes");
    }
    assert_eq!(by_service.len(), 10);
}

#[test]
fn cbor_vs_protobuf_size() {
    let cbor_records = generate_cbor_records();

    let mut total_cbor: usize = 0;
    let mut total_proto: usize = 0;
    let mut total_json: usize = 0;

    for cbor in &cbor_records {
        let record = MetricRecord::from_cbor(cbor).unwrap();
        let proto_bytes = record.to_proto_bytes();
        let json_bytes = serde_json::to_vec(&record.to_json_value()).unwrap();

        total_cbor += cbor.len();
        total_proto += proto_bytes.len();
        total_json += json_bytes.len();
    }

    let count = cbor_records.len();
    eprintln!("\nwire format size comparison ({count} records):");
    eprintln!("  JSON:     {total_json:>8} bytes ({:.0} bytes/record)", total_json as f64 / count as f64);
    eprintln!("  CBOR:     {total_cbor:>8} bytes ({:.0} bytes/record)", total_cbor as f64 / count as f64);
    eprintln!("  Protobuf: {total_proto:>8} bytes ({:.0} bytes/record)", total_proto as f64 / count as f64);
}
