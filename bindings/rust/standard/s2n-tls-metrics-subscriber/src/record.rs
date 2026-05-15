// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use crate::{
    attribution::Attribution,
    compatibility::{Cnsa1, Cnsa2, Fips20251201, General20251201, TlsProfile},
    counter::{Counter, FrozenCounter},
    label::{State, metric_label},
    parsing::ClientHelloSupportedParameters,
    static_lists::{
        CIPHER_COUNT, Cipher, FiniteCounter, GROUP_COUNT, Group, PROTOCOL_COUNT, SIGNATURE_COUNT,
        Signature, TlsParam, ToStaticString, Version,
    },
};

/// Metric Record is an opaque type which implements [`metrique_writer::Entry`].
///
/// This is the preferred type for public s2n-tls-metric-subscriber traits and
/// interfaces.
// This currently just holds a single struct. In the future we will
// likely rely on an enum to handle different record types, e.g. SessionResumptionFailure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricRecord {
    pub attribution: Attribution,
    pub handshake: FrozenHandshakeRecord,
}

impl MetricRecord {
    pub(crate) fn new(handshake: FrozenHandshakeRecord, attribution: Attribution) -> Self {
        Self {
            attribution,
            handshake,
        }
    }
}

impl metrique_writer::Entry for MetricRecord {
    /// Write the handshake record with `service` and `resource` attached as
    /// dimensions to every metric value so they are queryable fields.
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        // We can't use `metrique_writer::entry::WithGlobalDimensions` here: its
        // `Entry::write` requires the wrapper to live for the outer `'a` (tied
        // to `&self`), and a local constructed here cannot.
        let dims: [(&'a str, &'a str); 2] = [
            ("resource", self.attribution.resource.as_str()),
            ("service", self.attribution.service.as_str()),
        ];
        let mut wrapped = DimensionedEntryWriter {
            inner: writer,
            dims: &dims,
        };
        self.handshake.write(&mut wrapped);
    }
}

/// `EntryWriter` wrapper that attaches a fixed set of dimensions to every
/// metric value written through it.
struct DimensionedEntryWriter<'d, W> {
    inner: W,
    dims: &'d [(&'d str, &'d str)],
}

impl<'a, W: metrique_writer::EntryWriter<'a>> metrique_writer::EntryWriter<'a>
    for DimensionedEntryWriter<'_, W>
{
    fn timestamp(&mut self, timestamp: std::time::SystemTime) {
        self.inner.timestamp(timestamp);
    }

    fn value(
        &mut self,
        name: impl Into<std::borrow::Cow<'a, str>>,
        value: &(impl metrique_writer::Value + ?Sized),
    ) {
        self.inner.value(
            name,
            &DimensionedValue {
                value,
                dims: self.dims,
            },
        );
    }

    fn config(&mut self, config: &'a dyn metrique_writer::EntryConfig) {
        self.inner.config(config);
    }
}

struct DimensionedValue<'d, 'v, V: ?Sized> {
    value: &'v V,
    dims: &'d [(&'d str, &'d str)],
}

impl<V: metrique_writer::Value + ?Sized> metrique_writer::Value for DimensionedValue<'_, '_, V> {
    fn write(&self, writer: impl metrique_writer::ValueWriter) {
        self.value.write(DimensionedValueWriter {
            inner: writer,
            dims: self.dims,
        });
    }
}

struct DimensionedValueWriter<'d, W> {
    inner: W,
    dims: &'d [(&'d str, &'d str)],
}

impl<W: metrique_writer::ValueWriter> metrique_writer::ValueWriter
    for DimensionedValueWriter<'_, W>
{
    fn string(self, value: &str) {
        self.inner.string(value);
    }

    fn metric<'a>(
        self,
        distribution: impl IntoIterator<Item = metrique_writer::Observation>,
        unit: metrique_writer::Unit,
        dimensions: impl IntoIterator<Item = (&'a str, &'a str)>,
        flags: metrique_writer::MetricFlags<'_>,
    ) {
        self.inner.metric(
            distribution,
            unit,
            // reborrow to align lifetimes between caller dims and self.dims
            // false positive: https://github.com/rust-lang/rust-clippy/issues/9280
            #[allow(clippy::map_identity)]
            dimensions
                .into_iter()
                .map(|(k, v)| (k, v))
                .chain(self.dims.iter().map(|(c, i)| (*c, *i))),
            flags,
        );
    }

    fn error(self, error: metrique_writer::ValidationError) {
        self.inner.error(error);
    }
}

/// The HandshakeRecordInProgress stores the in-flight counters for handshake
/// information - e.g. negotiated parameters.
#[derive(Debug)]
pub(crate) struct HandshakeRecordInProgress {
    /// This is used to send a frozen version back to the Aggregator, after which
    /// point it can be exported. This is only used in the drop impl.
    exporter: std::sync::mpsc::Sender<FrozenHandshakeRecord>,

    /// the total number of handshakes that this record represents.
    handshake_count: AtomicU64,

    negotiated_protocols: Counter<PROTOCOL_COUNT, Version>,
    negotiated_ciphers: Counter<CIPHER_COUNT, Cipher>,
    negotiated_groups: Counter<GROUP_COUNT, Group>,
    negotiated_signatures: Counter<SIGNATURE_COUNT, Signature>,

    // we do not attempt to detect supported parameters for SSLv2 formatted client
    // hellos
    sslv2_client_hello: AtomicU64,
    supported_protocols: Counter<PROTOCOL_COUNT, Version>,
    supported_ciphers: Counter<CIPHER_COUNT, Cipher>,
    supported_groups: Counter<GROUP_COUNT, Group>,
    supported_signatures: Counter<SIGNATURE_COUNT, Signature>,

    compatibility_general20251201: AtomicU64,
    compatibility_fips20251201: AtomicU64,
    compatibility_cnsa1: AtomicU64,
    compatibility_cnsa2: AtomicU64,

    /// sum of handshake duration, including network latency and waiting
    ///
    /// To get the average, divide this by handshake_count.
    handshake_duration_us: AtomicU64,
    /// sum of handshake compute
    ///
    /// To get the average, divide this by handshake_count.
    handshake_compute_us: AtomicU64,
}

impl HandshakeRecordInProgress {
    pub fn new(exporter: std::sync::mpsc::Sender<FrozenHandshakeRecord>) -> Self {
        Self {
            handshake_count: Default::default(),

            negotiated_groups: Counter::new(),
            negotiated_ciphers: Counter::new(),
            negotiated_protocols: Counter::new(),
            negotiated_signatures: Counter::new(),

            sslv2_client_hello: Default::default(),
            supported_groups: Counter::new(),
            supported_ciphers: Counter::new(),
            supported_protocols: Counter::new(),
            supported_signatures: Counter::new(),

            compatibility_general20251201: AtomicU64::default(),
            compatibility_fips20251201: AtomicU64::default(),
            compatibility_cnsa1: AtomicU64::default(),
            compatibility_cnsa2: AtomicU64::default(),

            handshake_duration_us: Default::default(),
            handshake_compute_us: Default::default(),
            exporter,
        }
    }

    pub fn update(
        &self,
        conn: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.handshake_count.fetch_add(1, Ordering::Relaxed);

        ////////////////////////////////////////////////////////////////////////
        /////////////////////   fields from connection   ///////////////////////
        ////////////////////////////////////////////////////////////////////////

        if let Some(sig) = conn.signature_scheme().and_then(|s| s.parse().ok()) {
            self.negotiated_signatures.increment(&sig);
        }

        if conn.client_hello_is_sslv2()? {
            self.sslv2_client_hello.fetch_add(1, Ordering::Relaxed);
        } else {
            let supported_parameter = ClientHelloSupportedParameters::new(conn.client_hello()?);

            supported_parameter
                .supported_versions()?
                .iter()
                .for_each(|version| self.supported_protocols.increment(version));

            supported_parameter
                .supported_ciphers()?
                .iter()
                .for_each(|cipher| self.supported_ciphers.increment(cipher));

            supported_parameter
                .supported_groups()?
                .iter()
                .flatten()
                .for_each(|group| self.supported_groups.increment(group));

            supported_parameter
                .supported_signatures()?
                .iter()
                .flatten()
                .for_each(|signature| self.supported_signatures.increment(signature));

            if General20251201::supported(&supported_parameter) {
                self.compatibility_general20251201
                    .fetch_add(1, Ordering::Relaxed);
            }
            if Fips20251201::supported(&supported_parameter) {
                self.compatibility_fips20251201
                    .fetch_add(1, Ordering::Relaxed);
            }
            if Cnsa1::supported(&supported_parameter) {
                self.compatibility_cnsa1.fetch_add(1, Ordering::Relaxed);
            }
            if Cnsa2::supported(&supported_parameter) {
                self.compatibility_cnsa2.fetch_add(1, Ordering::Relaxed);
            }
        }

        ////////////////////////////////////////////////////////////////////////
        //////////////////////   fields from event   ///////////////////////////
        ////////////////////////////////////////////////////////////////////////

        if let Ok(version) = event.protocol_version().to_static_string().parse() {
            self.negotiated_protocols.increment(&version);
        }

        if let Some(cipher) = Cipher::from_openssl_name(event.cipher()) {
            self.negotiated_ciphers.increment(&cipher);
        }

        if let Some(group) = event.group().and_then(|g| g.parse().ok()) {
            self.negotiated_groups.increment(&group);
        }

        // accuracy: as long as the handshake took less than 500,000 years
        // this cast will not truncate. We prefer truncation/less accurate metrics
        // over a panic.
        self.handshake_compute_us.fetch_add(
            event.synchronous_time().as_micros() as u64,
            Ordering::Relaxed,
        );
        self.handshake_duration_us
            .fetch_add(event.duration().as_micros() as u64, Ordering::Relaxed);

        Ok(())
    }

    /// make a copy of this record to be exported.
    ///
    /// ### A Note On Ordering Correctness
    ///
    /// It is important that this function observes the results of all the `fetch_add`
    /// operations on other threads.
    ///
    /// Simple Intuition: This function takes a `&mut`. Therefore the rust compiler
    /// enforces that there are no other references to this memory and there isn't
    /// anything to actually synchronize. So a Relaxed load is fine.
    fn finish(&mut self) -> FrozenHandshakeRecord {
        FrozenHandshakeRecord {
            freeze_time: SystemTime::now(),
            handshake_count: self.handshake_count.load(Ordering::Relaxed),
            negotiated_protocols: self.negotiated_protocols.freeze(),
            negotiated_ciphers: self.negotiated_ciphers.freeze(),
            negotiated_groups: self.negotiated_groups.freeze(),
            negotiated_signatures: self.negotiated_signatures.freeze(),

            sslv2_client_hello: self.sslv2_client_hello.load(Ordering::Relaxed),
            supported_protocols: self.supported_protocols.freeze(),
            supported_ciphers: self.supported_ciphers.freeze(),
            supported_groups: self.supported_groups.freeze(),
            supported_signatures: self.supported_signatures.freeze(),

            compatibility_general20251201: self
                .compatibility_general20251201
                .load(Ordering::Relaxed),
            compatibility_fips20251201: self.compatibility_fips20251201.load(Ordering::Relaxed),
            compatibility_cnsa1: self.compatibility_cnsa1.load(Ordering::Relaxed),
            compatibility_cnsa2: self.compatibility_cnsa2.load(Ordering::Relaxed),

            handshake_duration_us: self.handshake_duration_us.load(Ordering::Relaxed),
            handshake_compute_us: self.handshake_compute_us.load(Ordering::Relaxed),
        }
    }
}

impl Drop for HandshakeRecordInProgress {
    fn drop(&mut self) {
        let frozen = self.finish();
        // no available way to report error
        let _ = self.exporter.send(frozen);
    }
}

/// `SystemTime` has no meaningful `Default` impl for serde's purposes, so we
/// pick `UNIX_EPOCH` explicitly as the `#[serde(default = ...)]` target for
/// `freeze_time`.
fn system_time_epoch() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrozenHandshakeRecord {
    #[serde(default = "system_time_epoch")]
    pub freeze_time: SystemTime,

    #[serde(default)]
    pub handshake_count: u64,

    #[serde(default)]
    pub negotiated_protocols: FrozenCounter<PROTOCOL_COUNT, Version>,
    #[serde(default)]
    pub negotiated_ciphers: FrozenCounter<CIPHER_COUNT, Cipher>,
    #[serde(default)]
    pub negotiated_groups: FrozenCounter<GROUP_COUNT, Group>,
    #[serde(default)]
    pub negotiated_signatures: FrozenCounter<SIGNATURE_COUNT, Signature>,

    #[serde(default)]
    pub sslv2_client_hello: u64,
    #[serde(default)]
    pub supported_protocols: FrozenCounter<PROTOCOL_COUNT, Version>,
    #[serde(default)]
    pub supported_ciphers: FrozenCounter<CIPHER_COUNT, Cipher>,
    #[serde(default)]
    pub supported_groups: FrozenCounter<GROUP_COUNT, Group>,
    #[serde(default)]
    pub supported_signatures: FrozenCounter<SIGNATURE_COUNT, Signature>,

    #[serde(default)]
    pub compatibility_general20251201: u64,
    #[serde(default)]
    pub compatibility_fips20251201: u64,
    #[serde(default)]
    pub compatibility_cnsa1: u64,
    #[serde(default)]
    pub compatibility_cnsa2: u64,

    #[serde(default)]
    pub handshake_duration_us: u64,
    #[serde(default)]
    pub handshake_compute_us: u64,
}

// This is just cfg(test) because we only use it in tests to assert on cases of
// all-zero records
#[cfg(test)]
impl Default for FrozenHandshakeRecord {
    fn default() -> Self {
        Self {
            freeze_time: SystemTime::UNIX_EPOCH,
            handshake_count: 0,
            negotiated_protocols: FrozenCounter::default(),
            negotiated_ciphers: FrozenCounter::default(),
            negotiated_groups: FrozenCounter::default(),
            negotiated_signatures: FrozenCounter::default(),
            sslv2_client_hello: 0,
            supported_protocols: FrozenCounter::default(),
            supported_ciphers: FrozenCounter::default(),
            supported_groups: FrozenCounter::default(),
            supported_signatures: FrozenCounter::default(),
            compatibility_general20251201: 0,
            compatibility_fips20251201: 0,
            compatibility_cnsa1: 0,
            compatibility_cnsa2: 0,
            handshake_duration_us: 0,
            handshake_compute_us: 0,
        }
    }
}

impl metrique_writer::Entry for FrozenHandshakeRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        writer.timestamp(self.freeze_time);

        // Emit one label per non-zero slot for each (kind, state) cell.
        // The label uses the element's `Display` impl.
        fn write_counter<'a, const N: usize, T, W>(
            counter: &'a FrozenCounter<N, T>,
            parameter: TlsParam,
            state: State,
            writer: &mut W,
        ) where
            T: FiniteCounter<N> + std::fmt::Display,
            W: metrique_writer::EntryWriter<'a>,
        {
            for (slot, element, count) in counter.iter_non_zero() {
                let label = metric_label(slot, element, parameter, state);
                writer.value(label, &count);
            }
        }

        write_counter(
            &self.negotiated_protocols,
            TlsParam::Version,
            State::Negotiated,
            writer,
        );
        write_counter(
            &self.negotiated_ciphers,
            TlsParam::Cipher,
            State::Negotiated,
            writer,
        );
        write_counter(
            &self.negotiated_groups,
            TlsParam::Group,
            State::Negotiated,
            writer,
        );
        write_counter(
            &self.negotiated_signatures,
            TlsParam::SignatureScheme,
            State::Negotiated,
            writer,
        );
        write_counter(
            &self.supported_protocols,
            TlsParam::Version,
            State::Supported,
            writer,
        );
        write_counter(
            &self.supported_ciphers,
            TlsParam::Cipher,
            State::Supported,
            writer,
        );
        write_counter(
            &self.supported_groups,
            TlsParam::Group,
            State::Supported,
            writer,
        );
        write_counter(
            &self.supported_signatures,
            TlsParam::SignatureScheme,
            State::Supported,
            writer,
        );

        writer.value(
            "compatibility.general20251201",
            &self.compatibility_general20251201,
        );
        writer.value(
            "compatibility.fips20251201",
            &self.compatibility_fips20251201,
        );
        writer.value("compatibility.cnsa1", &self.compatibility_cnsa1);
        writer.value("compatibility.cnsa2", &self.compatibility_cnsa2);

        writer.value("sslv2_client_hello", &self.sslv2_client_hello);
        writer.value("handshake_count", &self.handshake_count);
        writer.value("handshake_duration_us", &self.handshake_duration_us);
        writer.value("handshake_compute_us", &self.handshake_compute_us);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{ARBITRARY_POLICY_1, TestEndpoint};

    #[test]
    fn record_contents_negotiated_parameters() {
        let endpoint = TestEndpoint::new();

        let result = endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].handshake;

        assert_eq!(record.handshake_count, 1);
        assert_eq!(record.negotiated_ciphers.total(), 1);
        assert_eq!(record.negotiated_groups.total(), 1);
        assert_eq!(record.negotiated_signatures.total(), 1);
        assert_eq!(record.negotiated_protocols.total(), 1);

        let expected_version = result
            .client
            .actual_protocol_version()
            .unwrap()
            .to_static_string();
        assert_eq!(record.negotiated_protocols.count_for(expected_version), 1);

        let expected_cipher = result.client.cipher_suite().unwrap().to_owned();
        let expected_cipher_description = Cipher::from_openssl_name(expected_cipher.as_str())
            .and_then(|cipher| cipher.known_description())
            .unwrap();
        assert_eq!(
            record
                .negotiated_ciphers
                .count_for(expected_cipher_description),
            1
        );

        let expected_group = result
            .client
            .selected_key_exchange_group()
            .unwrap()
            .to_owned();
        assert_eq!(
            record.negotiated_groups.count_for(expected_group.as_str()),
            1
        );

        let expected_sig = result.client.signature_scheme().unwrap().to_owned();
        assert_eq!(
            record
                .negotiated_signatures
                .count_for(expected_sig.as_str()),
            1
        );
    }

    #[test]
    fn record_contents_supported_parameters() {
        const EXPECTED_VERSIONS: &[&str] = &["TLSv1_3", "TLSv1_2"];
        const EXPECTED_CIPHERS: &[&str] = &[
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ];
        const EXPECTED_GROUPS: &[&str] = &["secp256r1", "secp384r1", "secp521r1", "x25519"];
        const EXPECTED_SIGS: &[&str] = &[
            "ecdsa_sha256",
            "ecdsa_sha384",
            "ecdsa_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pss_pss_sha256",
            "rsa_pss_pss_sha384",
            "rsa_pss_pss_sha512",
        ];

        let endpoint = TestEndpoint::new();

        let _ = endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].handshake;

        /// For every slot in `counter`, assert the count is 1 iff the slot's
        /// element description appears in `expected`, else 0.
        fn assert_supported_matches<const N: usize, T>(
            counter: &FrozenCounter<N, T>,
            expected: &[&str],
        ) where
            T: FiniteCounter<N> + std::fmt::Display + std::str::FromStr<Err = ()>,
        {
            let expected_slots: Vec<usize> = expected
                .iter()
                .map(|description| {
                    description
                        .parse::<T>()
                        .unwrap_or_else(|()| panic!("unknown description {description}"))
                        .slot_from_key()
                        .unwrap()
                })
                .collect();

            for (slot, &count) in counter.slots_for_test().iter().enumerate() {
                let name = T::key_from_slot(slot).unwrap();
                if expected_slots.contains(&slot) {
                    assert_eq!(count, 1, "{name} count is {count}, not one");
                } else {
                    assert_eq!(count, 0, "{name} count is {count}, not zero");
                }
            }
        }

        assert_supported_matches(&record.supported_protocols, EXPECTED_VERSIONS);
        assert_supported_matches(&record.supported_ciphers, EXPECTED_CIPHERS);
        assert_supported_matches(&record.supported_groups, EXPECTED_GROUPS);
        assert_supported_matches(&record.supported_signatures, EXPECTED_SIGS);
    }

    #[test]
    fn multiple_records() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].handshake;

        assert_eq!(record.handshake_count, 3);
        assert_eq!(record.negotiated_ciphers.total(), 3);
        assert_eq!(record.negotiated_groups.total(), 3);
        assert_eq!(record.negotiated_signatures.total(), 3);
        assert_eq!(record.negotiated_protocols.total(), 3);
    }

    /// A record with no handshakes should be entirely empty/default.
    #[test]
    fn empty_record() {
        let endpoint = TestEndpoint::new();

        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let mut record = records[0].handshake.clone();

        // ignore the freeze time, since that "default" value is set to the Unix Epoch.
        record.freeze_time = SystemTime::UNIX_EPOCH;
        assert_eq!(record, FrozenHandshakeRecord::default());
    }

    /// ARBITRARY_POLICY_1 (20240503 / default_tls13) should be compatible with
    /// General, Fips, and Cnsa1 profiles, but not CNSA2 (which requires MLKEM1024
    /// and mldsa87).
    #[test]
    fn record_contents_compatibility_metrics() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].handshake;

        assert_eq!(record.compatibility_general20251201, 1);
        assert_eq!(record.compatibility_fips20251201, 1);
        assert_eq!(record.compatibility_cnsa1, 1);
        assert_eq!(record.compatibility_cnsa2, 0);
    }

    /// Make sure that the compute time is less than the overall handshake time.
    ///
    /// Additionally, make sure that three handshakes takes longer than one handshake.
    /// This provides some confidence that we are correctly e.g. adding amounts
    #[test]
    fn timers() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let single_handshake = &records[0].handshake;

        assert!(single_handshake.handshake_compute_us <= single_handshake.handshake_duration_us);
        drop(records);

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let single_handshake = &records[0].handshake;
        let multiple_handshakes = &records[1].handshake;

        assert!(
            multiple_handshakes.handshake_compute_us <= multiple_handshakes.handshake_duration_us
        );

        assert!(single_handshake.handshake_compute_us < multiple_handshakes.handshake_compute_us);
        assert!(single_handshake.handshake_duration_us < multiple_handshakes.handshake_duration_us);
    }

    /// A JSON payload that only includes `handshake_count` deserializes
    /// successfully: `#[serde(default)]` on every other field fills it with
    /// its documented default (0 for integer counters, `SystemTime::UNIX_EPOCH`
    /// for `freeze_time`, a zero-filled `FrozenCounter` for per-kind fields).
    #[test]
    fn deserialize_missing_fields_uses_defaults() {
        let json = r#"{"handshake_count": 10}"#;
        let record: FrozenHandshakeRecord = serde_json::from_str(json).unwrap();

        assert_eq!(record.handshake_count, 10);
        assert_eq!(record.freeze_time, SystemTime::UNIX_EPOCH);

        // Per-kind counters default to a zero-filled slab of the right length.
        assert_eq!(record.negotiated_protocols, FrozenCounter::default());
        assert_eq!(record.negotiated_ciphers, FrozenCounter::default());
        assert_eq!(record.negotiated_groups, FrozenCounter::default());
        assert_eq!(record.negotiated_signatures, FrozenCounter::default());
        assert_eq!(record.supported_protocols, FrozenCounter::default());
        assert_eq!(record.supported_ciphers, FrozenCounter::default());
        assert_eq!(record.supported_groups, FrozenCounter::default());
        assert_eq!(record.supported_signatures, FrozenCounter::default());

        // Scalar integer fields default to zero.
        assert_eq!(record.sslv2_client_hello, 0);
        assert_eq!(record.compatibility_general20251201, 0);
        assert_eq!(record.compatibility_fips20251201, 0);
        assert_eq!(record.compatibility_cnsa1, 0);
        assert_eq!(record.compatibility_cnsa2, 0);
        assert_eq!(record.handshake_duration_us, 0);
        assert_eq!(record.handshake_compute_us, 0);
    }

    /// Verifies that `service` and `resource` are emitted as dimensions on
    /// every metric written by `MetricRecord::write`, and not as string
    /// properties.
    #[test]
    fn attribution_emitted_as_dimensions() {
        use metrique_writer::{
            Entry, EntryConfig, EntryWriter, MetricFlags, Observation, Unit, ValidationError,
            Value, ValueWriter,
        };
        use std::borrow::Cow;
        use std::time::SystemTime;

        use crate::Attribution;

        #[derive(Default)]
        struct Capture {
            metrics: Vec<(String, Vec<(String, String)>)>,
            properties: Vec<(String, String)>,
        }

        impl<'a> EntryWriter<'a> for Capture {
            fn timestamp(&mut self, _: SystemTime) {}

            fn value(&mut self, name: impl Into<Cow<'a, str>>, value: &(impl Value + ?Sized)) {
                let name = name.into().into_owned();
                value.write(CaptureValueWriter {
                    name,
                    capture: self,
                });
            }

            fn config(&mut self, _: &'a dyn EntryConfig) {}
        }

        struct CaptureValueWriter<'c> {
            name: String,
            capture: &'c mut Capture,
        }

        impl ValueWriter for CaptureValueWriter<'_> {
            fn string(self, value: &str) {
                self.capture.properties.push((self.name, value.to_owned()));
            }

            fn metric<'a>(
                self,
                _: impl IntoIterator<Item = Observation>,
                _: Unit,
                dimensions: impl IntoIterator<Item = (&'a str, &'a str)>,
                _: MetricFlags<'_>,
            ) {
                let dims = dimensions
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect();
                self.capture.metrics.push((self.name, dims));
            }

            fn error(self, _: ValidationError) {}
        }

        let handshake = FrozenHandshakeRecord {
            handshake_count: 1,
            ..Default::default()
        };
        let record = MetricRecord::new(
            handshake,
            Attribution {
                service: "svc".to_owned(),
                resource: "res".to_owned(),
            },
        );

        let mut capture = Capture::default();
        record.write(&mut capture);

        assert!(!capture.metrics.is_empty(), "expected at least one metric");
        for (name, dims) in &capture.metrics {
            assert!(
                dims.contains(&("service".to_owned(), "svc".to_owned())),
                "metric {name} missing service dim, got {dims:?}",
            );
            assert!(
                dims.contains(&("resource".to_owned(), "res".to_owned())),
                "metric {name} missing resource dim, got {dims:?}",
            );
        }

        assert!(
            !capture
                .properties
                .iter()
                .any(|(k, _)| k == "service" || k == "resource"),
            "service/resource leaked as string properties: {:?}",
            capture.properties,
        );
    }
}
