// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap, sync::atomic::{AtomicU64, Ordering}, time::SystemTime
};

use s2n_tls_sys::s2n_tls_extension_type::SUPPORTED_VERSIONS;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use crate::{
    condensed::Attribution, flat_map::to_map, label::{State, metric_label}, parsing::ClientHelloSupportedParameters, static_lists::{
        self, CIPHERS_AVAILABLE_IN_S2N, Cipher, GROUPS_AVAILABLE_IN_S2N, Group, S2N_VERSIONS, SIGNATURE_SCHEMES_AVAILABLE_IN_S2N, Signature, TlsParam, ToStaticString, VERSIONS_AVAILABLE_IN_S2N, Version
    }
};

const GROUP_COUNT: usize = GROUPS_AVAILABLE_IN_S2N.len();
const CIPHER_COUNT: usize = CIPHERS_AVAILABLE_IN_S2N.len();
const SIGNATURE_COUNT: usize = SIGNATURE_SCHEMES_AVAILABLE_IN_S2N.len();
const PROTOCOL_COUNT: usize = VERSIONS_AVAILABLE_IN_S2N.len();

/// Metric Record is an opaque type which implements [`metrique_writer::Entry`].
///
/// This is the preferred type for public s2n-tls-metric-subscriber traits and
/// interfaces.
// This currently just holds a single struct. In the future we will
// likely rely on an enum to handle different record types, e.g. SessionResumptionFailure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricRecord {
    attribution: Option<Attribution>,
    handshake: FrozenHandshakeRecord,
}

impl MetricRecord {
    pub(crate) fn new(handshake: FrozenHandshakeRecord) -> Self {
        Self { attribution: None, handshake }
    }

    /// Set the attribution for this metric record.
    pub fn set_attribution(&mut self, attribution: Attribution) {
        self.attribution = Some(attribution);
    }

    /// Serialize this metric record to CBOR bytes.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .expect("CBOR serialization should not fail");
        buf
    }

    /// Deserialize a metric record from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }

    /// Return the attribution, if set.
    pub fn attribution(&self) -> Option<&Attribution> {
        self.attribution.as_ref()
    }

    /// Serialize the record to a JSON Value for generic processing.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("serialization should not fail")
    }

    /// Serialize the condensed form (IANA-keyed HashMaps) to CBOR bytes.
    pub fn to_condensed_cbor(&self) -> Vec<u8> {
        let condensed = CondensedMetricRecord {
            attribution: self.attribution.clone(),
            handshake: CondensedHandshakeRecord::from_frozen_hs_record(&self.handshake),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&condensed, &mut buf)
            .expect("CBOR serialization should not fail");
        buf
    }

    /// Serialize the condensed form (IANA-keyed HashMaps) to JSON bytes.
    pub fn to_condensed_json(&self) -> Vec<u8> {
        let condensed = CondensedMetricRecord {
            attribution: self.attribution.clone(),
            handshake: CondensedHandshakeRecord::from_frozen_hs_record(&self.handshake),
        };
        serde_json::to_vec(&condensed).expect("JSON serialization should not fail")
    }
}

impl metrique_writer::Entry for MetricRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        self.handshake.write(writer)
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

    negotiated_protocols: [AtomicU64; PROTOCOL_COUNT],
    negotiated_ciphers: [AtomicU64; CIPHER_COUNT],
    negotiated_groups: [AtomicU64; GROUP_COUNT],
    negotiated_signatures: [AtomicU64; SIGNATURE_COUNT],

    // we do not attempt to detect supported parameters for SSLv2 formatted client
    // hellos
    sslv2_client_hello: AtomicU64,
    supported_protocols: [AtomicU64; PROTOCOL_COUNT],
    supported_ciphers: [AtomicU64; CIPHER_COUNT],
    supported_groups: [AtomicU64; GROUP_COUNT],
    supported_signatures: [AtomicU64; SIGNATURE_COUNT],

    /// sum of handshake duration, including network latency and waiting
    ///
    /// To get the average, divide this by handshake_count.
    handshake_duration_us: AtomicU64,
    /// sum of handshake compute
    ///
    /// To get the average, divide this by handshake_count.
    handshake_compute_us: AtomicU64,
}

fn relaxed_freeze<const T: usize>(array: &[AtomicU64; T]) -> [u64; T] {
    array
        .each_ref()
        .map(|counter| counter.load(Ordering::Relaxed))
}

impl HandshakeRecordInProgress {
    pub fn new(exporter: std::sync::mpsc::Sender<FrozenHandshakeRecord>) -> Self {
        // default is not implemented for arrays this large
        let negotiated_ciphers = [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        let supported_ciphers = [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        Self {
            handshake_count: Default::default(),

            negotiated_groups: Default::default(),
            negotiated_ciphers,
            negotiated_protocols: Default::default(),
            negotiated_signatures: Default::default(),

            sslv2_client_hello: Default::default(),
            supported_groups: Default::default(),
            supported_ciphers,
            supported_protocols: Default::default(),
            supported_signatures: Default::default(),

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

        conn.signature_scheme()
            .and_then(|name| TlsParam::SignatureScheme.description_to_index(name))
            .and_then(|index| self.negotiated_signatures.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));

        if conn.client_hello_is_sslv2()? {
            self.sslv2_client_hello.fetch_add(1, Ordering::Relaxed);
        } else {
            let supported_parameter = ClientHelloSupportedParameters::new(conn.client_hello()?);

            supported_parameter
                .supported_versions()?
                .iter()
                .filter_map(|version| version.known_description())
                .filter_map(|description| TlsParam::Version.description_to_index(description))
                .filter_map(|index| self.supported_protocols.get(index))
                .for_each(|counter| {
                    counter.fetch_add(1, Ordering::Relaxed);
                });

            supported_parameter
                .supported_ciphers()?
                .iter()
                .filter_map(|cipher| cipher.known_description())
                .filter_map(|description| TlsParam::Cipher.description_to_index(description))
                .filter_map(|index| self.supported_ciphers.get(index))
                .for_each(|counter| {
                    counter.fetch_add(1, Ordering::Relaxed);
                });

            if let Some(supported_groups) = supported_parameter.supported_groups()? {
                supported_groups
                    .iter()
                    .filter_map(|group| group.known_description())
                    .filter_map(|description| TlsParam::Group.description_to_index(description))
                    .filter_map(|index| self.supported_groups.get(index))
                    .for_each(|counter| {
                        counter.fetch_add(1, Ordering::Relaxed);
                    });
            }

            if let Some(supported_sigs) = supported_parameter.supported_signatures()? {
                supported_sigs
                    .iter()
                    .filter_map(|signature| signature.known_description())
                    .filter_map(|description| {
                        TlsParam::SignatureScheme.description_to_index(description)
                    })
                    .filter_map(|index| self.supported_signatures.get(index))
                    .for_each(|counter| {
                        counter.fetch_add(1, Ordering::Relaxed);
                    });
            }
        }

        ////////////////////////////////////////////////////////////////////////
        //////////////////////   fields from event   ///////////////////////////
        ////////////////////////////////////////////////////////////////////////

        TlsParam::Version
            .description_to_index(event.protocol_version().to_static_string())
            .and_then(|index| self.negotiated_protocols.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));

        static_lists::cipher_ossl_name_to_index(event.cipher())
            .and_then(|index| self.negotiated_ciphers.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));

        event
            .group()
            .and_then(|name| TlsParam::Group.description_to_index(name))
            .and_then(|index| self.negotiated_groups.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));

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
            negotiated_protocols: relaxed_freeze(&self.negotiated_protocols),
            negotiated_ciphers: relaxed_freeze(&self.negotiated_ciphers),
            negotiated_groups: relaxed_freeze(&self.negotiated_groups),
            negotiated_signatures: relaxed_freeze(&self.negotiated_signatures),

            sslv2_client_hello: self.sslv2_client_hello.fetch_add(1, Ordering::SeqCst),
            supported_protocols: relaxed_freeze(&self.supported_protocols),
            supported_ciphers: relaxed_freeze(&self.supported_ciphers),
            supported_groups: relaxed_freeze(&self.supported_groups),
            supported_signatures: relaxed_freeze(&self.supported_signatures),

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FrozenHandshakeRecord {
    freeze_time: SystemTime,

    handshake_count: u64,

    negotiated_protocols: [u64; PROTOCOL_COUNT],
    #[serde(with = "BigArray")]
    negotiated_ciphers: [u64; CIPHER_COUNT],
    negotiated_groups: [u64; GROUP_COUNT],
    negotiated_signatures: [u64; SIGNATURE_COUNT],

    sslv2_client_hello: u64,
    supported_protocols: [u64; PROTOCOL_COUNT],
    #[serde(with = "BigArray")]
    supported_ciphers: [u64; CIPHER_COUNT],
    supported_groups: [u64; GROUP_COUNT],
    supported_signatures: [u64; SIGNATURE_COUNT],

    handshake_duration_us: u64,
    handshake_compute_us: u64,
}

impl metrique_writer::Entry for FrozenHandshakeRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        writer.timestamp(self.freeze_time);

        for (list, parameter, state) in [
            (
                self.negotiated_protocols.as_slice(),
                TlsParam::Version,
                State::Negotiated,
            ),
            (
                self.negotiated_ciphers.as_slice(),
                TlsParam::Cipher,
                State::Negotiated,
            ),
            (
                self.negotiated_groups.as_slice(),
                TlsParam::Group,
                State::Negotiated,
            ),
            (
                self.negotiated_signatures.as_slice(),
                TlsParam::SignatureScheme,
                State::Negotiated,
            ),
            (
                self.supported_protocols.as_slice(),
                TlsParam::Version,
                State::Supported,
            ),
            (
                self.supported_ciphers.as_slice(),
                TlsParam::Cipher,
                State::Supported,
            ),
            (
                self.supported_groups.as_slice(),
                TlsParam::Group,
                State::Supported,
            ),
            (
                self.supported_signatures.as_slice(),
                TlsParam::SignatureScheme,
                State::Supported,
            ),
        ] {
            list.iter()
                .enumerate()
                .filter(|(_index, count)| **count > 0)
                .filter_map(
                    |(index, count)| match parameter.index_to_description(index) {
                        Some(name) => Some((name, count)),
                        None => {
                            debug_assert!(false, "failed to get name for {index} of {parameter:?}");
                            None
                        }
                    },
                )
                .for_each(|(name, count)| {
                    let label = metric_label(name, parameter, state);
                    writer.value(label, count);
                });
        }

        writer.value("sslv2_client_hello", &self.sslv2_client_hello);
        writer.value("handshake_count", &self.handshake_count);
        writer.value("handshake_duration_us", &self.handshake_duration_us);
        writer.value("handshake_compute_us", &self.handshake_compute_us);
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ParamCount {
    #[serde(rename = "p")]
    protocols: HashMap<Version, u64>,
    #[serde(rename = "c")]
    ciphers: HashMap<Cipher, u64>,
    #[serde(rename = "g")]
    group: HashMap<Group, u64>,
    #[serde(rename = "s")]
    signatures: HashMap<Signature, u64>,
}

/// Condensed metric record with attribution, suitable for wire serialization.
#[derive(Debug, Serialize, Deserialize)]
struct CondensedMetricRecord {
    attribution: Option<Attribution>,
    handshake: CondensedHandshakeRecord,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CondensedHandshakeRecord {
    #[serde(rename = "hs")]
    handshake_count: u64,
    #[serde(rename = "n")]
    negotiated: ParamCount,

    #[serde(rename = "sslv2")]
    sslv2_client_hello: u64,
    #[serde(rename = "s")]
    supported: ParamCount,

    #[serde(rename = "hsd")]
    handshake_duration_us: u64,
    #[serde(rename = "hsc")]
    handshake_compute_us: u64,
}

impl CondensedHandshakeRecord {
    fn from_frozen_hs_record(record: &FrozenHandshakeRecord) -> Self {
        let negotiated = ParamCount {
            protocols: to_map(&record.negotiated_protocols, S2N_VERSIONS),
            ciphers: to_map(&record.negotiated_ciphers, CIPHERS_AVAILABLE_IN_S2N),
            group: to_map(&record.negotiated_groups, GROUPS_AVAILABLE_IN_S2N),
            signatures: to_map(&record.negotiated_signatures, SIGNATURE_SCHEMES_AVAILABLE_IN_S2N),
        };
        let supported = ParamCount {
            protocols: to_map(&record.supported_protocols, S2N_VERSIONS),
            ciphers: to_map(&record.supported_ciphers, CIPHERS_AVAILABLE_IN_S2N),
            group: to_map(&record.supported_groups, GROUPS_AVAILABLE_IN_S2N),
            signatures: to_map(&record.supported_signatures, SIGNATURE_SCHEMES_AVAILABLE_IN_S2N),
        };
        Self {
            handshake_count: record.handshake_count,
            negotiated,
            sslv2_client_hello: record.sslv2_client_hello,
            supported,
            handshake_duration_us: record.handshake_duration_us,
            handshake_compute_us: record.handshake_compute_us,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::Receiver;

    use super::*;
    use crate::test_utils::{ARBITRARY_POLICY_1, ARBITRARY_POLICY_2, TestEndpoint};

    #[test]
    fn record_contents_negotiated_parameters() {
        let endpoint = TestEndpoint::<Receiver<MetricRecord>>::new();

        let result = endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let record = endpoint.exporter.recv().unwrap();
        let record = record.handshake;

        assert_eq!(record.handshake_count, 1);
        assert_eq!(record.negotiated_ciphers.iter().sum::<u64>(), 1);
        assert_eq!(record.negotiated_groups.iter().sum::<u64>(), 1);
        assert_eq!(record.negotiated_signatures.iter().sum::<u64>(), 1);
        assert_eq!(record.negotiated_protocols.iter().sum::<u64>(), 1);

        let expected_version = result
            .client
            .actual_protocol_version()
            .unwrap()
            .to_static_string();
        let expected_index = TlsParam::Version
            .description_to_index(expected_version)
            .unwrap();
        assert_eq!(record.negotiated_protocols[expected_index], 1);

        let expected_cipher = result.client.cipher_suite().unwrap().to_owned();
        let expected_index =
            static_lists::cipher_ossl_name_to_index(expected_cipher.as_str()).unwrap();
        assert_eq!(record.negotiated_ciphers[expected_index], 1);

        let expected_group = result
            .client
            .selected_key_exchange_group()
            .unwrap()
            .to_owned();
        let expected_index = TlsParam::Group
            .description_to_index(expected_group.as_str())
            .unwrap();
        assert_eq!(record.negotiated_groups[expected_index], 1);

        let expected_sig = result.client.signature_scheme().unwrap().to_owned();
        let expected_index = TlsParam::SignatureScheme
            .description_to_index(expected_sig.as_str())
            .unwrap();
        assert_eq!(record.negotiated_signatures[expected_index], 1);
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

        let endpoint = TestEndpoint::<Receiver<MetricRecord>>::new();

        let _ = endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let record = endpoint.exporter.recv().unwrap();
        let record = record.handshake;

        let expected_version: Vec<usize> = EXPECTED_VERSIONS
            .iter()
            .map(|description| TlsParam::Version.description_to_index(description).unwrap())
            .collect();
        let expected_ciphers: Vec<usize> = EXPECTED_CIPHERS
            .iter()
            .map(|description| TlsParam::Cipher.description_to_index(description).unwrap())
            .collect();
        let expected_groups: Vec<usize> = EXPECTED_GROUPS
            .iter()
            .map(|description| TlsParam::Group.description_to_index(description).unwrap())
            .collect();
        let expected_sigs: Vec<usize> = EXPECTED_SIGS
            .iter()
            .map(|description| {
                TlsParam::SignatureScheme
                    .description_to_index(description)
                    .unwrap()
            })
            .collect();

        for (index, count) in record.supported_protocols.iter().enumerate() {
            let param = TlsParam::Version.index_to_description(index).unwrap();
            if expected_version.contains(&index) {
                assert_eq!(*count, 1, "{param} count is {count}, not one");
            } else {
                assert_eq!(*count, 0, "{param} count is {count}, not zero");
            }
        }

        for (index, count) in record.supported_ciphers.iter().enumerate() {
            let param = TlsParam::Cipher.index_to_description(index).unwrap();
            if expected_ciphers.contains(&index) {
                assert_eq!(*count, 1, "{param} count is {count}, not one");
            } else {
                assert_eq!(*count, 0, "{param} count is {count}, not zero");
            }
        }

        for (index, count) in record.supported_groups.iter().enumerate() {
            let param = TlsParam::Group.index_to_description(index).unwrap();
            if expected_groups.contains(&index) {
                assert_eq!(*count, 1, "{param} count is {count}, not one");
            } else {
                assert_eq!(*count, 0, "{param} count is {count}, not zero");
            }
        }

        for (index, count) in record.supported_signatures.iter().enumerate() {
            let param = TlsParam::SignatureScheme
                .index_to_description(index)
                .unwrap();
            if expected_sigs.contains(&index) {
                assert_eq!(*count, 1, "{param} count is {count}, not one");
            } else {
                assert_eq!(*count, 0, "{param} count is {count}, not zero");
            }
        }
    }

    #[test]
    fn multiple_records() {
        let endpoint = TestEndpoint::<Receiver<MetricRecord>>::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        endpoint.subscriber.finish_record();
        let record = endpoint.exporter.recv().unwrap();
        let record = record.handshake;

        assert_eq!(record.handshake_count, 3);
        assert_eq!(record.negotiated_ciphers.iter().sum::<u64>(), 3);
        assert_eq!(record.negotiated_groups.iter().sum::<u64>(), 3);
        assert_eq!(record.negotiated_signatures.iter().sum::<u64>(), 3);
        assert_eq!(record.negotiated_protocols.iter().sum::<u64>(), 3);
    }

    /// Make sure that the compute time is less than the overall handshake time.
    ///
    /// Additionally, make sure that three handshakes takes longer than one handshake.
    /// This provides some confidence that we are correctly e.g. adding amounts
    #[test]
    fn timers() {
        let endpoint = TestEndpoint::<Receiver<MetricRecord>>::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let single_handshake = endpoint.exporter.recv().unwrap().handshake;

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let multiple_handshakes = endpoint.exporter.recv().unwrap().handshake;

        assert!(single_handshake.handshake_compute_us <= single_handshake.handshake_duration_us);
        assert!(
            multiple_handshakes.handshake_compute_us <= multiple_handshakes.handshake_duration_us
        );

        assert!(single_handshake.handshake_compute_us < multiple_handshakes.handshake_compute_us);
        assert!(single_handshake.handshake_duration_us < multiple_handshakes.handshake_duration_us);
    }

    #[test]
    fn condensed_cbor() {
        let endpoint = TestEndpoint::<Receiver<MetricRecord>>::new();
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_2);
        endpoint.subscriber.finish_record();

        let record = endpoint.exporter.recv().unwrap();
        let condensed = CondensedHandshakeRecord::from_frozen_hs_record(&record.handshake);

        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&condensed, &mut cbor_buf).unwrap();
        std::fs::write("resources/condensed_sample.cbor", &cbor_buf).unwrap();

        let json_buf = serde_json::to_string(&condensed).unwrap();
        std::fs::write("resources/condensed_sample.json", &json_buf).unwrap();
    }
}
