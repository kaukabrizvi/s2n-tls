// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module contains the static lists of all possible values emitted by the
//! s2n-tls "getter" APIs. These static lists are important because they allow us
//! to maintain an array of atomic counters instead of having to resort to a hashmap

// allowing unused lints while crate is under development, many of these structs
// won't be used until the subscriber is actually implemented
#![allow(unused)]

use std::{
    collections::HashMap,
    ffi::c_char,
    fmt::Display,
    sync::{LazyLock, Mutex},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serialize/deserialize a 2-byte value as a hex string like "0x0303".
/// Serialize/deserialize wrapper types as their inner u16 value.
mod hex_id {
    use super::*;

    pub(super) fn serialize_u16<S: Serializer>(val: u16, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u16(val)
    }

    pub(super) fn deserialize_u16<'de, D: Deserializer<'de>>(d: D) -> Result<u16, D::Error> {
        u16::deserialize(d)
    }

    pub(super) fn serialize_bytes<S: Serializer>(bytes: &[u8; 2], s: S) -> Result<S::Ok, S::Error> {
        serialize_u16(u16::from_be_bytes(*bytes), s)
    }

    pub(super) fn deserialize_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 2], D::Error> {
        deserialize_u16(d).map(|v| v.to_be_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsParam {
    /// E.g. TLS 1.2
    Version,
    /// E.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    Cipher,
    /// E.g. SecP256r1MLKEM768
    Group,
    /// E.g. ecdsa_secp384r1_sha384
    SignatureScheme,
}

pub(crate) const GROUP_COUNT: usize = GROUPS_AVAILABLE_IN_S2N.len();
pub(crate) const CIPHER_COUNT: usize = CIPHERS_AVAILABLE_IN_S2N.len();
pub(crate) const SIGNATURE_COUNT: usize = SIGNATURE_SCHEMES_AVAILABLE_IN_S2N.len();
pub(crate) const PROTOCOL_COUNT: usize = VERSIONS_AVAILABLE_IN_S2N.len();

use s2n_codec::{zerocopy::U16, DecoderValue};
#[cfg(test)]
use s2n_tls_sys_internal::{
    s2n_cipher_suite, s2n_ecc_named_curve, s2n_kem_group, s2n_signature_scheme,
};
use zerocopy::{BigEndian, ByteOrder, FromBytes, Immutable, Order, Unaligned};

impl TlsParam {
    pub fn index_to_description(&self, index: usize) -> Option<&'static str> {
        match self {
            TlsParam::Version => VERSIONS_AVAILABLE_IN_S2N.get(index).copied(),
            TlsParam::Cipher => CIPHER_NAMES.get(index).map(|(iana, _)| *iana),
            TlsParam::Group => GROUP_NAMES.get(index).copied(),
            TlsParam::SignatureScheme => SIGNATURE_NAMES.get(index).copied(),
        }
    }

    pub fn description_to_index(&self, name: &str) -> Option<usize> {
        match self {
            TlsParam::Version => VERSIONS_AVAILABLE_IN_S2N
                .iter()
                .position(|version| *version == name),
            TlsParam::Cipher => CIPHER_NAMES
                .iter()
                .position(|(iana, _)| *iana == name),
            TlsParam::Group => GROUP_NAMES
                .iter()
                .position(|desc| *desc == name),
            TlsParam::SignatureScheme => SIGNATURE_NAMES
                .iter()
                .position(|desc| *desc == name),
        }
    }
}

impl Display for TlsParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsParam::Version => write!(f, "version"),
            TlsParam::Cipher => write!(f, "cipher"),
            TlsParam::Group => write!(f, "group"),
            TlsParam::SignatureScheme => write!(f, "signature_scheme"),
        }
    }
}

/// get the counter index from the openssl name. We prefer to work with IANA id's
/// but s2n-tls returns the OpenSSL cipher name.
pub fn cipher_ossl_name_to_index(name: &str) -> Option<usize> {
    CIPHER_NAMES
        .iter()
        .position(|(_iana, openssl)| *openssl == name)
}

pub trait ToStaticString {
    fn to_static_string(&self) -> &'static str;
}

impl ToStaticString for s2n_tls::enums::Version {
    fn to_static_string(&self) -> &'static str {
        match self {
            s2n_tls::enums::Version::SSLV3 => "SSLv3",
            s2n_tls::enums::Version::TLS10 => "TLSv1_0",
            s2n_tls::enums::Version::TLS11 => "TLSv1_1",
            s2n_tls::enums::Version::TLS12 => "TLSv1_2",
            s2n_tls::enums::Version::TLS13 => "TLSv1_3",
            _ => "unknown",
        }
    }
}

/// This list should match the negotiable TLS versions in s2n-tls, and determines
/// how many "counter" slots the negotiated version metrics have.
pub const VERSIONS_AVAILABLE_IN_S2N: &[&str] =
    &["SSLv3", "TLSv1_0", "TLSv1_1", "TLSv1_2", "TLSv1_3"];

pub const S2N_VERSIONS: &[Version] = &[
    Version::SSL_V3,
    Version::TLS_1_0,
    Version::TLS_1_1,
    Version::TLS_1_2,
    Version::TLS_1_3,
];

/// Convert a pointer to null terminated bytes into a static string
///
/// Safety: the memory pointed to by value is static
/// Safety: the bytes are null terminated
#[cfg(test)]
unsafe fn static_memory_to_str(value: *const c_char) -> &'static str {
    unsafe {
        use std::ffi::CStr;
        CStr::from_ptr(value).to_str().unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Version(pub(crate) s2n_codec::zerocopy::U16);

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        hex_id::serialize_u16(self.0.get(), s)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        hex_id::deserialize_u16(d).map(|v| Self(U16::new(v)))
    }
}

impl Version {
    pub const SSL_V3: Version = Version(U16::new(0x0300));
    pub const TLS_1_0: Version = Version(U16::new(0x0301));
    pub const TLS_1_1: Version = Version(U16::new(0x0302));
    pub const TLS_1_2: Version = Version(U16::new(0x0303));
    pub const TLS_1_3: Version = Version(U16::new(0x0304));

    pub fn known_description(&self) -> Option<&'static str> {
        match *self {
            Self::SSL_V3 => Some("SSLv3"),
            Self::TLS_1_0 => Some("TLSv1_0"),
            Self::TLS_1_1 => Some("TLSv1_1"),
            Self::TLS_1_2 => Some("TLSv1_2"),
            Self::TLS_1_3 => Some("TLSv1_3"),
            _ => None,
        }
    }
}

impl<'a> DecoderValue<'a> for Version {
    fn decode(bytes: s2n_codec::DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (value, bytes) = bytes.decode()?;
        Ok((Self(value), bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Cipher(pub(crate) [u8; 2]);

impl Serialize for Cipher {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        hex_id::serialize_bytes(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for Cipher {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        hex_id::deserialize_bytes(d).map(Self)
    }
}

impl Cipher {
    pub(crate) const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: Self = Cipher([0, 255]);

    /// e.g. "TLS_AES_256_GCM_SHA384"
    ///
    /// `None` if the group is not supported by s2n-tls
    pub fn known_description(&self) -> Option<&'static str> {
        CIPHERS_AVAILABLE_IN_S2N
            .iter()
            .position(|c| *c == *self)
            .and_then(|i| CIPHER_NAMES.get(i))
            .map(|(iana, _)| *iana)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Signature(pub(crate) s2n_codec::zerocopy::U16);

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        hex_id::serialize_u16(self.0.get(), s)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        hex_id::deserialize_u16(d).map(|v| Self(U16::new(v)))
    }
}

impl Signature {
    pub fn known_description(&self) -> Option<&'static str> {
        SIGNATURE_SCHEMES_AVAILABLE_IN_S2N
            .iter()
            .position(|s| *s == *self)
            .and_then(|i| SIGNATURE_NAMES.get(i))
            .copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Group(pub(crate) s2n_codec::zerocopy::U16);

impl Serialize for Group {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        hex_id::serialize_u16(self.0.get(), s)
    }
}

impl<'de> Deserialize<'de> for Group {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        hex_id::deserialize_u16(d).map(|v| Self(U16::new(v)))
    }
}

impl Group {
    /// e.g. "secp256r1"
    ///
    /// "unknown" if the group is not supported by s2n-tls
    pub fn known_description(&self) -> Option<&'static str> {
        GROUPS_AVAILABLE_IN_S2N
            .iter()
            .position(|g| *g == *self)
            .and_then(|i| GROUP_NAMES.get(i))
            .copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherInformation {
    cipher: Cipher,
    iana_description: &'static str,
    openssl_name: &'static str,
}

impl CipherInformation {
    #[cfg(test)]
    fn from_s2n_cipher_suite(s2n_cipher: &s2n_cipher_suite) -> Self {
        unsafe {
            // SAFETY: the name and iana_name fields are both static, null-terminated
            // strings
            let openssl_name = static_memory_to_str(s2n_cipher.name);
            let iana_description = static_memory_to_str(s2n_cipher.iana_name);
            let iana_value = s2n_cipher.iana_value;
            Self{
                iana_description, 
                cipher:  Cipher(iana_value),
                openssl_name
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct GroupInformation {
    iana_description: &'static str,
    group: Group,
}

#[cfg(test)]
impl GroupInformation {
    fn from_s2n_kem_group(kem_group: &s2n_kem_group) -> Self {
        unsafe {
            let iana_description = static_memory_to_str(kem_group.name);
            let iana_id = kem_group.iana_id;
            Self { iana_description, group: Group(iana_id.into()) }
        }
    }

    fn from_s2n_ecc_curve(curve: &s2n_ecc_named_curve) -> Self {
        unsafe {
            let iana_description = static_memory_to_str(curve.name);
            let iana_id = curve.iana_id;
            Self { iana_description, group: Group(U16::new(iana_id)) }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SignatureSchemeInformation {
    /// This is the IANA description only where that is unambiguously correct.
    ///
    /// Examples of non-iana signatures include legacy hashes (e.g. `legacy_ecdsa_sha224`)
    /// and ECDSA signatures (e.g. `ecdsa_sha256`).
    description: &'static str,
    signature: Signature,
}

impl SignatureSchemeInformation {
    pub fn description(&self) -> &'static str {
        self.description
    }

    #[cfg(test)]
    fn from_s2n_signature_scheme(scheme: &s2n_signature_scheme) -> Self {
        unsafe {
            let description = static_memory_to_str(scheme.name);
            let iana_value = scheme.iana_value;
            Self { description, signature: Signature(U16::new(iana_value)) }
        }
    }
}

/// We are required to track OpenSSL naming because that is what the s2n-tls 
/// connection API's return.
#[rustfmt::skip]
pub(crate) const CIPHER_NAMES: &[(&'static str, &'static str)] = &[
    ("TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256" ),
    ("TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384" ),
    ("TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256" ),
    ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE-RSA-DES-CBC3-SHA" ),
    ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES128-SHA" ),
    ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE-RSA-AES128-SHA256" ),
    ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE-RSA-AES128-GCM-SHA256" ),
    ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE-RSA-AES256-SHA" ),
    ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE-RSA-AES256-SHA256" ),
    ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384" ),
    ("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE-RSA-CHACHA20-POLY1305" ),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE-ECDSA-AES128-SHA" ),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256" ),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256" ),
    ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE-ECDSA-AES256-SHA" ),
    ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE-ECDSA-AES256-SHA384" ),
    ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384" ),
    ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305" ),
    ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-RSA-DES-CBC3-SHA" ),
    ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-SHA" ),
    ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256" ),
    ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256" ),
    ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE-RSA-AES256-SHA" ),
    ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384" ),
    ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384" ),
    ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE-RSA-CHACHA20-POLY1305" ),
    ("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE-RSA-RC4-SHA" ),
    ("TLS_NULL_WITH_NULL_NULL", "TLS_NULL_WITH_NULL_NULL" ),
    ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA" ),
    ("TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA" ),
    ("TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256" ),
    ("TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256" ),
    ("TLS_RSA_WITH_AES_256_CBC_SHA", "AES256-SHA" ),
    ("TLS_RSA_WITH_AES_256_CBC_SHA256", "AES256-SHA256" ),
    ("TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384" ),
    ("TLS_RSA_WITH_RC4_128_MD5", "RC4-MD5" ),
    ("TLS_RSA_WITH_RC4_128_SHA", "RC4-SHA"),
];

pub(crate) const CIPHERS_AVAILABLE_IN_S2N: &[Cipher] = &[
    Cipher([19, 1]),
    Cipher([19, 2]),
    Cipher([19, 3]),
    Cipher([0, 22]),
    Cipher([0, 51]),
    Cipher([0, 103]),
    Cipher([0, 158]),
    Cipher([0, 57]),
    Cipher([0, 107]),
    Cipher([0, 159]),
    Cipher([204, 170]),
    Cipher([192, 9]),
    Cipher([192, 35]),
    Cipher([192, 43]),
    Cipher([192, 10]),
    Cipher([192, 36]),
    Cipher([192, 44]),
    Cipher([204, 169]),
    Cipher([192, 18]),
    Cipher([192, 19]),
    Cipher([192, 39]),
    Cipher([192, 47]),
    Cipher([192, 20]),
    Cipher([192, 40]),
    Cipher([192, 48]),
    Cipher([204, 168]),
    Cipher([192, 17]),
    Cipher([0, 0]),
    Cipher([0, 10]),
    Cipher([0, 47]),
    Cipher([0, 60]),
    Cipher([0, 156]),
    Cipher([0, 53]),
    Cipher([0, 61]),
    Cipher([0, 157]),
    Cipher([0, 4]),
    Cipher([0, 5]),
];

pub(crate) const GROUPS_AVAILABLE_IN_S2N: &[Group] = &[
    Group(U16::new(514)),
    Group(U16::new(4587)),
    Group(U16::new(4589)),
    Group(U16::new(4588)),
    Group(U16::new(23)),
    Group(U16::new(24)),
    Group(U16::new(25)),
    Group(U16::new(29)),
];

pub(crate) const GROUP_NAMES: &[&str] = &[
    "MLKEM1024",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "X25519MLKEM768",
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "x25519",
];

pub(crate) const SIGNATURE_SCHEMES_AVAILABLE_IN_S2N: &[Signature] = &[
    Signature(U16::new(515)),
    Signature(U16::new(1027)),
    Signature(U16::new(1283)),
    Signature(U16::new(1539)),
    Signature(U16::new(771)),
    Signature(U16::new(65535)),
    Signature(U16::new(769)),
    Signature(U16::new(2308)),
    Signature(U16::new(2309)),
    Signature(U16::new(2310)),
    Signature(U16::new(513)),
    Signature(U16::new(1025)),
    Signature(U16::new(1281)),
    Signature(U16::new(1537)),
    Signature(U16::new(2057)),
    Signature(U16::new(2058)),
    Signature(U16::new(2059)),
    Signature(U16::new(2052)),
    Signature(U16::new(2053)),
    Signature(U16::new(2054)),
];

pub(crate) const SIGNATURE_NAMES: &[&str] = &[
    "ecdsa_sha1",
    "ecdsa_sha256",
    "ecdsa_sha384",
    "ecdsa_sha512",
    "legacy_ecdsa_sha224",
    "legacy_rsa_md5_sha1",
    "legacy_rsa_sha224",
    "mldsa44",
    "mldsa65",
    "mldsa87",
    "rsa_pkcs1_sha1",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "rsa_pss_pss_sha256",
    "rsa_pss_pss_sha384",
    "rsa_pss_pss_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        ffi::{CStr, c_char, c_int, c_void},
    };

    /// return all of the ciphers defined in any s2n-tls security policy
    fn all_available_ciphers() -> Vec<CipherInformation> {
        let ciphers: HashSet<CipherInformation> = s2n_tls_sys_internal::security_policy_table()
            .iter()
            .flat_map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                let names: Vec<CipherInformation> = sp
                    .ciphers()
                    .iter()
                    .cloned()
                    .map(CipherInformation::from_s2n_cipher_suite)
                    .collect();
                names
            })
            .collect();
        let mut ciphers: Vec<CipherInformation> = ciphers.into_iter().collect();
        ciphers.sort_by_key(|cipher| cipher.iana_description);
        ciphers
    }

    /// return all of the groups defined in any s2n-tls security policy
    fn all_available_groups() -> Vec<GroupInformation> {
        let groups: HashSet<GroupInformation> = s2n_tls_sys_internal::security_policy_table()
            .iter()
            .flat_map(|sp| {
                let sp = unsafe { &*sp.security_policy };
                let curves = sp
                    .curves()
                    .iter()
                    .map(|curve| GroupInformation::from_s2n_ecc_curve(curve));
                let kem_groups = sp
                    .kems()
                    .iter()
                    .map(|kem| GroupInformation::from_s2n_kem_group(kem));
                curves.chain(kem_groups).collect::<Vec<GroupInformation>>()
            })
            .collect();
        let mut groups: Vec<GroupInformation> = groups.into_iter().collect();
        groups.sort_by_key(|group| group.iana_description);
        groups
    }

    /// return all of the signatures defined in any s2n-tls security policy
    fn all_available_signatures() -> Vec<SignatureSchemeInformation> {
        let sigs: HashSet<SignatureSchemeInformation> =
            s2n_tls_sys_internal::security_policy_table()
                .iter()
                .flat_map(|sp| {
                    let sp = unsafe { &*sp.security_policy };
                    sp.signatures()
                        .iter()
                        .map(|sig| SignatureSchemeInformation::from_s2n_signature_scheme(sig))
                })
                .collect();
        let mut sigs: Vec<SignatureSchemeInformation> = sigs.into_iter().collect();
        sigs.sort_by_key(|sig| sig.description);
        sigs
    }

    #[test]
    fn all_ciphers_in_static_list() {
        let ciphers = all_available_ciphers();
        let expected_ciphers: Vec<Cipher> = ciphers.iter().map(|c| c.cipher).collect();
        let expected_names: Vec<(&str, &str)> = ciphers
            .iter()
            .map(|c| (c.iana_description, c.openssl_name))
            .collect();
        assert_eq!(CIPHERS_AVAILABLE_IN_S2N, expected_ciphers.as_slice());
        assert_eq!(CIPHER_NAMES, expected_names.as_slice());
    }

    #[test]
    fn all_groups_in_static_list() {
        let groups = all_available_groups();
        let expected_groups: Vec<Group> = groups.iter().map(|g| g.group).collect();
        let expected_names: Vec<&str> = groups.iter().map(|g| g.iana_description).collect();
        assert_eq!(GROUPS_AVAILABLE_IN_S2N, expected_groups.as_slice());
        assert_eq!(GROUP_NAMES, expected_names.as_slice());
    }

    #[test]
    fn all_signature_schemes_in_static_list() {
        let schemes = all_available_signatures();
        let expected_sigs: Vec<Signature> = schemes.iter().map(|s| s.signature).collect();
        let expected_names: Vec<&str> = schemes.iter().map(|s| s.description).collect();
        assert_eq!(SIGNATURE_SCHEMES_AVAILABLE_IN_S2N, expected_sigs.as_slice());
        assert_eq!(SIGNATURE_NAMES, expected_names.as_slice());
    }

    #[test]
    fn index_and_name_lookup() {
        for (index, (iana_desc, _)) in CIPHER_NAMES.iter().enumerate() {
            let returned_index = TlsParam::Cipher
                .description_to_index(iana_desc)
                .unwrap();
            let returned_description = TlsParam::Cipher
                .index_to_description(returned_index)
                .unwrap();
            assert_eq!(returned_description, *iana_desc);
            assert_eq!(returned_index, index);
        }

        for (index, name) in GROUP_NAMES.iter().enumerate() {
            let returned_index = TlsParam::Group
                .description_to_index(name)
                .unwrap();
            let returned_description = TlsParam::Group
                .index_to_description(returned_index)
                .unwrap();
            assert_eq!(returned_description, *name);
            assert_eq!(returned_index, index);
        }

        for (index, name) in SIGNATURE_NAMES.iter().enumerate() {
            let returned_index = TlsParam::SignatureScheme
                .description_to_index(name)
                .unwrap();
            let returned_description = TlsParam::SignatureScheme
                .index_to_description(returned_index)
                .unwrap();
            assert_eq!(returned_description, *name);
            assert_eq!(returned_index, index);
        }
    }
}
