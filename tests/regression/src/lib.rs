use s2n_tls::{callbacks::VerifyHostNameCallback, config::Builder, security};
type Error = Box<dyn std::error::Error>;

pub fn create_empty_config() -> Result <s2n_tls::config::Builder, s2n_tls::error::Error> {
    Ok(Builder::new())
}

pub struct CertKeyPair {
    cert_path: &'static str,
    cert: &'static [u8],
    key: &'static [u8],
}

impl CertKeyPair {
    pub fn cert_path(&self) -> &'static str {
        self.cert_path
    }

    pub fn cert(&self) -> &'static [u8] {
        self.cert
    }

    pub fn key(&self) -> &'static [u8] {
        self.key
    }

    pub fn rsa() -> Self {
        CertKeyPair {
            cert_path: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../tests/pems/rsa_4096_sha512_client_cert.pem",
            ),
            cert: &include_bytes!("../../../tests/pems/rsa_4096_sha512_client_cert.pem")[..],
            key: &include_bytes!("../../../tests/pems/rsa_4096_sha512_client_key.pem")[..],
        }
    }

    pub fn ecdsa() -> Self {
        CertKeyPair {
            cert_path: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../tests/pems/ecdsa_p256_client_cert.pem",
            ),
            cert: &include_bytes!("../../../tests/pems/ecdsa_p384_pkcs1_cert.pem")[..],
            key: &include_bytes!("../../../tests/pems/ecdsa_p384_pkcs1_key.pem")[..],
        }
    }
}

impl Default for CertKeyPair {
    fn default() -> Self {
        CertKeyPair::rsa()
    }
}

pub struct InsecureAcceptAllCertificatesHandler {}

impl VerifyHostNameCallback for InsecureAcceptAllCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}

// Function to create config
pub fn create_config(
    cipher_prefs: &security::Policy,
    keypair: CertKeyPair
) -> Result<s2n_tls::config::Config, Error> {
    let builder = Builder::new();
    let builder = configure_config(builder, cipher_prefs)?;
    let builder = create_cert(builder, keypair)?;
    builder.build().map_err(|e| e.into())
}

// Function to configure config
pub fn configure_config(
    mut builder: s2n_tls::config::Builder,
    cipher_prefs: &security::Policy
) -> Result<s2n_tls::config::Builder, Error> {
    builder
        .set_security_policy(cipher_prefs)
        .expect("Unable to set config cipher preferences");
    builder
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
        .expect("Unable to set a host verify callback.");
    Ok(builder)
}

pub fn create_cert(
    mut builder: s2n_tls::config::Builder,
    keypair: CertKeyPair
) -> Result<s2n_tls::config::Builder, Error> {
    builder
        .load_pem(keypair.cert(), keypair.key())
        .expect("Unable to load cert/pem");
    builder.trust_pem(keypair.cert()).expect("load cert pem");
    Ok(builder)
}
