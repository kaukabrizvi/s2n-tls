use crabgrind as cg;

fn main() {
    cg::cachegrind::stop_instrumentation();
    // Example usage with RSA keypair
    let keypair_rsa = regression::CertKeyPair::rsa();
    let config = regression::create_config(&s2n_tls::security::DEFAULT_TLS13, keypair_rsa).unwrap();
    // create a pair (client + server) with uses that config, start handshake measurement
    cg::cachegrind::start_instrumentation();
    let mut _pair = s2n_tls::testing::TestPair::from_config(&config);
    cg::cachegrind::stop_instrumentation();
}
