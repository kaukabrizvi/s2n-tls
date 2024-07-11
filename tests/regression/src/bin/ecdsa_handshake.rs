use crabgrind as cg;

fn main() {
    cg::cachegrind::stop_instrumentation();
    let keypair_ecdsa = regression::CertKeyPair::ecdsa();
    let config = regression::create_config(&s2n_tls::security::DEFAULT_TLS13, keypair_ecdsa).unwrap();
    // create a pair (client + server) with uses that config, start measurement
    let mut pair = s2n_tls::testing::TestPair::from_config(&config);
    // assert a successful handshake
    cg::cachegrind::start_instrumentation();
    assert!(pair.handshake().is_ok());
    cg::cachegrind::stop_instrumentation();
}
