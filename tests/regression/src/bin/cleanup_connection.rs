use crabgrind as cg;
use s2n_tls::security;
use s2n_tls::testing::TestPair;
use regression::{set_config, CertKeyPair};

fn main() -> Result<(), s2n_tls::error::Error> {
    // Stop instrumentation before the setup
    cg::cachegrind::stop_instrumentation();

    // Create and configure the connection
    let keypair_rsa = CertKeyPair::rsa();
    let config = set_config(&security::DEFAULT_TLS13, keypair_rsa)?;

    // Create a new connection
    let mut pair = TestPair::from_config(&config);

    // Perform the handshake
    assert!(pair.handshake().is_ok());

    // Start instrumentation for cleanup benchmarking
    cg::cachegrind::start_instrumentation();

    // Cleanup the connection
    pair.server.wipe()?;
    pair.client.wipe()?;

    // Stop instrumentation after cleanup
    cg::cachegrind::stop_instrumentation();

    Ok(())
}
