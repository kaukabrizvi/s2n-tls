use crabgrind as cg;
use regression::{CertKeyPair, create_config};
use s2n_tls::security;
use s2n_tls::testing::TestPair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    cg::cachegrind::stop_instrumentation();
    
    // Example usage with RSA keypair
    let keypair_rsa = CertKeyPair::rsa();
    let config = create_config(&security::DEFAULT_TLS13, keypair_rsa)?;
    
    // Create a pair (client + server) using that config, start handshake measurement
    let mut pair = TestPair::from_config(&config);
    
    // Assert a successful handshake
    cg::cachegrind::start_instrumentation();
    assert!(pair.handshake().is_ok());
    cg::cachegrind::stop_instrumentation();
    
    Ok(())
}
