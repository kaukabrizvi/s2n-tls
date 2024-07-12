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
    cg::cachegrind::start_instrumentation();
    let mut _pair = TestPair::from_config(&config);
    cg::cachegrind::stop_instrumentation();
    
    Ok(())
}
