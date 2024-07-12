use crabgrind as cg;
use s2n_tls::security;
use regression::{create_empty_config, configure_config, CertKeyPair, create_cert};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    cg::cachegrind::stop_instrumentation();
    
    let builder = create_empty_config()?;
    let builder = configure_config(builder, &security::DEFAULT_TLS13)?;
    
    let keypair_rsa = CertKeyPair::rsa();
    
    cg::cachegrind::start_instrumentation();
    
    let builder = create_cert(builder, keypair_rsa)?;
    
    cg::cachegrind::stop_instrumentation();
    
    builder.build().map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    
    Ok(())
}
