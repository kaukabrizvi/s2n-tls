use crabgrind as cg;
use s2n_tls::config::Builder;
use regression::CertKeyPair;

fn main() -> Result<(), s2n_tls::error::Error> {
    cg::cachegrind::stop_instrumentation();
    
    let mut builder = Builder::new();
    
    let keypair_rsa = CertKeyPair::rsa();
    
    cg::cachegrind::start_instrumentation();
    
    builder
        .load_pem(keypair_rsa.cert(), keypair_rsa.key())
        .expect("Unable to load cert/pem");
    builder.trust_pem(keypair_rsa.cert()).expect("load cert pem");
    let _config = builder.build().expect("Failed to build config");
    
    cg::cachegrind::stop_instrumentation();
    
    Ok(())
}
