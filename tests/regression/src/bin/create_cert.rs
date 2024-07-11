use crabgrind as cg;
use s2n_tls::security;

fn main() {
    cg::cachegrind::stop_instrumentation();
    let builder = regression::create_empty_config().unwrap();
    let builder = regression::configure_config(builder, &crate::security::DEFAULT_TLS13).unwrap();
    let keypair_rsa = regression::CertKeyPair::rsa();
    cg::cachegrind::start_instrumentation();
    let builder = regression::create_cert(builder, keypair_rsa);
    cg::cachegrind::stop_instrumentation();
    let config = builder.unwrap().build(); 
    config.ok();
}