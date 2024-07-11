use crabgrind as cg;
use s2n_tls::security;

fn main() {
    cg::cachegrind::stop_instrumentation();
    let builder = regression::create_empty_config().unwrap();
    cg::cachegrind::start_instrumentation();
    let builder = regression::configure_config(builder, &crate::security::DEFAULT_TLS13);
    let config = builder.unwrap().build(); //loads certs so maybe not the right place for it.
    config.ok();
}
