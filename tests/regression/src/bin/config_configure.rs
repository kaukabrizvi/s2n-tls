use crabgrind as cg;
use s2n_tls::security;
use regression::{create_empty_config, configure_config};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    cg::cachegrind::stop_instrumentation();
    
    let builder = create_empty_config()?;
    
    cg::cachegrind::start_instrumentation();
    
    let builder = configure_config(builder, &security::DEFAULT_TLS13)?;
    
    let _config = builder.build().expect("Failed to build config");

    cg::cachegrind::stop_instrumentation();
    
    Ok(())
}
