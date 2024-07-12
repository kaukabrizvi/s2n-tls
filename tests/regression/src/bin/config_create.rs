use crabgrind as cg;
use regression::create_empty_config;
use s2n_tls::config::Builder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    let builder: Builder = create_empty_config()?;
    
    builder.build().map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    cg::cachegrind::stop_instrumentation();
    
    Ok(())
}

