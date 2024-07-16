use crabgrind as cg;
use regression::create_empty_config;
use s2n_tls::config::Builder;

fn main() -> Result<(),  s2n_tls::error::Error >{
    
    let builder: Builder = create_empty_config()?;
    
    builder.build()?;

    cg::cachegrind::stop_instrumentation();
    
    Ok(())
}

