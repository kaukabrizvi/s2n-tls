// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::{config::Config, security::{DEFAULT_TLS13, Policy}};
use s2n_tls_tokio::TlsConnector;
use std::{error::Error, fs, time::{Duration, Instant}};
use tokio::{io::AsyncWriteExt, net::TcpStream};

/// NOTE: this ca is to be used for demonstration purposes only!
const DEFAULT_CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/ca-cert.pem");

// const DOMAIN: &str = "mtls-verify-rps-c54xl-control-488851166.elb-gamma.amazonaws.com";
const DOMAIN: &str = "mtls-verify-rps-c54xl-test-1432159227.elb-gamma.amazonaws.com";
const POLICY: &str = "rfc9151";
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value_t = String::from(DEFAULT_CA))]
    trust: String,
    addr: String,
}

async fn run_client() -> Result<Duration, Box<dyn Error>> {
    // Set up the configuration for new connections.
    // Minimally you will need a trust store.
    let mut config = Config::builder();
    let policy = Policy::from_version(POLICY).unwrap();
    config.set_security_policy(&policy)?;
    config.with_system_certs(true)?;
    unsafe {config.disable_x509_verification()?};

    // Create the TlsConnector based on the configuration.
    let client = TlsConnector::new(config.build()?);

    // Connect to the server.
    let stream = TcpStream::connect(format!("{DOMAIN}:443")).await?;
    let start = Instant::now();
    let tls = client.connect(DOMAIN, stream).await?;
    let elapsed = start.elapsed();
    println!("took {elapsed:?}");

    // println!("{:#?}", tls);

    // // Split the stream.
    // // This allows us to call read and write from different tasks.
    // let (mut reader, mut writer) = tokio::io::split(tls);

    // // Copy data from the server to stdout
    // tokio::spawn(async move {
    //     let mut stdout = tokio::io::stdout();
    //     tokio::io::copy(&mut reader, &mut stdout).await
    // });

    // // Send data from stdin to the server
    // let mut stdin = tokio::io::stdin();
    // tokio::io::copy(&mut stdin, &mut writer).await?;
    // writer.shutdown().await?;

    Ok(elapsed)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    const TRIALS: usize = 10;
    let mut time = Duration::from_hours(0);
    for i in 0..TRIALS {
        time += run_client().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let avg = time.div_f32(TRIALS as f32);
    println!("{POLICY} - {DOMAIN}: avg of {TRIALS} trials was {avg:?}");
    Ok(())
}
