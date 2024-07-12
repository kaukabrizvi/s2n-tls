use crabgrind as cg;
use s2n_tls::security;
use s2n_tls::testing::TestPair;

const DATA_CHUNK: &[u8] = &[3, 1, 4]; // The data chunk to be sent
const ONE_MB: usize = 1_048_576; // 1 MB in bytes

fn main() -> Result<(), Box<dyn std::error::Error>> {
    cg::cachegrind::stop_instrumentation();
    
    let config = s2n_tls::testing::build_config(&security::DEFAULT_TLS13).expect("Failed to build config");
    
    // Create a pair (client + server) which uses that config
    let mut pair = TestPair::from_config(&config);
    
    // Assert a successful handshake
    assert!(pair.handshake().is_ok());
    
    // We can also do IO using the poll_* functions
    // This data is sent using the shared data buffers owned by the harness
    cg::cachegrind::start_instrumentation();
    
    let mut total_bytes_sent = 0;
    let mut buffer = vec![0u8; DATA_CHUNK.len()]; // Buffer to receive data

    while total_bytes_sent < ONE_MB {
        // Send data chunk
        while !pair.server.poll_send(DATA_CHUNK).is_ready() {
            // Polling until the send is ready
        }
        total_bytes_sent += DATA_CHUNK.len();

        // Receive data chunk
        while !pair.client.poll_recv(&mut buffer).is_ready() {
            // Polling until the receive is ready
        }

        // Verify that the received data matches the sent data
        assert_eq!(DATA_CHUNK, &buffer[..DATA_CHUNK.len()]);
    }

    cg::cachegrind::stop_instrumentation();
    
    println!("Transferred {} bytes successfully.", total_bytes_sent);
    
    Ok(())
}
