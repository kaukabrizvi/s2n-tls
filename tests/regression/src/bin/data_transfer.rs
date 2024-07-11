use crabgrind as cg;

const DATA_CHUNK: &[u8] = &[3, 1, 4]; // The data chunk to be sent
const ONE_MB: usize = 1_048_576; // 1 MB in bytes

fn main() {
    cg::cachegrind::stop_instrumentation();
    let config = s2n_tls::testing::build_config(&s2n_tls::security::DEFAULT_TLS13).unwrap();
    // create a pair (client + server) which uses that config
    let mut pair = s2n_tls::testing::TestPair::from_config(&config);
    // assert a successful handshake
    assert!(pair.handshake().is_ok());
    // we can also do IO using the poll_* functions
    // this data is sent using the shared data buffers owned by the harness
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

    println!("Transferred {} bytes successfully.", total_bytes_sent);
}
