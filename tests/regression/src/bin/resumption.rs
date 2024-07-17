use crabgrind as cg;
use regression::{CertKeyPair, InsecureAcceptAllCertificatesHandler};
use s2n_tls::security;
use s2n_tls::config::Builder;
use std::{
    sync::{Arc, Mutex},
    time::SystemTime,
    pin::Pin,
};
use futures_test::task::noop_waker;
use s2n_tls::connection::{self, Connection};
use s2n_tls::callbacks::{SessionTicket, SessionTicketCallback, ConnectionFuture};

#[derive(Default, Clone)]
pub struct SessionTicketHandler {
    stored_ticket: Arc<Mutex<Option<Vec<u8>>>>,
}

// Implement the session ticket callback that stores the SessionTicket type
impl SessionTicketCallback for SessionTicketHandler {
    fn on_session_ticket(
        &self,
        _connection: &mut connection::Connection,
        session_ticket: &SessionTicket,
    ) {
        let size = session_ticket.len().unwrap();
        let mut data = vec![0; size];
        session_ticket.data(&mut data).unwrap();
        let mut ptr = (*self.stored_ticket).lock().unwrap();
        if ptr.is_none() {
            *ptr = Some(data);
        }
    }
}

impl s2n_tls::config::ConnectionInitializer for SessionTicketHandler {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        if let Some(ticket) = (*self.stored_ticket).lock().unwrap().as_deref() {
            connection.set_session_ticket(ticket)?;
        }
        Ok(None)
    }
}

const KEY: [u8; 16] = [0; 16];
const KEYNAME: [u8; 3] = [1, 3, 4];

fn validate_session_ticket(conn: &Connection) -> Result<(), s2n_tls::error::Error> {
    assert!(conn.session_ticket_length()? > 0);
    let mut session = vec![0; conn.session_ticket_length()?];
    assert_eq!(
        conn.session_ticket(&mut session)?,
        conn.session_ticket_length()?
    );
    assert_ne!(session, vec![0; conn.session_ticket_length()?]);
    Ok(())
}

fn main() -> Result<(), s2n_tls::error::Error> {
    cg::cachegrind::stop_instrumentation();
    let keypair = CertKeyPair::default();

    // Initialize config for server with a ticket key
    let mut server_config_builder = Builder::new();
    server_config_builder
        .add_session_ticket_key(&KEYNAME, &KEY, SystemTime::now())?
        .load_pem(keypair.cert(), keypair.key())?
        .set_security_policy(&security::DEFAULT_TLS13)?;
    let server_config = server_config_builder.build()?;

    let handler = SessionTicketHandler::default();

    // Create config for client
    let mut client_config_builder = Builder::new();
    client_config_builder
        .enable_session_tickets(true)?
        .set_session_ticket_callback(handler.clone())?
        .set_connection_initializer(handler)?
        .trust_pem(keypair.cert())?
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?
        .set_security_policy(&security::DEFAULT_TLS13)?;
    let client_config = client_config_builder.build()?;

    // 1st handshake: no session ticket, so no resumption
    {
        let mut pair = s2n_tls::testing::TestPair::from_configs(&client_config, &server_config);
        // Client needs a waker due to its use of an async callback
        pair.client.set_waker(Some(&noop_waker()))?;
        pair.handshake()?;

        // Do a recv call on the client side to read a session ticket. Poll function
        // returns pending since no application data was read, however it is enough
        // to collect the session ticket.
        assert!(pair.client.poll_recv(&mut [0]).is_pending());

        // Assert the resumption status
        assert!(!pair.client.resumed());

        // Validate that a ticket is available
        validate_session_ticket(&pair.client)?;
    }

    // Start Cachegrind instrumentation for the second handshake
    cg::cachegrind::start_instrumentation();

    // 2nd handshake: should be able to use the session ticket from the first
    //                handshake (stored on the config) to resume
    {
        let mut pair = s2n_tls::testing::TestPair::from_configs(&client_config, &server_config);
        // Client needs a waker due to its use of an async callback
        pair.client.set_waker(Some(&noop_waker()))?;
        pair.handshake()?;

        // Do a recv call on the client side to read a session ticket. Poll function
        // returns pending since no application data was read, however it is enough
        // to collect the session ticket.
        assert!(pair.client.poll_recv(&mut [0]).is_pending());

        // Assert the resumption status
        assert!(pair.client.resumed());

        // Validate that a ticket is available
        validate_session_ticket(&pair.client)?;
    }

    // Stop Cachegrind instrumentation
    cg::cachegrind::stop_instrumentation();

    Ok(())
}
