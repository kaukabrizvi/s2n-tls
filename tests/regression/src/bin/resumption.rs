use crabgrind as cg;
use regression::{CertKeyPair, InsecureAcceptAllCertificatesHandler};
use s2n_tls::security;
use s2n_tls::config::Builder;
use std::{
    error::Error,
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

fn validate_session_ticket(conn: &Connection) -> Result<(), Box<dyn Error>> {
    assert!(conn.session_ticket_length()? > 0);
    let mut session = vec![0; conn.session_ticket_length()?];
    assert_eq!(
        conn.session_ticket(&mut session)?,
        conn.session_ticket_length()?
    );
    assert_ne!(session, vec![0; conn.session_ticket_length()?]);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // create config for client
    let mut client_config_builder = Builder::new();
    client_config_builder
        .enable_session_tickets(true)?
        .set_session_ticket_callback(handler.clone())?
        .set_connection_initializer(handler.clone())?
        .trust_pem(keypair.cert())?
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?
        .set_security_policy(&security::DEFAULT_TLS13)?;
    let client_config = client_config_builder.build()?;

    // Initial handshake, no instrumentation
    {
        let mut pair = s2n_tls::testing::TestPair::from_configs(&client_config, &server_config);
        pair.client.set_waker(Some(&noop_waker()))?;
        pair.handshake()?;
        assert!(!pair.client.resumed());
        validate_session_ticket(&pair.client)?;
    }

    // Session resumption handshake with instrumentation
    cg::cachegrind::start_instrumentation();
    {
        let mut pair = s2n_tls::testing::TestPair::from_configs(&client_config, &server_config);
        pair.client.set_waker(Some(&noop_waker()))?;
        pair.handshake()?;
        assert!(pair.client.resumed());
        validate_session_ticket(&pair.client)?;
        validate_session_ticket(&pair.server)?;
    }
    cg::cachegrind::stop_instrumentation();

    Ok(())
}
