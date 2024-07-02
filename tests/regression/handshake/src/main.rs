use s2n_tls::{
    callbacks::VerifyHostNameCallback,
    config::{self, *},
    connection,
    enums::{self, Blinding},
    error,
};
use core::{
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
};
use libc::{c_int, c_void};
use std::{
    cell::RefCell,
    io::{Read, Write, Bytes},
    pin::Pin,
    collections::VecDeque,
    sync::Arc
};
type LocalDataBuffer = RefCell<VecDeque<u8>>;
use crabgrind as cg;

#[allow(dead_code)]
pub struct TestPair {
    pub server: connection::Connection,
    pub client: connection::Connection,
    server_tx_stream: Pin<Box<LocalDataBuffer>>,
    client_tx_stream: Pin<Box<LocalDataBuffer>>,
}

impl TestPair {
    pub fn handshake_with_config(config: &config::Config) -> Result<(), error::Error> {
        Self::from_configs(config, config).handshake()
    }
    pub fn from_config(config: &config::Config) -> Self {
        Self::from_configs(config, config)
    }

    pub fn from_configs(client_config: &config::Config, server_config: &config::Config) -> Self {
        let client_tx_stream = Box::pin(Default::default());
        let server_tx_stream = Box::pin(Default::default());

        let client = Self::register_connection(
            enums::Mode::Client,
            client_config,
            &client_tx_stream,
            &server_tx_stream,
        )
        .unwrap();

        let server = Self::register_connection(
            enums::Mode::Server,
            server_config,
            &server_tx_stream,
            &client_tx_stream,
        )
        .unwrap();

        Self {
            server,
            client,
            server_tx_stream,
            client_tx_stream,
        }
    }

    fn register_connection(
        mode: enums::Mode,
        config: &config::Config,
        send_ctx: &Pin<Box<LocalDataBuffer>>,
        recv_ctx: &Pin<Box<LocalDataBuffer>>,
    ) -> Result<connection::Connection, error::Error> {
        let mut conn = connection::Connection::new(mode);
        conn.set_config(config.clone())?
            .set_blinding(Blinding::SelfService)?
            .set_send_callback(Some(Self::send_cb))?
            .set_receive_callback(Some(Self::recv_cb))?;
        unsafe {
            conn.set_send_context(
                send_ctx as &LocalDataBuffer as *const LocalDataBuffer as *mut c_void,
            )?
            .set_receive_context(
                recv_ctx as &LocalDataBuffer as *const LocalDataBuffer as *mut c_void,
            )?;
        }
        Ok(conn)
    }

    pub fn handshake(&mut self) -> Result<(), error::Error> {
        loop {
            match (self.client.poll_negotiate(), self.server.poll_negotiate()) {
                (Poll::Ready(Ok(_)), Poll::Ready(Ok(_))) => return Ok(()),
                (_, Poll::Ready(Err(e))) => return Err(e),
                (Poll::Ready(Err(e)), _) => return Err(e),
                _ => { /* not ready, poll again */ }
            }
        }
    }

    unsafe extern "C" fn send_cb(context: *mut c_void, data: *const u8, len: u32) -> c_int {
        let context = &*(context as *const LocalDataBuffer);
        let data = core::slice::from_raw_parts(data, len as _);
        let bytes_written = context.borrow_mut().write(data).unwrap();
        bytes_written as c_int
    }

    unsafe extern "C" fn recv_cb(context: *mut c_void, data: *mut u8, len: u32) -> c_int {
        let context = &*(context as *const LocalDataBuffer);
        let data = core::slice::from_raw_parts_mut(data, len as _);
        match context.borrow_mut().read(data) {
            Ok(len) => {
                if len == 0 {
                    errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
                    -1
                } else {
                    len as c_int
                }
            }
            Err(err) => {
                panic!("{err:?}");
            }
        }
    }
}


fn main() {
    cg::cachegrind::stop_instrumentation();
    let config = s2n_tls::testing::build_config(&s2n_tls::security::DEFAULT_TLS13).unwrap();
    // create a pair (client + server) with uses that config
    cg::cachegrind::start_instrumentation();
    let mut pair = TestPair::from_config(&config);
    // assert a successful handshake
    assert!(pair.handshake().is_ok());
    // we can also do IO using the poll_* functions
    // this data is sent using the shared data buffers owned by the harness
    assert!(pair.server.poll_send(&[3, 1, 4]).is_ready());
    let mut buffer = [0; 3];
    assert!(pair.client.poll_recv(&mut buffer).is_ready());
    assert_eq!([3, 1, 4], buffer);
}

