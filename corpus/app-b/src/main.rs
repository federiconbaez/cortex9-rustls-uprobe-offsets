// app-b: cliente y servidor TLS en hilos sobre un socketpair Unix, vía StreamOwned.
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

const CA: &[u8] = include_bytes!("../../fixtures/ca.pem");
const LEAF: &[u8] = include_bytes!("../../fixtures/leaf.pem");
const KEY: &[u8] = include_bytes!("../../fixtures/leaf.pk8.pem");

fn main() {
    let lines: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(32);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let scfg = Arc::new(
        ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions().unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from_pem_slice(LEAF).unwrap()], PrivateKeyDer::from_pem_slice(KEY).unwrap())
            .unwrap(),
    );
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(CA).unwrap()).unwrap();
    let ccfg = Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions().unwrap()
            .with_root_certificates(roots).with_no_client_auth(),
    );
    let (a, b) = UnixStream::pair().expect("socketpair");
    let server = std::thread::spawn(move || {
        let conn = ServerConnection::new(scfg).unwrap();
        let mut tls = BufReader::new(StreamOwned::new(conn, a));
        let mut upper = 0usize;
        let mut line = String::new();
        loop {
            line.clear();
            if tls.read_line(&mut line).unwrap() == 0 { break; }
            let reply = line.to_uppercase();
            upper += reply.len();
            tls.get_mut().write_all(reply.as_bytes()).unwrap();
            if line.starts_with("quit") { break; }
        }
        upper
    });
    let conn = ClientConnection::new(ccfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut tls = BufReader::new(StreamOwned::new(conn, b));
    let mut got = 0usize;
    for i in 0..=lines {
        let msg = if i == lines { "quit\n".to_string() } else { format!("line number {i}\n") };
        tls.get_mut().write_all(msg.as_bytes()).unwrap();
        let mut reply = String::new();
        tls.read_line(&mut reply).unwrap();
        assert_eq!(reply, msg.to_uppercase());
        got += reply.len();
    }
    let upper = server.join().unwrap();
    assert_eq!(upper, got);
    println!("app-b ok lines={lines} bytes={got}");
}
