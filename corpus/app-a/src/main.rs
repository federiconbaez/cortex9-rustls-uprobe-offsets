// app-a: handshake TLS en memoria (sin red) y eco de mensajes vía Reader/Writer.
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::sync::Arc;

const CA: &[u8] = include_bytes!("../../fixtures/ca.pem");
const LEAF: &[u8] = include_bytes!("../../fixtures/leaf.pem");
const KEY: &[u8] = include_bytes!("../../fixtures/leaf.pk8.pem");

macro_rules! pump {
    ($from:expr, $to:expr) => {{
        let mut buf: Vec<u8> = Vec::new();
        while $from.wants_write() {
            $from.write_tls(&mut buf).expect("write_tls");
        }
        let mut cur = &buf[..];
        while !cur.is_empty() {
            $to.read_tls(&mut cur).expect("read_tls");
            $to.process_new_packets().expect("process_new_packets");
        }
    }};
}

fn main() {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(CA).unwrap()).unwrap();
    let ccfg = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions().unwrap()
        .with_root_certificates(roots).with_no_client_auth();
    let scfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions().unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from_pem_slice(LEAF).unwrap()], PrivateKeyDer::from_pem_slice(KEY).unwrap())
        .unwrap();
    let mut c = ClientConnection::new(Arc::new(ccfg), ServerName::try_from("localhost").unwrap()).unwrap();
    let mut s = ServerConnection::new(Arc::new(scfg)).unwrap();
    while c.is_handshaking() || s.is_handshaking() {
        pump!(c, s);
        pump!(s, c);
    }
    let rounds: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(16);
    let mut total = 0usize;
    for i in 0..rounds {
        let msg = format!("ping {i}");
        c.writer().write_all(msg.as_bytes()).unwrap();
        pump!(c, s);
        let mut buf = [0u8; 256];
        let n = s.reader().read(&mut buf).unwrap();
        assert_eq!(&buf[..n], msg.as_bytes());
        s.writer().write_all(&buf[..n]).unwrap();
        pump!(s, c);
        let m = c.reader().read(&mut buf).unwrap();
        assert_eq!(m, n);
        total += m;
    }
    println!("app-a ok rounds={rounds} bytes={total}");
}
