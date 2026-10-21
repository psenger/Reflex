//! End-to-end tests against the real `ib-server`, `ib-client` and `ib-certgen`
//! binaries. Each test mints its own credentials in a temporary directory and
//! starts its own server on a free port.

use std::fs::File;
use std::io::{BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use protocol::{
    Event, EventKind, Hello, Message, Nonce, Transcript, BINDING_LABEL, PROTOCOL_VERSION,
};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

type Wire = Framed<TlsStream<TcpStream>, LengthDelimitedCodec>;

/// Path to a workspace binary built alongside this test.
fn bin(name: &str) -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps/
    p.pop(); // debug/
    p.push(name);
    assert!(
        p.exists(),
        "{} not built; run `cargo test` from the workspace root",
        p.display()
    );
    p
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Kills the child on drop so a failing test never leaves a server behind.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    addr: String,
    _server: Proc,
}

impl Fixture {
    /// Mint credentials for `clients`, start a server, wait until it listens.
    fn start(clients: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut certgen = Command::new(bin("ib-certgen"));
        certgen.arg("--out").arg(dir.path());
        for c in clients {
            certgen.arg("--client").arg(c);
        }
        let status = certgen.status().unwrap();
        assert!(status.success(), "ib-certgen failed");

        let port = free_port();
        let addr = format!("127.0.0.1:{port}");
        let stdout = File::create(dir.path().join("server.out")).unwrap();
        let stderr = File::create(dir.path().join("server.err")).unwrap();
        let server = Command::new(bin("ib-server"))
            .arg(&addr)
            .arg("--cert")
            .arg(dir.path().join("server.pem"))
            .arg("--key")
            .arg(dir.path().join("server.key"))
            .arg("--ca")
            .arg(dir.path().join("ca.pem"))
            .arg("--tokens")
            .arg(dir.path().join("tokens.txt"))
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while std::net::TcpStream::connect(&addr).is_err() {
            assert!(Instant::now() < deadline, "server never started");
            std::thread::sleep(Duration::from_millis(50));
        }
        Self {
            dir,
            addr,
            _server: Proc(server),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn server_stdout(&self) -> String {
        std::fs::read_to_string(self.path("server.out")).unwrap()
    }

    fn server_stderr(&self) -> String {
        std::fs::read_to_string(self.path("server.err")).unwrap()
    }

    fn token(&self, client: &str) -> Vec<u8> {
        std::fs::read_to_string(self.path(&format!("{client}.token")))
            .unwrap()
            .trim()
            .as_bytes()
            .to_vec()
    }

    /// Run the real client with `input` on stdin and wait for it to exit.
    fn run_client(&self, client: &str, input: &str) -> std::process::ExitStatus {
        let mut child = Command::new(bin("ib-client"))
            .arg(&self.addr)
            .arg(client)
            .arg("--cert")
            .arg(self.path(&format!("{client}.pem")))
            .arg("--key")
            .arg(self.path(&format!("{client}.key")))
            .arg("--ca")
            .arg(self.path("ca.pem"))
            .arg("--token")
            .arg(self.path(&format!("{client}.token")))
            .stdin(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait().unwrap()
    }

    /// A hand-rolled TLS connection, optionally with a client certificate, so
    /// tests can misbehave in ways the real client never would.
    async fn raw_connect(&self, client_cert: Option<&str>) -> Result<(Wire, [u8; 32])> {
        let mut roots = RootCertStore::empty();
        for ca in load_certs(&self.path("ca.pem"))? {
            roots.add(ca)?;
        }
        let builder = ClientConfig::builder().with_root_certificates(roots);
        let config = match client_cert {
            Some(c) => builder.with_client_auth_cert(
                load_certs(&self.path(&format!("{c}.pem")))?,
                load_key(&self.path(&format!("{c}.key")))?,
            )?,
            None => builder.with_no_client_auth(),
        };
        let connector = TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(&self.addr).await?;
        let tls = connector
            .connect(ServerName::try_from("127.0.0.1".to_string())?, tcp)
            .await?;
        let binding = tls
            .get_ref()
            .1
            .export_keying_material([0u8; 32], BINDING_LABEL, None)?;
        Ok((Framed::new(tls, LengthDelimitedCodec::new()), binding))
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    Ok(rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?.context("no key")
}

async fn send(wire: &mut Wire, msg: &Message) -> Result<()> {
    wire.send(Bytes::from(protocol::encode(msg)?)).await?;
    Ok(())
}

/// Next frame, or `None` if the server closed the connection or the TLS layer
/// reported an alert. Both count as "the server refused us".
async fn recv(wire: &mut Wire) -> Option<Message> {
    match tokio::time::timeout(Duration::from_secs(5), wire.next()).await {
        Ok(Some(Ok(frame))) => protocol::decode(&frame).ok(),
        _ => None,
    }
}

/// Complete the token handshake as `client`, with `secret`. Returns the
/// transcript's Welcome if the server accepted us.
async fn handshake(
    wire: &mut Wire,
    binding: &[u8],
    client: &str,
    secret: &[u8],
) -> Option<protocol::Welcome> {
    let challenge = match recv(wire).await? {
        Message::Challenge(c) => c,
        other => panic!("expected Challenge, got {other:?}"),
    };
    let client_nonce: Nonce = rand::random();
    let transcript = Transcript {
        server_nonce: &challenge.nonce,
        client_nonce: &client_nonce,
        client_id: client,
        channel_binding: binding,
    };
    send(
        wire,
        &Message::Hello(Hello {
            client_id: client.to_string(),
            protocol_version: PROTOCOL_VERSION,
            resume_from_seq: 0,
            nonce: client_nonce,
            proof: protocol::client_proof(secret, &transcript),
        }),
    )
    .await
    .ok()?;
    match recv(wire).await? {
        Message::Welcome(w) => Some(w),
        other => panic!("expected Welcome, got {other:?}"),
    }
}

fn text_event(seq: u64, data: &str) -> Message {
    Message::Event(Event {
        seq,
        timestamp_micros: protocol::now_micros(),
        kind: EventKind::Text { data: data.into() },
    })
}

fn wait_for_lines(fx: &Fixture, n: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let lines: Vec<String> = fx.server_stdout().lines().map(str::to_string).collect();
        if lines.len() >= n || Instant::now() > deadline {
            return lines;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn delivers_events_in_order_over_mutual_tls() {
    let fx = Fixture::start(&["laptop-a"]);
    let status = fx.run_client("laptop-a", "one\ntwo\nthree\n");
    assert!(status.success(), "client exited with {status}");

    let lines = wait_for_lines(&fx, 3);
    assert_eq!(lines.len(), 3, "server stdout: {lines:?}");
    for (i, line) in lines.iter().enumerate() {
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(cols[0], "laptop-a");
        assert_eq!(cols[1], (i + 1).to_string());
    }
    assert!(lines[0].contains("\"one\""));
    assert!(lines[2].contains("\"three\""));
}

#[tokio::test]
async fn refuses_a_peer_without_a_client_certificate() {
    let fx = Fixture::start(&["laptop-a"]);
    let (mut wire, _) = fx.raw_connect(None).await.unwrap();
    // TLS 1.3 lets the client finish its side before the server has judged the
    // certificate, so the refusal shows up on the first read rather than in
    // connect(). Either way, no Challenge must ever arrive.
    assert!(
        recv(&mut wire).await.is_none(),
        "server talked to an unauthenticated peer"
    );
    assert_eq!(fx.server_stdout(), "");
}

#[tokio::test]
async fn refuses_a_valid_certificate_with_the_wrong_token() {
    let fx = Fixture::start(&["laptop-a"]);
    let (mut wire, binding) = fx.raw_connect(Some("laptop-a")).await.unwrap();
    let welcome = handshake(&mut wire, &binding, "laptop-a", b"not-the-token").await;
    assert!(welcome.is_none(), "server accepted a bad token");
    assert!(
        fx.server_stderr().contains("token proof failed"),
        "{}",
        fx.server_stderr()
    );
}

#[tokio::test]
async fn refuses_a_certificate_holder_claiming_another_client_id() {
    let fx = Fixture::start(&["laptop-a", "laptop-b"]);
    // laptop-b has a perfectly good certificate and its own token, but tries to
    // speak as laptop-a.
    let (mut wire, binding) = fx.raw_connect(Some("laptop-b")).await.unwrap();
    let welcome = handshake(&mut wire, &binding, "laptop-a", &fx.token("laptop-b")).await;
    assert!(
        welcome.is_none(),
        "server let laptop-b impersonate laptop-a"
    );
}

#[tokio::test]
async fn rejects_a_sequence_far_ahead_and_keeps_serving_the_genuine_client() {
    let fx = Fixture::start(&["laptop-a"]);

    // An authenticated but misbehaving session tries to poison last_seq.
    let (mut wire, binding) = fx.raw_connect(Some("laptop-a")).await.unwrap();
    let welcome = handshake(&mut wire, &binding, "laptop-a", &fx.token("laptop-a")).await;
    assert_eq!(welcome.expect("handshake should succeed").last_seq, 0);
    send(&mut wire, &text_event(1_000_000, "poison"))
        .await
        .unwrap();
    assert!(
        recv(&mut wire).await.is_none(),
        "server acked a sequence 1,000,000 ahead"
    );
    assert!(
        fx.server_stderr().contains("too far ahead"),
        "{}",
        fx.server_stderr()
    );
    drop(wire);

    // The genuine client must still get through with seq 1, 2, 3.
    let status = fx.run_client("laptop-a", "one\ntwo\nthree\n");
    assert!(status.success());
    let lines = wait_for_lines(&fx, 3);
    assert_eq!(lines.len(), 3, "server stdout: {lines:?}");
    assert!(!fx.server_stdout().contains("poison"));
    assert!(lines[0].starts_with("laptop-a\t1\t"));
}
