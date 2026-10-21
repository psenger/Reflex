//! Reflex client.
//!
//! Captures input events, buffers them with explicit backpressure, and streams
//! them to the server over a mutually authenticated, resumable TLS link. The
//! capture backend here reads lines from stdin, which works identically
//! everywhere and stands in for a real OS hook. To capture actual keyboard and
//! mouse events, replace the body of `capture_task` with a crate such as `rdev`
//! and push `EventKind::Key` / `EventKind::Mouse` values into the same ring.
//! Nothing downstream changes.
//!
//! Usage:
//!   echo "hello" | ib-client 10.0.0.5:9001 laptop-a \
//!       --cert certs/laptop-a.pem --key certs/laptop-a.key \
//!       --ca certs/ca.pem --token certs/laptop-a.token
//!
//! Security model:
//!   * Mutual TLS. The server certificate must chain to the configured CA and
//!     match the server name; the client presents its own certificate.
//!   * Token handshake. The client answers the server's challenge with an HMAC
//!     bound to this TLS session, and refuses to send a single event until the
//!     server has proven it holds the same token.
//!   * Authentication failures are fatal. Only network failures are retried.
//!
//! Reliability features:
//!   * A bounded ring between capture and network with a drop-oldest policy and
//!     a dropped-event counter, so a fast input source can never exhaust memory
//!     or block the OS hook.
//!   * Every event carries a monotonic sequence number and is held in an unacked
//!     buffer until the server confirms it. On reconnect the buffer is resent, so
//!     a dropped connection loses nothing in flight.
//!   * Automatic reconnect with capped exponential backoff.
//!   * Bidirectional heartbeat with a liveness deadline.

use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use protocol::{
    Event, EventKind, Hello, Message, Nonce, Transcript, BINDING_LABEL, MAX_FRAME_BYTES,
    PROTOCOL_VERSION,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader as AsyncBufReader};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::time::{interval, timeout};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const HEARTBEAT: Duration = Duration::from_secs(5);
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RING_CAPACITY: usize = 4096;
/// Upper bound on events held awaiting acknowledgement. Reached only when the
/// server is unreachable for a long stretch; oldest unacked events are shed
/// first so memory stays bounded.
const MAX_UNACKED: usize = 65_536;
const BACKOFF_START: Duration = Duration::from_millis(200);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(
    name = "ib-client",
    about = "Reflex client: captures events and streams them to the server over mutual TLS"
)]
struct Args {
    /// Server address.
    #[arg(default_value = "127.0.0.1:9001")]
    server: String,
    /// Stable identifier for this client. Must match a line in the server's
    /// token file.
    #[arg(default_value_t = default_client_id())]
    client_id: String,
    /// PEM file holding this client's certificate chain.
    #[arg(long)]
    cert: PathBuf,
    /// PEM file holding this client's private key.
    #[arg(long)]
    key: PathBuf,
    /// PEM file holding the CA that signs the server certificate.
    #[arg(long)]
    ca: PathBuf,
    /// File holding this client's token.
    #[arg(long)]
    token: PathBuf,
    /// Name to verify in the server certificate. Defaults to the host part of
    /// the server address.
    #[arg(long)]
    server_name: Option<String>,
}

/// Raised when the server fails authentication. Never retried.
#[derive(Debug)]
struct AuthFailure(String);

impl fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AuthFailure {}

/// One captured event before a sequence number is assigned.
struct Captured {
    timestamp_micros: u64,
    kind: EventKind,
}

/// A bounded, drop-oldest buffer sitting between the capture backend and the
/// network. This is where backpressure policy lives: when full, the oldest
/// event is discarded and a counter incremented, which keeps the newest input
/// flowing and never blocks the capture thread.
struct EventRing {
    inner: Mutex<VecDeque<Captured>>,
    cap: usize,
    dropped: AtomicU64,
    notify: Notify,
}

impl EventRing {
    fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(cap)),
            cap,
            dropped: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    fn push(&self, ev: Captured) {
        {
            let mut q = self.inner.lock().unwrap();
            if q.len() == self.cap {
                q.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            q.push_back(ev);
        }
        self.notify.notify_one();
    }

    fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Wait until at least one event is available, then take up to `max` of them.
    async fn recv_batch(&self, max: usize) -> Vec<Captured> {
        loop {
            {
                let mut q = self.inner.lock().unwrap();
                if !q.is_empty() {
                    let n = q.len().min(max);
                    return q.drain(..n).collect();
                }
            }
            self.notify.notified().await;
        }
    }
}

/// Delivery state that must survive reconnects.
struct Outbound {
    next_seq: u64,
    highest_acked: u64,
    unacked: VecDeque<Event>,
    shed: u64,
}

impl Outbound {
    fn new() -> Self {
        Self {
            next_seq: 1,
            highest_acked: 0,
            unacked: VecDeque::new(),
            shed: 0,
        }
    }

    /// Assign the next sequence number to a captured event and record it as
    /// unacked. If the unacked buffer is full the oldest is shed.
    fn enqueue(&mut self, c: Captured) -> Event {
        let ev = Event {
            seq: self.next_seq,
            timestamp_micros: c.timestamp_micros,
            kind: c.kind,
        };
        self.next_seq += 1;
        if self.unacked.len() >= MAX_UNACKED {
            self.unacked.pop_front();
            self.shed += 1;
        }
        self.unacked.push_back(ev.clone());
        ev
    }

    /// Drop everything the server has now confirmed.
    fn ack(&mut self, seq: u64) {
        if seq > self.highest_acked {
            self.highest_acked = seq;
        }
        while let Some(front) = self.unacked.front() {
            if front.seq <= seq {
                self.unacked.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Everything needed to open and authenticate one connection.
struct Link {
    addr: String,
    client_id: String,
    connector: TlsConnector,
    server_name: ServerName<'static>,
    secret: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let link = Link::from_args(&args)?;

    eprintln!("[client] id '{}' -> {}", link.client_id, link.addr);

    let ring = Arc::new(EventRing::new(RING_CAPACITY));
    let input_closed = Arc::new(AtomicBool::new(false));

    // Capture runs once and lives for the whole program, independent of how many
    // times the network connection comes and goes.
    {
        let ring = ring.clone();
        let input_closed = input_closed.clone();
        tokio::spawn(async move {
            if let Err(e) = capture_task(ring, input_closed).await {
                eprintln!("[client] capture ended: {e:#}");
            }
        });
    }

    let mut state = Outbound::new();
    let mut backoff = BACKOFF_START;

    loop {
        match run_session(&link, &ring, &input_closed, &mut state).await {
            Ok(SessionEnd::Finished) => {
                eprintln!("[client] all events delivered, exiting");
                return Ok(());
            }
            Err(e) if is_auth_failure(&e) => {
                eprintln!("[client] authentication failed, not retrying: {e:#}");
                std::process::exit(2);
            }
            Ok(SessionEnd::Disconnected) | Err(_) => {
                // Errors are expected here: the network is allowed to fail. Log,
                // wait, and try again with the same delivery state.
                eprintln!(
                    "[client] disconnected ({} unacked, {} dropped at capture, {} shed); retrying in {:?}",
                    state.unacked.len(),
                    ring.dropped(),
                    state.shed,
                    backoff
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

impl Link {
    fn from_args(args: &Args) -> Result<Self> {
        let certs = load_certs(&args.cert)?;
        let key = load_key(&args.key)?;
        let mut roots = RootCertStore::empty();
        for ca in load_certs(&args.ca)? {
            roots.add(ca).context("adding CA certificate")?;
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .context("loading client certificate and key")?;

        let name = args
            .server_name
            .clone()
            .unwrap_or_else(|| host_of(&args.server).to_string());
        let server_name = ServerName::try_from(name.clone())
            .with_context(|| format!("'{name}' is not a valid server name"))?;

        let secret = std::fs::read_to_string(&args.token)
            .with_context(|| format!("reading {}", args.token.display()))?;
        let secret = secret.trim();
        anyhow::ensure!(
            !secret.is_empty(),
            "token file {} is empty",
            args.token.display()
        );

        Ok(Self {
            addr: args.server.clone(),
            client_id: args.client_id.clone(),
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
            secret: secret.as_bytes().to_vec(),
        })
    }
}

/// `host:port` -> `host`, with IPv6 brackets removed.
fn host_of(addr: &str) -> &str {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    host.trim_start_matches('[').trim_end_matches(']')
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates in {}", path.display()))?;
    anyhow::ensure!(!certs.is_empty(), "no certificates in {}", path.display());
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing private key in {}", path.display()))?
        .with_context(|| format!("no private key in {}", path.display()))
}

/// An `AuthFailure` we raised ourselves, or a TLS-level rejection from rustls
/// (bad certificate, unknown CA). Neither will get better by retrying.
fn is_auth_failure(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause.downcast_ref::<AuthFailure>().is_some()
            || cause
                .downcast_ref::<std::io::Error>()
                .and_then(|io| io.get_ref())
                .is_some_and(|inner| inner.is::<tokio_rustls::rustls::Error>())
    })
}

fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME_BYTES)
        .new_codec()
}

enum SessionEnd {
    /// stdin closed and every event has been acknowledged.
    Finished,
    /// The peer closed or went silent; the caller should reconnect.
    Disconnected,
}

/// One connection's lifetime: connect, authenticate, resend, then pump events
/// and acks until something goes wrong or the work is done.
async fn run_session(
    link: &Link,
    ring: &EventRing,
    input_closed: &AtomicBool,
    state: &mut Outbound,
) -> Result<SessionEnd> {
    let tcp = TcpStream::connect(&link.addr)
        .await
        .with_context(|| format!("connecting to {}", link.addr))?;
    tcp.set_nodelay(true).ok();
    let tls = timeout(
        HANDSHAKE_TIMEOUT,
        link.connector.connect(link.server_name.clone(), tcp),
    )
    .await
    .context("TLS handshake timed out")?
    .context("TLS handshake")?;
    let binding = tls
        .get_ref()
        .1
        .export_keying_material([0u8; 32], BINDING_LABEL, None)
        .context("exporting channel binding")?;
    let mut wire = Framed::new(tls, codec());
    eprintln!("[client] connected");

    // Token handshake: answer the server's challenge, then insist the server
    // proves it holds our token before anything else is sent.
    let first = timeout(HANDSHAKE_TIMEOUT, wire.next())
        .await
        .context("server did not send a challenge in time")?
        .context("server closed before challenge")??;
    let challenge = match protocol::decode(&first)? {
        Message::Challenge(c) => c,
        other => anyhow::bail!("expected Challenge, got {other:?}"),
    };
    if challenge.protocol_version != PROTOCOL_VERSION {
        return Err(AuthFailure(format!(
            "protocol mismatch: client {PROTOCOL_VERSION}, server {}",
            challenge.protocol_version
        ))
        .into());
    }

    let client_nonce: Nonce = rand::random();
    let transcript = Transcript {
        server_nonce: &challenge.nonce,
        client_nonce: &client_nonce,
        client_id: &link.client_id,
        channel_binding: &binding,
    };
    send(
        &mut wire,
        &Message::Hello(Hello {
            client_id: link.client_id.clone(),
            protocol_version: PROTOCOL_VERSION,
            resume_from_seq: state.highest_acked,
            nonce: client_nonce,
            proof: protocol::client_proof(&link.secret, &transcript),
        }),
    )
    .await?;

    let second = timeout(HANDSHAKE_TIMEOUT, wire.next())
        .await
        .context("server did not answer the Hello in time")?
        .context("server closed during handshake (rejected certificate or token?)")??;
    let welcome = match protocol::decode(&second)? {
        Message::Welcome(w) => w,
        other => anyhow::bail!("expected Welcome, got {other:?}"),
    };
    if !protocol::verify_server_proof(&link.secret, &transcript, &welcome.proof) {
        return Err(AuthFailure("server failed the token proof".into()).into());
    }
    eprintln!(
        "[client] authenticated (server has seq {})",
        welcome.last_seq
    );

    // Anything the server already has can be forgotten; resend the rest. The
    // server deduplicates by sequence number, so re-sending is always safe.
    state.ack(welcome.last_seq);
    for ev in state.unacked.iter() {
        send(&mut wire, &Message::Event(ev.clone())).await?;
    }

    let mut hb_seq: u64 = 0;
    let mut ticker = interval(HEARTBEAT);
    let mut last_inbound = Instant::now();

    loop {
        // Clean exit: input is done and the server has confirmed everything.
        if input_closed.load(Ordering::Relaxed) && state.unacked.is_empty() && ring.is_empty() {
            send(&mut wire, &Message::Bye).await.ok();
            return Ok(SessionEnd::Finished);
        }

        tokio::select! {
            inbound = wire.next() => {
                let frame = match inbound {
                    Some(f) => f.context("reading frame")?,
                    None => return Ok(SessionEnd::Disconnected),
                };
                last_inbound = Instant::now();
                match protocol::decode(&frame)? {
                    Message::Ack(ack) => state.ack(ack.seq),
                    Message::Heartbeat(_) => { /* liveness refreshed above */ }
                    Message::Bye => return Ok(SessionEnd::Disconnected),
                    Message::Hello(_) | Message::Event(_) | Message::Challenge(_) | Message::Welcome(_) => {
                        anyhow::bail!("server sent an unexpected message");
                    }
                }
            }
            batch = ring.recv_batch(256) => {
                for c in batch {
                    let ev = state.enqueue(c);
                    send(&mut wire, &Message::Event(ev)).await?;
                }
            }
            _ = ticker.tick() => {
                hb_seq += 1;
                send(&mut wire, &Message::Heartbeat(protocol::Heartbeat { seq: hb_seq })).await?;
                if last_inbound.elapsed() > LIVENESS_TIMEOUT {
                    anyhow::bail!("server silent for {:?}", last_inbound.elapsed());
                }
            }
        }
    }
}

/// The capture backend. Reads lines from stdin and turns each into a text event.
/// Replace this with a real OS input hook when you are ready; keep pushing into
/// the same ring.
async fn capture_task(ring: Arc<EventRing>, input_closed: Arc<AtomicBool>) -> Result<()> {
    let mut lines = AsyncBufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        ring.push(Captured {
            timestamp_micros: protocol::now_micros(),
            kind: EventKind::Text { data: line },
        });
    }
    input_closed.store(true, Ordering::Relaxed);
    // Nudge the sender in case it is parked waiting on the ring.
    ring.notify.notify_one();
    Ok(())
}

async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Framed<S, LengthDelimitedCodec>,
    msg: &Message,
) -> Result<()> {
    let bytes = Bytes::from(protocol::encode(msg)?);
    wire.send(bytes).await.context("writing frame")?;
    Ok(())
}

/// A best-effort, human-readable default id when the caller does not supply one.
fn default_client_id() -> String {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "client".to_string());
    format!("{host}-{}", std::process::id())
}
