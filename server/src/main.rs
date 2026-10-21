//! Reflex server.
//!
//! Listens on a TCP socket, accepts any number of clients over mutual TLS, and
//! hands every event through to a sink. The default sink writes one line per
//! event to stdout, so the whole thing composes with ordinary Unix plumbing:
//!
//! ```text
//! ib-server 0.0.0.0:9001 --cert certs/server.pem --key certs/server.key \
//!     --ca certs/ca.pem --tokens certs/tokens.txt | your-program
//! ```
//!
//! Security model:
//!   * Mutual TLS. A peer without a certificate signed by the configured CA
//!     never gets past the TLS handshake.
//!   * Token handshake. After TLS, the server sends a random challenge and the
//!     client must answer with an HMAC over the challenge, its own nonce, its
//!     id and keying material exported from this TLS session. The server looks
//!     the token up by `client_id`, so one client cannot claim another's id.
//!     The server proves it holds the same token in its `Welcome`.
//!   * Sequence numbers are only accepted within `MAX_SEQ_AHEAD` of what the
//!     server has delivered, so a buggy or hostile client cannot poison the
//!     dedup state for its own id.
//!   * Frames and messages are capped at `MAX_FRAME_BYTES`, idle registry
//!     entries are evicted, and handshakes time out.
//!
//! Reliability features:
//!   * Length-delimited framing, so a short read can never split a message.
//!   * Per-client, cumulative acks. Re-sent events are recognised by their
//!     sequence number and acknowledged again rather than processed twice.
//!   * A heartbeat in both directions with a liveness deadline, so a dead peer
//!     is noticed and its connection dropped rather than left hanging.
//!   * Each connection runs in its own task; one misbehaving client cannot stall
//!     the others.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use protocol::{
    Ack, Challenge, Event, Hello, Message, Nonce, Transcript, Welcome, BINDING_LABEL,
    MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{interval, timeout};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// How often each side emits a heartbeat.
const HEARTBEAT: Duration = Duration::from_secs(5);
/// Drop a connection that has gone silent for this long.
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(15);
/// A peer that has not finished TLS plus the token handshake by then is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A client can never legitimately be further ahead than its own unacked
/// buffer, so anything beyond this is treated as hostile.
const MAX_SEQ_AHEAD: u64 = 65_536;
/// Forget a disconnected client's delivery state after this long.
const REGISTRY_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Parser)]
#[command(
    name = "ib-server",
    about = "Reflex server: receives events over mutual TLS and forwards them to stdout"
)]
struct Args {
    /// Address to listen on.
    #[arg(default_value = "127.0.0.1:9001")]
    listen: String,
    /// PEM file holding the server certificate chain.
    #[arg(long)]
    cert: PathBuf,
    /// PEM file holding the server private key.
    #[arg(long)]
    key: PathBuf,
    /// PEM file holding the CA that signs client certificates.
    #[arg(long)]
    ca: PathBuf,
    /// File of `client_id token` lines, one per client allowed to connect.
    #[arg(long)]
    tokens: PathBuf,
}

/// Anything that consumes decoded events. Swap this out to forward somewhere
/// other than stdout (a file, a database, another socket).
trait EventSink: Send + Sync {
    fn handle(&self, client_id: &str, ev: &Event) -> Result<()>;
}

/// Writes one tab-separated line per event to stdout and flushes immediately,
/// so a downstream program in a pipe sees events as they arrive.
struct StdoutSink;

impl EventSink for StdoutSink {
    fn handle(&self, client_id: &str, ev: &Event) -> Result<()> {
        let mut out = std::io::stdout().lock();
        writeln!(
            out,
            "{client_id}\t{}\t{}\t{:?}",
            ev.seq, ev.timestamp_micros, ev.kind
        )?;
        out.flush()?;
        Ok(())
    }
}

/// Delivery state the server remembers for each client id, so that a client
/// which drops and reconnects resumes without replaying work.
struct ClientState {
    /// Highest sequence number already handed to the sink.
    last_seq: u64,
    last_seen: Instant,
    connected: bool,
}

impl ClientState {
    fn new() -> Self {
        Self {
            last_seq: 0,
            last_seen: Instant::now(),
            connected: false,
        }
    }
}

type Registry = Arc<Mutex<HashMap<String, ClientState>>>;
type Tokens = Arc<HashMap<String, Vec<u8>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let acceptor = tls_acceptor(&args)?;
    let tokens: Tokens = Arc::new(load_tokens(&args.tokens)?);

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    eprintln!(
        "[server] listening on {} ({} client tokens loaded)",
        args.listen,
        tokens.len()
    );

    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
    let sink: Arc<dyn EventSink> = Arc::new(StdoutSink);

    // Shut down cleanly on Ctrl-C while still accepting connections otherwise.
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accepting connection")?;
                evict_idle(&registry);
                let acceptor = acceptor.clone();
                let registry = registry.clone();
                let tokens = tokens.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, acceptor, registry, tokens, sink).await {
                        eprintln!("[server] connection {peer} ended: {e:#}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[server] shutting down");
                return Ok(());
            }
        }
    }
}

fn tls_acceptor(args: &Args) -> Result<TlsAcceptor> {
    let certs = load_certs(&args.cert)?;
    let key = load_key(&args.key)?;
    let mut roots = RootCertStore::empty();
    for ca in load_certs(&args.ca)? {
        roots.add(ca).context("adding CA certificate")?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("building client certificate verifier")?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("loading server certificate and key")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
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

/// One `client_id token` pair per line. Blank lines and `#` comments are
/// ignored. The token is used as opaque bytes, so it must not contain spaces.
fn load_tokens(path: &Path) -> Result<HashMap<String, Vec<u8>>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut map = HashMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(id), Some(token), None) = (parts.next(), parts.next(), parts.next()) else {
            anyhow::bail!("{}:{}: expected `client_id token`", path.display(), n + 1);
        };
        if map
            .insert(id.to_string(), token.as_bytes().to_vec())
            .is_some()
        {
            anyhow::bail!("{}:{}: duplicate client_id '{id}'", path.display(), n + 1);
        }
    }
    anyhow::ensure!(!map.is_empty(), "no tokens in {}", path.display());
    Ok(map)
}

fn evict_idle(registry: &Registry) {
    registry
        .lock()
        .unwrap()
        .retain(|_, s| s.connected || s.last_seen.elapsed() < REGISTRY_TTL);
}

fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME_BYTES)
        .new_codec()
}

async fn handle_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    registry: Registry,
    tokens: Tokens,
    sink: Arc<dyn EventSink>,
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let tls = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .context("TLS handshake timed out")?
        .context("TLS handshake")?;
    let binding = tls
        .get_ref()
        .1
        .export_keying_material([0u8; 32], BINDING_LABEL, None)
        .context("exporting channel binding")?;
    let mut wire = Framed::new(tls, codec());

    // Token handshake. The challenge is fresh per connection and the proof is
    // bound to this TLS session, so nothing here can be replayed elsewhere.
    let server_nonce: Nonce = rand::random();
    send(
        &mut wire,
        &Message::Challenge(Challenge {
            protocol_version: PROTOCOL_VERSION,
            nonce: server_nonce,
        }),
    )
    .await?;

    let first = timeout(HANDSHAKE_TIMEOUT, wire.next())
        .await
        .context("client did not answer the challenge in time")?
        .context("client closed before handshake")??;
    let hello = match protocol::decode(&first)? {
        Message::Hello(h) => h,
        other => anyhow::bail!("expected Hello, got {other:?}"),
    };
    validate_hello(&hello)?;
    let secret = tokens
        .get(&hello.client_id)
        .with_context(|| format!("rejected unknown client '{}'", hello.client_id))?;
    let transcript = Transcript {
        server_nonce: &server_nonce,
        client_nonce: &hello.nonce,
        client_id: &hello.client_id,
        channel_binding: &binding,
    };
    anyhow::ensure!(
        protocol::verify_client_proof(secret, &transcript, &hello.proof),
        "rejected client '{}': token proof failed",
        hello.client_id
    );

    let client_id = hello.client_id.clone();
    eprintln!(
        "[server] client '{client_id}' authenticated (resume_from_seq={})",
        hello.resume_from_seq
    );

    // Tell the client where we already are, so it can discard anything we have
    // seen and resend only the rest, and prove we hold its token too.
    let last_seq = {
        let mut guard = registry.lock().unwrap();
        let state = guard
            .entry(client_id.clone())
            .or_insert_with(ClientState::new);
        state.connected = true;
        state.last_seen = Instant::now();
        state.last_seq
    };
    send(
        &mut wire,
        &Message::Welcome(Welcome {
            last_seq,
            proof: protocol::server_proof(secret, &transcript),
        }),
    )
    .await?;

    let result = pump(&mut wire, &client_id, &registry, &*sink).await;

    if let Some(state) = registry.lock().unwrap().get_mut(&client_id) {
        state.connected = false;
        state.last_seen = Instant::now();
    }
    result
}

/// The steady state of one authenticated connection: events in, acks out,
/// heartbeats both ways.
async fn pump<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Framed<S, LengthDelimitedCodec>,
    client_id: &str,
    registry: &Registry,
    sink: &dyn EventSink,
) -> Result<()> {
    let mut hb_seq: u64 = 0;
    let mut ticker = interval(HEARTBEAT);
    let mut last_inbound = Instant::now();

    loop {
        tokio::select! {
            inbound = wire.next() => {
                let frame = match inbound {
                    Some(f) => f.context("reading frame")?,
                    None => {
                        eprintln!("[server] client '{client_id}' disconnected");
                        return Ok(());
                    }
                };
                last_inbound = Instant::now();
                match protocol::decode(&frame)? {
                    Message::Event(ev) => {
                        let ack_to = process_event(registry, client_id, sink, ev)?;
                        send(wire, &Message::Ack(Ack { seq: ack_to })).await?;
                    }
                    Message::Heartbeat(_) => { /* liveness already refreshed */ }
                    Message::Bye => {
                        eprintln!("[server] client '{client_id}' said goodbye");
                        return Ok(());
                    }
                    Message::Hello(_) => anyhow::bail!("unexpected second Hello"),
                    Message::Challenge(_) | Message::Welcome(_) => {
                        anyhow::bail!("client sent a server-only message")
                    }
                    Message::Ack(_) => { /* clients do not ack the server */ }
                }
            }
            _ = ticker.tick() => {
                hb_seq += 1;
                send(wire, &Message::Heartbeat(protocol::Heartbeat { seq: hb_seq })).await?;
                if last_inbound.elapsed() > LIVENESS_TIMEOUT {
                    anyhow::bail!("client '{client_id}' silent for {:?}", last_inbound.elapsed());
                }
            }
        }
    }
}

/// Apply one event. Returns the sequence number the client should be acked to.
///
/// Dedup rule: anything at or below `last_seq` has already been delivered, so we
/// skip the sink and simply re-ack. Because events arrive in order on a single
/// connection and a reconnecting client resends from the first unacked event,
/// this gives at-least-once delivery with in-order processing and no duplicates
/// reaching the sink.
///
/// Anything more than `MAX_SEQ_AHEAD` past `last_seq` is refused. A genuine
/// client cannot get that far ahead, and accepting it would let one bad event
/// make the server discard every later genuine one as a duplicate.
fn process_event(
    registry: &Registry,
    client_id: &str,
    sink: &dyn EventSink,
    ev: Event,
) -> Result<u64> {
    let mut guard = registry.lock().unwrap();
    let state = guard
        .entry(client_id.to_string())
        .or_insert_with(ClientState::new);

    if ev.seq <= state.last_seq {
        return Ok(state.last_seq);
    }
    if ev.seq > state.last_seq.saturating_add(MAX_SEQ_AHEAD) {
        anyhow::bail!(
            "client '{client_id}' sequence {} is too far ahead of {}",
            ev.seq,
            state.last_seq
        );
    }

    // Release the lock before touching the sink: a slow sink must not block
    // other connections' bookkeeping.
    let expected = state.last_seq + 1;
    drop(guard);

    if ev.seq != expected {
        // Cannot happen over a healthy TCP link, but log it rather than hide it.
        eprintln!(
            "[server] client '{client_id}' sequence gap: expected {expected}, got {}",
            ev.seq
        );
    }

    sink.handle(client_id, &ev)?;

    let mut guard = registry.lock().unwrap();
    let state = guard
        .entry(client_id.to_string())
        .or_insert_with(ClientState::new);
    if ev.seq > state.last_seq {
        state.last_seq = ev.seq;
    }
    Ok(state.last_seq)
}

fn validate_hello(hello: &Hello) -> Result<()> {
    if hello.protocol_version != PROTOCOL_VERSION {
        anyhow::bail!(
            "protocol mismatch: server {PROTOCOL_VERSION}, client {}",
            hello.protocol_version
        );
    }
    if hello.client_id.trim().is_empty() {
        anyhow::bail!("empty client_id");
    }
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
