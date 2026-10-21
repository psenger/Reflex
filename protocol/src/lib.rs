//! Shared wire protocol for Reflex.
//!
//! Both the client and the server depend on this crate so that the two ends can
//! never drift out of agreement about the shape of a message. Messages are
//! serialised with `bincode` (compact and fast for a Rust-to-Rust link) and are
//! meant to be carried inside a length-delimited frame, so this module does not
//! concern itself with where one message ends and the next begins.
//!
//! The link itself is mutual TLS. On top of that, the first three frames form a
//! token handshake: the server sends a `Challenge`, the client answers with a
//! `Hello` carrying an HMAC proof, and the server replies with a `Welcome`
//! carrying its own proof. Both proofs mix in keying material exported from the
//! TLS session, so a proof captured on one connection is useless on any other.
//!
//! If you later need a second language on either end, swap the body of `encode`
//! and `decode` for Protobuf or FlatBuffers. Nothing else has to change.

use bincode::Options;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Bumped whenever the message layout changes in a way the other end must
/// understand. Each side rejects a peer whose version differs.
pub const PROTOCOL_VERSION: u16 = 2;

/// Largest message either side will encode or decode. The length-delimited
/// codec on both ends is capped to the same value, so a hostile peer cannot
/// make the receiver allocate more than this for one frame.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Label passed to the TLS keying-material exporter on both sides.
pub const BINDING_LABEL: &[u8] = b"EXPORTER-reflex-token-binding";

pub type Nonce = [u8; 32];
pub type Proof = [u8; 32];

/// Every frame on the wire is exactly one of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// First frame the server sends once the TLS handshake has completed.
    Challenge(Challenge),
    /// The client's answer to the challenge.
    Hello(Hello),
    /// The server's acceptance of a `Hello`. Takes the place of the first ack.
    Welcome(Welcome),
    /// A captured input event flowing client -> server.
    Event(Event),
    /// Server -> client confirmation that every event up to and including `seq`
    /// has been handed to the sink. Acks are cumulative and idempotent.
    Ack(Ack),
    /// Liveness probe sent by either side on a fixed interval.
    Heartbeat(Heartbeat),
    /// Polite shutdown notice. The peer may close straight away.
    Bye,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub protocol_version: u16,
    /// Fresh random bytes for this connection only.
    pub nonce: Nonce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// Stable identifier for this client. The server keeps per-client delivery
    /// state under this key and looks up the client's token with it, so a
    /// reconnecting client must reuse the same id to resume cleanly.
    pub client_id: String,
    pub protocol_version: u16,
    /// Highest sequence number the client has seen acknowledged. The server uses
    /// it to re-acknowledge anything it already processed.
    pub resume_from_seq: u64,
    /// Fresh random bytes chosen by the client, mixed into both proofs.
    pub nonce: Nonce,
    /// `client_proof` over this connection's transcript.
    pub proof: Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Welcome {
    /// Highest sequence number the server has already handed to the sink.
    pub last_seq: u64,
    /// `server_proof` over this connection's transcript.
    pub proof: Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Monotonic, gap-free per client. Assigned once and never reused, so a
    /// resend after reconnect carries the original `seq` and the server can
    /// deduplicate it.
    pub seq: u64,
    /// Microseconds since the Unix epoch, taken at capture time.
    pub timestamp_micros: u64,
    pub kind: EventKind,
}

/// The payload of an event. Extend this enum as you add real capture backends;
/// the transport and reliability layers do not care what is inside.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    Key {
        code: u32,
        pressed: bool,
    },
    Mouse {
        x: i32,
        y: i32,
        button: Option<u8>,
        pressed: bool,
    },
    Text {
        data: String,
    },
    Raw {
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Ack {
    pub seq: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Heartbeat {
    pub seq: u64,
}

/// Everything both handshake proofs are computed over.
pub struct Transcript<'a> {
    pub server_nonce: &'a Nonce,
    pub client_nonce: &'a Nonce,
    pub client_id: &'a str,
    /// Keying material exported from the TLS session. Both ends derive the same
    /// bytes from the session, so a proof is only valid on the connection it
    /// was made for.
    pub channel_binding: &'a [u8],
}

type HmacSha256 = Hmac<Sha256>;

fn mac(secret: &[u8], label: &[u8], t: &Transcript) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    m.update(label);
    m.update(t.server_nonce);
    m.update(t.client_nonce);
    m.update(&(t.client_id.len() as u64).to_be_bytes());
    m.update(t.client_id.as_bytes());
    m.update(t.channel_binding);
    m
}

fn finish(m: HmacSha256) -> Proof {
    m.finalize().into_bytes().into()
}

/// Proof the client puts in its `Hello`.
pub fn client_proof(secret: &[u8], t: &Transcript) -> Proof {
    finish(mac(secret, b"client", t))
}

/// Proof the server puts in its `Welcome`.
pub fn server_proof(secret: &[u8], t: &Transcript) -> Proof {
    finish(mac(secret, b"server", t))
}

/// Constant-time check of a client proof.
pub fn verify_client_proof(secret: &[u8], t: &Transcript, proof: &Proof) -> bool {
    mac(secret, b"client", t).verify_slice(proof).is_ok()
}

/// Constant-time check of a server proof.
pub fn verify_server_proof(secret: &[u8], t: &Transcript, proof: &Proof) -> bool {
    mac(secret, b"server", t).verify_slice(proof).is_ok()
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_FRAME_BYTES as u64)
}

/// Serialise a message to bytes, ready to drop into one frame.
pub fn encode(msg: &Message) -> Result<Vec<u8>, bincode::Error> {
    options().serialize(msg)
}

/// Parse one frame's worth of bytes back into a message. Refuses to allocate
/// more than `MAX_FRAME_BYTES` no matter what the bytes claim.
pub fn decode(bytes: &[u8]) -> Result<Message, bincode::Error> {
    options().deserialize(bytes)
}

/// Current wall-clock time in microseconds since the Unix epoch, saturating to 0
/// if the clock is somehow before the epoch.
pub fn now_micros() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript<'a>(sn: &'a Nonce, cn: &'a Nonce, id: &'a str, b: &'a [u8]) -> Transcript<'a> {
        Transcript {
            server_nonce: sn,
            client_nonce: cn,
            client_id: id,
            channel_binding: b,
        }
    }

    #[test]
    fn round_trips_an_event() {
        let msg = Message::Event(Event {
            seq: 42,
            timestamp_micros: 1234,
            kind: EventKind::Text {
                data: "hello".into(),
            },
        });
        let bytes = encode(&msg).unwrap();
        match decode(&bytes).unwrap() {
            Message::Event(e) => {
                assert_eq!(e.seq, 42);
                assert!(matches!(e.kind, EventKind::Text { .. }));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn round_trips_the_handshake() {
        let hello = Message::Hello(Hello {
            client_id: "laptop-a".into(),
            protocol_version: PROTOCOL_VERSION,
            resume_from_seq: 7,
            nonce: [1; 32],
            proof: [2; 32],
        });
        match decode(&encode(&hello).unwrap()).unwrap() {
            Message::Hello(h) => {
                assert_eq!(h.client_id, "laptop-a");
                assert_eq!(h.nonce, [1; 32]);
                assert_eq!(h.proof, [2; 32]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn proofs_verify_with_the_same_secret_and_transcript() {
        let (sn, cn, b) = ([3; 32], [4; 32], [5u8; 32]);
        let t = transcript(&sn, &cn, "laptop-a", &b);
        let secret = b"shared-token";
        assert!(verify_client_proof(secret, &t, &client_proof(secret, &t)));
        assert!(verify_server_proof(secret, &t, &server_proof(secret, &t)));
    }

    #[test]
    fn proofs_fail_when_anything_changes() {
        let (sn, cn, b) = ([3; 32], [4; 32], [5u8; 32]);
        let t = transcript(&sn, &cn, "laptop-a", &b);
        let proof = client_proof(b"shared-token", &t);

        assert!(!verify_client_proof(b"other-token", &t, &proof));

        let other_id = transcript(&sn, &cn, "laptop-b", &b);
        assert!(!verify_client_proof(b"shared-token", &other_id, &proof));

        let other_binding = [6u8; 32];
        let other_session = transcript(&sn, &cn, "laptop-a", &other_binding);
        assert!(!verify_client_proof(
            b"shared-token",
            &other_session,
            &proof
        ));

        // A client proof must never pass as a server proof, or a captured
        // Hello could be reflected back as a Welcome.
        assert!(!verify_server_proof(b"shared-token", &t, &proof));
    }

    #[test]
    fn refuses_oversized_messages() {
        let big = Message::Event(Event {
            seq: 1,
            timestamp_micros: 0,
            kind: EventKind::Raw {
                bytes: vec![0; MAX_FRAME_BYTES],
            },
        });
        assert!(encode(&big).is_err());
    }
}
