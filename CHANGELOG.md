# Changelog

All notable changes to Reflex are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ib-client`: captures events from stdin, buffers them in a bounded drop-oldest ring, and streams them to the server over mutual TLS with a resumable, acknowledged link and capped exponential backoff.
- `ib-server`: accepts any number of clients over mutual TLS, verifies a per-client token proof bound to the TLS session, deduplicates by sequence number, and writes one tab-separated line per event to stdout.
- `ib-certgen`: mints a private CA, a server certificate, and a certificate plus token for each client, with keys and tokens written as `0600`.
- `protocol` crate shared by both binaries: `bincode` messages, HMAC-SHA256 handshake proofs, and a 1 MiB cap on encode and decode. Protocol version 2.
- End-to-end tests that spawn the real binaries and cover the happy path, refusal of anonymous peers, bad tokens, impersonation, and sequence poisoning.
- Guide to generating, distributing, adding, rotating and revoking credentials in `doc/how-to-generate-tls-server.md`.
