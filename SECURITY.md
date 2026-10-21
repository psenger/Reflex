# Security policy

Reflex is designed on the assumption that the network between client and server is hostile. The [security model](README.md#security-model) in the README describes what each layer stops, what each side validates, and what a rogue client can and cannot do. This file covers how to report a problem with that model and what is in scope.

## Reporting a vulnerability

Do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting on this repository: the **Security** tab, then **Report a vulnerability**. Include:

- which binary or crate is affected;
- the versions or commit you tested;
- steps to reproduce, ideally as a test against the real binaries in the style of `e2e/tests/e2e.rs`;
- what an attacker gains.

You will get an acknowledgement, and a fix or a decision, as quickly as a part-time maintainer can manage. Please give a reasonable window before publishing details.

## Supported versions

Reflex is experimental. Only the `main` branch and the most recent release receive fixes.

## In scope

Anything that lets a party do something the security model says it cannot. For example:

- a peer without a certificate from the private CA getting past the TLS handshake;
- a valid certificate holder authenticating as a client id whose token it does not hold;
- a proof from one connection being accepted on another;
- a client, authenticated or not, causing the server to allocate unboundedly, hang, or drop events for another client;
- a client poisoning its own dedup state so that later genuine events are discarded;
- frames or messages that bypass the 1 MiB cap, the handshake timeout, or the liveness deadline;
- `ib-certgen` writing a key or token with permissions wider than `0600` on Unix, or producing certificates that fail to chain.

## Out of scope

These are documented in the README under [Limitations](README.md#limitations) and are design choices, not vulnerabilities:

- A compromised client host. Whoever holds a client's `.key` and `.token` is that client, in the same way an SSH private key holder is that user.
- Anything a legitimately authenticated client does with its own event payloads or timestamps. The server trusts authenticated content.
- Absence of rate limiting or a connection cap per client.
- Two sessions using the same credentials at once.
- No certificate revocation list. Revocation is by removing a line from the token file.
- Server delivery state living in memory and being lost on restart.
- Bounded buffers dropping events by design, with counters.

If you think one of these should become in scope, open an ordinary issue to discuss it.

## Handling credentials

`ib-certgen` writes private keys and tokens with mode `0600`. The CA private key `ca.key` is needed only to issue more certificates and should be kept off any host that runs Reflex. The repository's `.gitignore` excludes `certs/`, `*.key`, `*.token` and `tokens.txt`. If you find credentials committed to this repository, report it as a vulnerability.
