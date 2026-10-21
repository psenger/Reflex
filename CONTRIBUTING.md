# Contributing to Reflex

Thanks for considering a contribution. Reflex is small and the transport, security and reliability layers are meant to stay small. This guide explains how to build and test it, what a change needs to include, and how changes to the protocol or the security model are reviewed.

## Before you start

- Open an issue first for anything beyond a bug fix or a typo. A short description of the problem and the approach saves a round trip on the pull request.
- Security vulnerabilities go through [SECURITY.md](SECURITY.md), not the issue tracker.
- Contributions that are welcome: bug fixes, real OS capture backends, alternative sinks, test coverage, documentation fixes, and portability work.
- Contributions that need discussion first: anything that weakens a check in the [security model](README.md#security-model), adds a network listener on the client, or makes the server dial out.

## Prerequisites

- A current stable Rust toolchain with `rustfmt` and `clippy`. Install via [rustup](https://rustup.rs).
- `openssl` on your path is optional. It is only used by the recipes in [doc/how-to-generate-tls-server.md](doc/how-to-generate-tls-server.md).

Linux and macOS are tested in CI. Windows is not yet exercised; the end-to-end tests look for binaries without an `.exe` suffix.

## Build and test

Run everything from the workspace root.

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

`cargo test --workspace` builds `ib-server`, `ib-client` and `ib-certgen` and then runs the end-to-end tests against them. The tests mint their own credentials in a temporary directory and pick a free port, so nothing in `certs/` is needed and tests can run in parallel.

CI runs the same four commands. A pull request must pass all of them.

## Layout

| Crate       | Purpose                                                                 |
|-------------|-------------------------------------------------------------------------|
| `protocol/` | Message types, HMAC proofs, encode and decode. Shared by both binaries. |
| `server/`   | `ib-server`. Mutual TLS, token check, dedup, acks, sink.                |
| `client/`   | `ib-client`. Capture, bounded ring, resumable link.                     |
| `certgen/`  | `ib-certgen`. Mints the CA, certificates and tokens.                    |
| `e2e/`      | End-to-end tests that spawn the real binaries.                          |

The README has a fuller description under [How it works](README.md#how-it-works).

## What a change needs

**Tests.** Protocol changes get a unit test in `protocol/src/lib.rs`. Behaviour that crosses a binary boundary gets an end-to-end test in `e2e/tests/e2e.rs`. A fix for a bug includes a test that fails without the fix.

**Documentation in the same pull request.** The README is the reference for behaviour. If you change any of the following, update the matching section:

| You changed                                   | Update                                                               |
|-----------------------------------------------|----------------------------------------------------------------------|
| A message or field in `protocol`              | Wire protocol table, and bump `PROTOCOL_VERSION`                     |
| A validation step on either side              | The two "What each side validates" tables, in order                  |
| A `const` like `HEARTBEAT` or `MAX_UNACKED`   | Tuning table                                                         |
| Behaviour under a failure                     | Delivery guarantees table                                            |
| Something Reflex now does, or still does not  | Limitations                                                          |
| `ib-certgen` flags or output                  | `doc/how-to-generate-tls-server.md`                                  |

**Protocol version.** Any change to the layout of a message, or to what either proof is computed over, bumps `PROTOCOL_VERSION` in `protocol/src/lib.rs`. Each side rejects a peer with a different version, so a bump is what stops an old client talking to a new server with a mismatched layout.

**Security-relevant changes.** A change to TLS configuration, the token handshake, sequence checks, timeouts or frame limits needs:

- an end-to-end test that shows the refusal still happens, or that the new refusal happens;
- the README tables kept accurate, because they are the contract users rely on;
- a note in the pull request on what an attacker could do before and after.

**No credentials in the tree.** `.gitignore` excludes `certs/`, `*.key`, `*.token` and `tokens.txt`. Do not add exceptions. Tests mint what they need.

**Style.** `rustfmt` defaults, no configuration file. Clippy clean with warnings denied. Comments explain why, not what. Keep the tuning constants at the top of the relevant `main.rs` so they stay visible.

**Dependencies.** Add a new crate to `[workspace.dependencies]` in the root `Cargo.toml` and reference it with `workspace = true` from the member crate, so versions stay in lock-step. Prefer crates that are already in the tree.

## Pull requests

1. Branch from `main`. Use a short descriptive name such as `fix/handshake-timeout` or `feat/evdev-capture`.
2. Keep one change per pull request. A refactor and a behaviour change go in separately.
3. Make sure the four commands under [Build and test](#build-and-test) pass locally.
4. Fill in the pull request template. Say what changed, why, and how you tested it.
5. Add an entry under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for anything a user would notice.

Reviews look for correctness first, then whether the README still describes what the code does, then style.

## Commits

- Imperative subject line, 72 characters or fewer. `Reject a second Hello on an open connection`, not `Fixed hello bug`.
- The body explains why. The diff already shows what.
- If an AI assistant helped write the commit, add a `Co-Authored-By:` trailer naming it as the last line of the message.

## Reporting bugs

Open an issue with:

- the output of `rustc --version` and the commit or version of Reflex;
- the exact commands run for `ib-certgen`, `ib-server` and `ib-client`, with secrets removed;
- the server's stderr and the client's stderr around the failure;
- what you expected instead.

The [troubleshooting table](doc/how-to-generate-tls-server.md#troubleshooting) covers the common certificate and token mistakes. Check it first.

## Licence

Reflex is dual-licensed under MIT and Apache 2.0. Unless you state otherwise, any contribution you intentionally submit for inclusion is licensed the same way, without additional terms or conditions, as described in section 5 of the Apache License.
