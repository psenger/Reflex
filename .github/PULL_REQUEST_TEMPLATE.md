## What

<!-- One or two sentences on what this changes. -->

## Why

<!-- The problem this solves. Link the issue if there is one. -->

## How it was tested

<!-- Commands run, tests added, manual steps. -->

## Checklist

- [ ] `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass locally
- [ ] Tests cover the change (unit test in `protocol`, or end-to-end test in `e2e`)
- [ ] README tables updated if a message, validation step, constant, guarantee or limitation changed
- [ ] `PROTOCOL_VERSION` bumped if a message layout or proof transcript changed
- [ ] `CHANGELOG.md` has an entry under Unreleased
- [ ] No certificates, keys or tokens in the diff
