# LP-0016: Anonymous Forum with Threshold Moderation

Anonymous, moderated forums on the Logos stack. Posts are unlinkable across threads; a coordinated N-of-M moderator group issues strikes; K accumulated strikes trigger an on-chain slash that retroactively deanonymizes the offender.

## Requirements

- Rust (stable)
- Risc0 toolchain 3.0 — install via `rzup install` or `cargo risczero install`

## Quick start

```bash
export PATH="$HOME/.risc0/bin:$PATH"
cargo build --workspace
```

## Test suite (33 tests)

```bash
# Unit tests only (no zkVM required)
RISC0_SKIP_BUILD=1 cargo test -p forum-anon-shamir

# Integration tests with ZK in fast dev mode (no GPU needed)
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test registration
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test moderation_cert
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test shamir
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test membership_proof
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test slash
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test e2e

# Full suite
RISC0_DEV_MODE=1 cargo test --workspace
```

See [`docs/integration.md`](docs/integration.md) for the full CLI reference and library API.
See [`docs/protocol.md`](docs/protocol.md) for the cryptographic protocol specification.
