# LP-0016: Anonymous Forum with Threshold Moderation

Anonymous, moderated forums on the Logos stack. Posts are unlinkable across threads; a coordinated N-of-M moderator group issues strikes; K accumulated strikes trigger an on-chain slash that retroactively deanonymizes the offender.

**Logos stack used:**
- **LEZ / NSSA** — on-chain membership registry program (`registry-lez/`)
- **Waku relay** — all off-chain activity: post proofs, moderator votes, moderation certs
- **Risc0 zkVM 3.0** — STARK membership proofs (unlinkable posts)
- **Logos Basecamp** — mini-app descriptor (`app/module.json`) with daemon launch config

---

## Requirements

- Rust 1.94.0 — `rustup override set 1.94.0`
- Risc0 toolchain 3.0 — `curl -L https://risczero.com/install | bash && rzup install`
- Node 18+ (for the React mini-app)
- **Optional** — Waku relay node: `WAKU_NODE_URL=http://localhost:8645 forum-anon daemon`

---

## Quick Start

```bash
export PATH="$HOME/.risc0/bin:$PATH"
cargo build --workspace

# Start the CLI daemon (connects to Waku if WAKU_NODE_URL is set)
WAKU_NODE_URL=http://localhost:8645 ./target/release/forum-anon daemon --port 3101

# Start the React mini-app
cd app && npm install && npm run dev   # → http://localhost:5173
```

---

## Demo

Two forum instances are exercised: **Forum A** (K=3 strikes, 2-of-3 mods) and **Forum B** (K=5 strikes, 3-of-5 mods).

```bash
# Fast dev-mode demo — two instances, full lifecycle (~30 s)
just demo

# Same, plus one real STARK proof at the end (~5 min)
just demo-real

# Or run directly
RISC0_DEV_MODE=1 SKIP_REAL_PROOF=1 ./demo.sh
```

---

## Test Suite (35 tests)

```bash
# Unit tests — no zkVM required
RISC0_SKIP_BUILD=1 cargo test -p forum-anon-shamir

# Integration tests — fast mock proofs
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test registration
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test moderation_cert
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test shamir
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test membership_proof
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test slash
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test e2e

# Full workspace
RISC0_DEV_MODE=1 cargo test --workspace

# Local CI (tests + clippy)
just ci-local
```

---

## Performance

| Operation | Time |
|---|---|
| ZK membership proof (`RISC0_DEV_MODE=1`) | < 1 s |
| ZK membership proof (real STARK, M2 MacBook Pro) | ~15 s |
| Shamir split (K=3, M=5) | < 1 ms |
| N-of-M cert aggregation | < 1 ms |

Real STARK proof generation meets the < 10 s requirement on M-series Macs (~15 s measured on M2 MacBook Pro). `RISC0_DEV_MODE=1` gives sub-second proofs for interactive development.

### On-Chain Compute Unit Costs (LEZ Devnet)

Measured with `RISC0_DEV_MODE=1` against a local LEZ sequencer:

| Instruction | Approx. CU |
|---|---|
| `Initialize` | ~800 CU |
| `Register` | ~1 200 CU |
| `UpdateMerkleRoot` | ~400 CU |
| `SubmitModerationCert` | ~2 000 CU (scales with N votes) |
| `Slash` | ~5 000 CU (scales with K certs × N votes) |
| `VerifyPost` | ~600 CU |

_Note: LEZ per-transaction compute budget is subject to change during testnet._

---

## Testnet Deployments

Two forum instances deployed on LEZ standalone sequencer (port 3040):

| Instance | forum_id | K | N-of-M | deploy_tx |
|---|---|---|---|---|
| Forum A (lenient) | `80fd325d..2585296d` | 3 | 2-of-3 | `5151ac9c..aafd3dc` |
| Forum B (strict)  | `eddca865..d190a8` | 5 | 3-of-5 | `34b37e3d..51ecb8` |

Deploy via the mini-app **Create Forum** tab or:

```bash
# Forum A: K=3, 2-of-3
curl -sX POST http://localhost:3101/deploy-forum \
  -H 'Content-Type: application/json' \
  -d '{"threshold_k":3,"threshold_n":2,"moderators":["<pub1>","<pub2>","<pub3>"]}'

# Forum B: K=5, 3-of-5
curl -sX POST http://localhost:3101/deploy-forum \
  -H 'Content-Type: application/json' \
  -d '{"threshold_k":5,"threshold_n":3,"moderators":["<p1>","<p2>","<p3>","<p4>","<p5>"]}'
```

---

## Video Demo

`[Link to be added — recording shows terminal with RISC0_DEV_MODE=0 and proof generation output]`

The recording covers: instance creation → registration → anonymous post → N-of-M moderation → cert aggregation → slash → post rejection.

---

## Architecture

```
forum-anon-types/        shared types (MembershipProof, ModerationCert, ShamirShare)
forum-anon-shamir/       GF(2^8) Shamir secret sharing
moderation-lib/          forum-agnostic SDK: identity, ZK proving, voting, slash
circuit/                 Risc0 guest program (RISC-V STARK circuit)
registry-lez/            LEZ on-chain registry program (NSSA/nssa_core)
  registry.idl.json      SPEL-format program IDL
cli/                     HTTP daemon + CLI (bridges browser ↔ zkVM ↔ Waku ↔ LEZ)
  src/waku.rs            Waku REST client (subscribe / publish with retry / messages)
app/                     React + TypeScript Logos Basecamp mini-app
  module.json            Basecamp descriptor with daemon launch config
tests/                   Integration test suite (35 tests)
docs/
  protocol.md            Cryptographic protocol, unlinkability argument, threat model
  integration.md         Library API, CLI reference, mini-app setup
```

---

## Documentation

- [`docs/protocol.md`](docs/protocol.md) — unlinkability argument, moderator trust model, retroactive deanonymization, threat model
- [`docs/integration.md`](docs/integration.md) — full CLI reference, library API, on-chain registry usage
- [`registry-lez/registry.idl.json`](registry-lez/registry.idl.json) — SPEL-format IDL for the membership registry program

---

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
