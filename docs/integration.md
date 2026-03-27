# Integration Guide

## Quick Start

```bash
# Build
export PATH="$HOME/.risc0/bin:$PATH"
cargo build --workspace

# All tests (fast, dev mode — no GPU needed)
RISC0_DEV_MODE=1 cargo test --workspace

# CLI
./target/debug/forum-anon --help
```

## CLI Reference

### `keygen`

Generate a new member identity key.  The 32-byte `id_secret` is stored raw.

```bash
forum-anon keygen --out identity.key
# → Commitment: <64-char hex>
```

### `register`

Output registration data (commitment, member_tag, Shamir shares) for a forum.

```bash
forum-anon register \
  --key identity.key \
  --forum <forum-id-hex> \
  --stake 1000 \
  --threshold 3 \
  --total 5
# → JSON: { commitment, member_tag, shamir_commitments, shares }
```

Distribute `shares[i]` to moderator `i` out-of-band (encrypt to their pubkey).

### `moderate`

Issue a moderator vote for a piece of content.

```bash
forum-anon moderate \
  --key mod.key \
  --forum <forum-id-hex> \
  --post-hash <sha256-of-content-hex> \
  --member-tag <member-tag-hex> \
  --reason "spam" \
  --out vote.json
```

### `aggregate-cert`

Combine N or more votes into a moderation certificate.

```bash
forum-anon aggregate-cert \
  --votes vote1.json vote2.json vote3.json \
  --threshold-n 2 \
  --out cert.json
```

### `slash`

Build a slash transaction from K certs and K Shamir shares.

```bash
forum-anon slash \
  --forum <forum-id-hex> \
  --member-tag <member-tag-hex> \
  --certs cert1.json cert2.json cert3.json \
  --shares share1.json share2.json share3.json \
  --out slash.json
```

### `verify-share`

Verify a Shamir share against its on-chain commitment.

```bash
forum-anon verify-share --share share1.json --commitment <hex>
# → Share is VALID
```

### `verify-slash`

Reconstruct `id_secret` off-chain and verify against commitment.

```bash
forum-anon verify-slash \
  --shares share1.json share2.json share3.json \
  --commitment <hex>
# → Reconstruction OK — id_secret: <hex>
```

## Library API

```rust
use forum_anon_moderation::{
    identity::{MemberIdentity, split_identity, verify_share},
    membership::{prove_post, verify_post},
    moderation::{draft_vote, aggregate_votes, verify_cert},
    slash::{build_slash, reconstruct_and_verify},
};
```

### Identity

```rust
let identity = MemberIdentity::generate(&mut OsRng);
let commitment = identity.commitment();
let member_tag = identity.member_tag(&forum_id);

// Shamir split (at registration)
let (shares, commitments) = split_identity(&identity, 3, 5, &mut OsRng)?;
// → shares: distribute to moderators
// → commitments: store on-chain
```

### Posting

```rust
let receipt = prove_post(
    &identity,
    merkle_proof,       // from on-chain tree
    merkle_root,
    forum_id,
    ext_nullifier,      // SHA256(topic_id)
    presenter_pubkey,
)?;

// Verify on recipient side
let proof = verify_post(&receipt, &forum_id, &merkle_root)?;
// proof.member_tag — stable pseudonym
// proof.post_nullifier — unique per topic
```

### Moderation

```rust
let vote = draft_vote(forum_id, content_hash, member_tag, reason, &signing_key)?;
// Collect N votes from different moderators, then:
let cert = aggregate_votes(votes, threshold_n)?;
verify_cert(&cert, &moderator_pubkeys, threshold_n)?;
```

### Slash

```rust
let slash = build_slash(forum_id, member_tag, certs, shares);
// Submit to on-chain registry

// Off-chain verification
let id_secret = reconstruct_and_verify(&shares, &commitment)?;
```

## On-Chain Registry

The registry is a LEZ stateless program.  All state is passed in and returned.

```rust
use forum_anon_registry::{process, Instruction, RegistryError};

// Initialise a new forum
process(&mut state, Instruction::Initialize {
    forum_id, moderators, threshold_n: 2, threshold_k: 3,
    stake_required: 1000, initial_root,
})?;

// Register a member
process(&mut state, Instruction::Register {
    commitment, member_tag, stake: 1000, shamir_commitments,
})?;

// Submit a cert (increments strike_count)
process(&mut state, Instruction::SubmitModerationCert { cert })?;

// Slash (K certs + K shares → revocation)
process(&mut state, Instruction::Slash { slash })?;
```

## Running the Mini-App

```bash
cd app
npm install
npm run dev
# → http://localhost:3000
```

The app calls a local CLI daemon (`forum-anon daemon`) for ZK proof generation,
since Risc0 cannot run in the browser.  In RISC0_DEV_MODE=1, proofs are
instantaneous mock receipts.

## Test Suite

```bash
# Unit tests (no zkVM)
RISC0_SKIP_BUILD=1 cargo test -p forum-anon-shamir

# Integration tests (with ZK, fast dev mode)
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test registration
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test membership_proof
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test moderation_cert
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test slash
RISC0_DEV_MODE=1 cargo test -p forum-anon-tests --test e2e

# Full suite
RISC0_DEV_MODE=1 cargo test --workspace
```
