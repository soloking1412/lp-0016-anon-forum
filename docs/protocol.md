# LP-0016 Cryptographic Protocol

## Overview

Forum Anon provides truly anonymous, moderated forums on the Logos stack.  Posts
are unlinkable across threads, a coordinated N-of-M moderator group issues
strikes, and K accumulated strikes trigger an on-chain slash that retroactively
deanonymizes the offender.

---

## 1. Identity Commitment Scheme

All hashes use SHA256 with domain-separated prefixes to prevent second-preimage
attacks across different uses of the same input.

```
id_secret     = random_bytes(32)   -- held privately by member only
commitment    = SHA256("forum/v1/commitment:" ‖ id_secret)
member_tag    = SHA256("forum/v1/member-tag:" ‖ id_secret ‖ forum_id)
post_nullifier = SHA256("forum/v1/post-null:"  ‖ id_secret ‖ ext_nullifier)
```

`commitment` is stored as a Merkle leaf in the on-chain registry.
`member_tag` is stable per (member × forum) and enables moderation tracking.
`post_nullifier` is unique per (member × topic) and prevents double-posting.

---

## 2. Membership Merkle Tree

Leaves are `SHA256(commitment)` (double-hash to resist length-extension).
Internal nodes are `SHA256(left ‖ right)`.  Tree depth is `log2(num_members)`
rounded up to the next power of two.

The circuit verifies a Merkle membership path from `commitment` to `merkle_root`
inside the zkVM, so the verifier only sees the root and the circuit outputs.

---

## 3. ZK Circuit (Risc0 Guest)

**Private inputs** (never leave the prover):
- `id_secret: [u8; 32]`
- `merkle_proof: MerkleProof`

**Public inputs** (passed alongside the witness):
- `merkle_root: [u8; 32]`
- `forum_id: [u8; 32]`
- `ext_nullifier: [u8; 32]` — typically `SHA256(topic_id)`
- `presenter_pubkey: [u8; 32]` — binds proof to one holder

**Journal output** (publicly verifiable):
- `merkle_root, forum_id, member_tag, post_nullifier, ext_nullifier, presenter_pubkey`

**Guest logic:**
1. `commitment = SHA256("forum/v1/commitment:" ‖ id_secret)`
2. Verify Merkle path: `commitment` is a leaf of `merkle_root`
3. `member_tag = SHA256("forum/v1/member-tag:" ‖ id_secret ‖ forum_id)`
4. `post_nullifier = SHA256("forum/v1/post-null:" ‖ id_secret ‖ ext_nullifier)`
5. `env::commit_slice(&borsh::to_vec(&MembershipProof { … }))`

---

## 4. Shamir Secret Sharing (Retroactive Deanonymization)

At registration, the member splits `id_secret` into M shares with threshold K
using Shamir's secret sharing over GF(2^8):

- **Polynomial**: degree-(K−1) polynomial with `id_secret[i]` as the constant
  term for each of the 32 secret bytes.
- **Shares**: `share_j = (j, f(j))` for `j = 1..M`, evaluated byte-by-byte.
- **Commitment**: each share is committed as
  `SHA256("forum/v1/share-commit:" ‖ index ‖ value)` and stored on-chain.
- **Distribution**: shares are encrypted to moderator pubkeys and sent
  out-of-band (Logos Messaging).

At slash time, K moderators reveal their shares.  The registry verifies each
share against its on-chain commitment, then performs Lagrange interpolation to
reconstruct `id_secret` and verifies:

```
SHA256("forum/v1/commitment:" ‖ reconstructed) == commitment
```

A match proves that the slashed `member_tag` belongs to this commitment.

### Security

- Any K−1 shares reveal zero information about `id_secret` (information-theoretic
  security of Shamir's scheme over GF(256)).
- Moderators cannot forge shares — each is bound to its commitment on-chain.
- Lagrange interpolation is performed over GF(2^8) (characteristic 2, so
  addition is XOR and subtraction is identical to addition).

---

## 5. N-of-M Moderation Certificates

A moderator vote message is:

```
SHA256("forum/v1/vote:" ‖ forum_id ‖ content_hash ‖ member_tag ‖ reason)
```

A moderator signs this message with their Ed25519 key.  A `ModerationCert`
aggregates N or more such votes covering the same `(forum_id, content_hash,
member_tag)` triple.

**Properties:**
- Fewer than N moderators cannot produce a valid cert.
- Certs accumulate against `member_tag`, not against content or identity — so
  the member is trackable within a forum while remaining anonymous to outsiders.
- Certs are stored off-chain (Logos Messaging / public bulletin); only the slash
  transaction goes on-chain.

---

## 6. Slash Protocol

A slash transaction contains:
- K valid `ModerationCert`s (each with N Ed25519 signatures)
- K Shamir shares (from K distinct moderators)

The on-chain registry:
1. Verifies K certs have no duplicates (by `content_hash`)
2. Verifies each cert has N valid moderator signatures
3. Verifies each Shamir share against its on-chain commitment
4. Reconstructs `id_secret` via Lagrange interpolation
5. Asserts `SHA256("forum/v1/commitment:" ‖ id_secret) == commitment`
6. Adds `commitment` to the revocation set
7. Marks the member record as revoked

After a slash, any future post with a `post_nullifier` derived from this member's
`id_secret` will be rejected by the registry's `VerifyPost` instruction.

---

## 7. Retroactive Deanonymization Upon Slash

When a slash is executed, K moderators reveal their Shamir shares.  The on-chain
registry performs Lagrange interpolation over GF(2^8) to reconstruct the full
`id_secret` and verifies:

```
SHA256("forum/v1/commitment:" ‖ reconstructed_id_secret) == commitment
```

With `id_secret` now known, any observer can compute:

```
member_tag    = SHA256("forum/v1/member-tag:" ‖ id_secret ‖ forum_id)
post_nullifier_i = SHA256("forum/v1/post-null:" ‖ id_secret ‖ ext_nullifier_i)
```

Every post previously published under this `member_tag` is now retroactively
attributable to the reconstructed identity.  The `id_secret` also allows
verification of which `post_nullifier` values belong to this member, linking all
of their posts across every topic in the forum.

**No other member's anonymity is affected.**  Each member's `id_secret` is
independent.  Knowing one `id_secret` provides zero information about any other
member's `id_secret`, commitment, or post history.  The Shamir shares distributed
at registration are specific to the slashed member; shares from other members
remain secret.

---

## 9. Unlinkability Argument

**Across topics:** Each post uses `ext_nullifier = SHA256(topic_id)`.
Different topics produce different `post_nullifier` values.  A verifier seeing
`(member_tag, post_nullifier_A)` and `(member_tag, post_nullifier_B)` knows
they are from the same forum member but cannot link the underlying identity.

**Across forums:** `member_tag` includes `forum_id` in its hash.  A member's
tag in forum A is computationally independent of their tag in forum B.

**Anonymity set:** All non-revoked registered members.

---

## 10. Threat Model

| Threat | Mitigation |
|---|---|
| Malicious member posts rule-violating content | K strikes → slash → revocation + stake loss |
| Single malicious moderator issues false certs | N-of-M threshold: need N colluding mods per cert, K such certs |
| Moderators deanonymize without K strikes | Cannot reconstruct without K shares; need legitimate certs |
| Member submits fake Shamir shares at slash | On-chain commitments detect substitution |
| Member registers twice | One `commitment` per leaf; duplicate check in registry |
| Post from revoked member | `post_nullifier` blocked by registry |
| Proof replay across forums | `forum_id` in `member_tag` and in `PostPublicInputs` |

---

## 11. Parameterisation

| Parameter | Description | Example values |
|---|---|---|
| K | Strikes to slash | 3 (lenient), 5 (strict) |
| N | Votes per cert | 2 (fast), 3 (cautious) |
| M | Total moderators | 5, 7 |
| stake_required | Deposit at registration | 1000 base units |
