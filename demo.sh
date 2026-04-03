#!/usr/bin/env bash
# End-to-end demo: two forum instances with different K/N-of-M parameters.
# Forum A: lenient  — K=3 strikes, 2-of-3 moderators
# Forum B: strict   — K=5 strikes, 3-of-5 moderators
#
# Usage:
#   RISC0_DEV_MODE=1 ./demo.sh             # fast mock proofs (~30 s)
#   SKIP_REAL_PROOF=1 ./demo.sh            # same, skip the real-proof section
#   ./demo.sh                              # real STARK at the end (~5 min)
set -euo pipefail

BINARY=${BINARY:-./target/release/forum-anon}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

export RISC0_DEV_MODE=1

echo "==> building release binary"
cargo build --release -p forum-anon -q

# helpers
rand32() { dd if=/dev/urandom bs=32 count=1 2>/dev/null | xxd -p | tr -d '\n'; }

merkle_root() {
  python3 - "$1" <<'PYEOF'
import sys, hashlib

def hash_leaf(b):
    return hashlib.sha256(b).digest()

def hash_pair(l, r):
    return hashlib.sha256(l + r).digest()

L0 = hash_leaf(bytes.fromhex(sys.argv[1]))
L1 = hash_leaf(bytes(32))
L2 = hash_leaf(bytes(32))
L3 = hash_leaf(bytes(32))
P0 = hash_pair(L0, L1)
P1 = hash_pair(L2, L3)
print(hash_pair(P0, P1).hex())
PYEOF
}

echo ""
echo "--- FAST DEMO (RISC0_DEV_MODE=1) ---"
echo ""

# Forum A: K=3 strikes to slash, 2-of-3 moderators
echo "--- Forum A: K=3, 2-of-3 moderators ---"
FORUM_A=$(rand32)
echo "   forum_id: $FORUM_A"

echo "[A-1] keygen — Alice"
"$BINARY" keygen --out "$TMP/alice.key"

echo "[A-2] register Alice (threshold=2, total=3)"
REG=$("$BINARY" register \
        --key "$TMP/alice.key" \
        --forum "$FORUM_A" \
        --total 3 --threshold 2)
ALICE_COMMIT=$(echo "$REG" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['commitment'])")
ALICE_TAG=$(echo "$REG"    | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['member_tag'])")
for i in 0 1 2; do
  echo "$REG" | python3 -c \
    "import sys,json;d=json.load(sys.stdin);print(json.dumps(d['shares'][$i]))" \
    > "$TMP/alice_share_$i.json"
done
echo "   commitment: $ALICE_COMMIT"
echo "   member_tag: $ALICE_TAG"

ROOT_A=$(merkle_root "$ALICE_COMMIT")
echo "   merkle_root: $ROOT_A"
TOPIC_A=$(rand32)

echo "[A-3] prove-post — Alice"
"$BINARY" post \
  --key "$TMP/alice.key" --forum "$FORUM_A" --topic "$TOPIC_A" \
  --root "$ROOT_A" --leaf-index 0 --num-leaves 4 \
  --out "$TMP/proof_a.bin"
echo "   proof: $TMP/proof_a.bin ($(wc -c < "$TMP/proof_a.bin") bytes)"

# Forum A uses 2-of-3: collect 2 votes
MOD_A1=$(rand32); MOD_A2=$(rand32)
echo "$MOD_A1" | xxd -r -p > "$TMP/mod_a1.key"
echo "$MOD_A2" | xxd -r -p > "$TMP/mod_a2.key"
CONTENT_A=$(rand32)

echo "[A-4] moderate (2 votes, threshold=2)"
"$BINARY" moderate \
  --key "$TMP/mod_a1.key" --forum "$FORUM_A" \
  --post-hash "$CONTENT_A" --member-tag "$ALICE_TAG" --reason "spam" \
  --out "$TMP/vote_a1.json"
"$BINARY" moderate \
  --key "$TMP/mod_a2.key" --forum "$FORUM_A" \
  --post-hash "$CONTENT_A" --member-tag "$ALICE_TAG" --reason "spam" \
  --out "$TMP/vote_a2.json"

echo "[A-5] aggregate-cert (2-of-3)"
"$BINARY" aggregate-cert \
  --votes "$TMP/vote_a1.json" "$TMP/vote_a2.json" \
  --threshold-n 2 \
  --out "$TMP/cert_a.json"
echo "   cert written: $TMP/cert_a.json"

# Generate 3 certs (K=3 required to slash)
CONTENT_A2=$(rand32); CONTENT_A3=$(rand32)
for i in 2 3; do
  C=$(eval echo "\$CONTENT_A$i")
  for j in 1 2; do
    "$BINARY" moderate \
      --key "$TMP/mod_a$j.key" --forum "$FORUM_A" \
      --post-hash "$C" --member-tag "$ALICE_TAG" --reason "spam" \
      --out "$TMP/vote_a${j}_$i.json"
  done
  "$BINARY" aggregate-cert \
    --votes "$TMP/vote_a1_$i.json" "$TMP/vote_a2_$i.json" \
    --threshold-n 2 --out "$TMP/cert_a_$i.json"
done

echo "[A-6] slash Alice (K=3 certs, 2 shares)"
"$BINARY" slash \
  --forum "$FORUM_A" --member-tag "$ALICE_TAG" \
  --certs "$TMP/cert_a.json" "$TMP/cert_a_2.json" "$TMP/cert_a_3.json" \
  --shares "$TMP/alice_share_0.json" "$TMP/alice_share_1.json" \
  --out "$TMP/slash_a.json"
echo "   slash payload: $TMP/slash_a.json"
python3 -m json.tool "$TMP/slash_a.json" 2>/dev/null | head -8 || cat "$TMP/slash_a.json" | head -8

echo ""
echo "   Forum A: ✓  K=3 slash demonstrated (2-of-3 moderators)"

# Forum B: K=5 strikes to slash, 3-of-5 moderators
echo ""
echo "--- Forum B: K=5, 3-of-5 moderators ---"
FORUM_B=$(rand32)
echo "   forum_id: $FORUM_B"

echo "[B-1] keygen — Bob"
"$BINARY" keygen --out "$TMP/bob.key"
REG_B=$("$BINARY" register \
          --key "$TMP/bob.key" \
          --forum "$FORUM_B" \
          --total 5 --threshold 3)
BOB_COMMIT=$(echo "$REG_B" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['commitment'])")
BOB_TAG=$(echo "$REG_B"    | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['member_tag'])")
for i in 0 1 2 3 4; do
  echo "$REG_B" | python3 -c \
    "import sys,json;d=json.load(sys.stdin);print(json.dumps(d['shares'][$i]))" \
    > "$TMP/bob_share_$i.json"
done
echo "   commitment: $BOB_COMMIT"
echo "   member_tag: $BOB_TAG"

ROOT_B=$(merkle_root "$BOB_COMMIT")
TOPIC_B=$(rand32)

echo "[B-2] prove-post — Bob"
"$BINARY" post \
  --key "$TMP/bob.key" --forum "$FORUM_B" --topic "$TOPIC_B" \
  --root "$ROOT_B" --leaf-index 0 --num-leaves 4 \
  --out "$TMP/proof_b.bin"
echo "   proof: $TMP/proof_b.bin ($(wc -c < "$TMP/proof_b.bin") bytes)"

# Forum B: 3-of-5 moderators, 5 certs to slash
for j in 1 2 3 4 5; do
  SEED=$(rand32); echo "$SEED" | xxd -r -p > "$TMP/mod_b$j.key"
done

echo "[B-3] moderate — 5 separate certs (3-of-5 each), K=5 to slash"
for i in $(seq 1 5); do
  CHASH=$(rand32)
  for j in 1 2 3; do
    "$BINARY" moderate \
      --key "$TMP/mod_b$j.key" --forum "$FORUM_B" \
      --post-hash "$CHASH" --member-tag "$BOB_TAG" --reason "harassment" \
      --out "$TMP/vote_b${j}_$i.json"
  done
  "$BINARY" aggregate-cert \
    --votes "$TMP/vote_b1_$i.json" "$TMP/vote_b2_$i.json" "$TMP/vote_b3_$i.json" \
    --threshold-n 3 --out "$TMP/cert_b_$i.json"
done
echo "   5 certs written"

echo "[B-4] slash Bob (K=5 certs, 3 shares)"
"$BINARY" slash \
  --forum "$FORUM_B" --member-tag "$BOB_TAG" \
  --certs "$TMP/cert_b_1.json" "$TMP/cert_b_2.json" \
          "$TMP/cert_b_3.json" "$TMP/cert_b_4.json" "$TMP/cert_b_5.json" \
  --shares "$TMP/bob_share_0.json" "$TMP/bob_share_1.json" "$TMP/bob_share_2.json" \
  --out "$TMP/slash_b.json"
echo "   slash payload: $TMP/slash_b.json"
python3 -m json.tool "$TMP/slash_b.json" 2>/dev/null | head -8 || cat "$TMP/slash_b.json" | head -8

echo ""
echo "   Forum B: ✓  K=5 slash demonstrated (3-of-5 moderators)"

echo ""
echo "--- FAST DEMO COMPLETE ---"
echo "  Forum A: K=3 strikes, 2-of-3 mods"
echo "  Forum B: K=5 strikes, 3-of-5 mods"

# Real STARK proof section
if [[ "${SKIP_REAL_PROOF:-0}" == "1" ]]; then
  echo ""
  echo "(skipping real STARK proof — SKIP_REAL_PROOF=1)"
  exit 0
fi

echo ""
echo "--- REAL ZK PROOF (RISC0_DEV_MODE unset) ---"
echo "Generating STARK on Forum A..."
unset RISC0_DEV_MODE

echo "[real] keygen — Carol"
"$BINARY" keygen --out "$TMP/carol.key"
REG_C=$("$BINARY" register \
          --key "$TMP/carol.key" \
          --forum "$FORUM_A" \
          --total 3 --threshold 2)
CAROL_COMMIT=$(echo "$REG_C" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['commitment'])")
ROOT_C=$(merkle_root "$CAROL_COMMIT")
TOPIC_C=$(rand32)

echo "[real] prove-post — Carol (RISC0_DEV_MODE unset — real STARK)"
time "$BINARY" post \
  --key "$TMP/carol.key" --forum "$FORUM_A" --topic "$TOPIC_C" \
  --root "$ROOT_C" --leaf-index 0 --num-leaves 4 \
  --out "$TMP/carol_proof.bin"

echo ""
echo "   real proof: $TMP/carol_proof.bin ($(wc -c < "$TMP/carol_proof.bin") bytes)"
echo ""
echo "--- ALL DONE ---"
