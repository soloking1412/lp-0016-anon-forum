use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, VerifyingKey};
use nssa_core::program::{AccountPostState, DEFAULT_PROGRAM_ID, ProgramInput, ProgramOutput, read_nssa_inputs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// All types derive both Borsh (account state storage) and Serde (instruction wire).
// Signature fields use Vec<u8> because serde doesn't support [u8; 64] by default.

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Default, Clone)]
struct RegistryState {
    forum_id:         [u8; 32],
    merkle_root:      [u8; 32],
    moderators:       Vec<[u8; 32]>,
    threshold_n:      u32,
    threshold_k:      u32,
    stake_required:   u64,
    members:          Vec<MemberRecord>,
    revocation_set:   Vec<[u8; 32]>,
    pending_certs:    Vec<ModerationCert>,
    spent_nullifiers: Vec<[u8; 32]>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
struct MemberRecord {
    commitment:         [u8; 32],
    member_tag:         [u8; 32],
    stake:              u64,
    strike_count:       u32,
    revoked:            bool,
    shamir_commitments: Vec<Vec<u8>>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
struct ModeratorVote {
    forum_id:         [u8; 32],
    content_hash:     [u8; 32],
    member_tag:       [u8; 32],
    strike_reason:    String,
    moderator_pubkey: [u8; 32],
    signature:        Vec<u8>,    // 64 bytes; Vec<u8> for serde compat
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
struct ModerationCert {
    forum_id:     [u8; 32],
    content_hash: [u8; 32],
    member_tag:   [u8; 32],
    votes:        Vec<ModeratorVote>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
struct ShamirShare {
    index: u8,
    value: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
struct SlashData {
    forum_id:   [u8; 32],
    member_tag: [u8; 32],
    certs:      Vec<ModerationCert>,
    shares:     Vec<ShamirShare>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone)]
struct MembershipProof {
    merkle_root:      [u8; 32],
    forum_id:         [u8; 32],
    member_tag:       [u8; 32],
    post_nullifier:   [u8; 32],
    ext_nullifier:    [u8; 32],
    presenter_pubkey: [u8; 32],
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
enum Instruction {
    Initialize {
        forum_id:       [u8; 32],
        moderators:     Vec<[u8; 32]>,
        threshold_n:    u32,
        threshold_k:    u32,
        stake_required: u64,
        initial_root:   [u8; 32],
    },
    Register {
        commitment:         [u8; 32],
        member_tag:         [u8; 32],
        stake:              u64,
        shamir_commitments: Vec<[u8; 32]>,
    },
    UpdateMerkleRoot { new_root: [u8; 32] },
    SubmitModerationCert { cert: ModerationCert },
    Slash { slash: SlashData },
    RejectNullifier { nullifier: [u8; 32] },
    VerifyPost { proof: MembershipProof },
}


fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn derive_commitment(id_secret: &[u8; 32]) -> [u8; 32] {
    sha256(&[b"forum/v1/commitment:", id_secret])
}

fn vote_message(forum_id: &[u8; 32], content_hash: &[u8; 32], member_tag: &[u8; 32], reason: &str) -> [u8; 32] {
    sha256(&[b"forum/v1/vote:", forum_id, content_hash, member_tag, reason.as_bytes()])
}

fn verify_share(share: &ShamirShare, commitment: &[u8; 32]) -> bool {
    &sha256(&[b"forum/v1/share-commit:", &[share.index], &share.value]) == commitment
}


fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    r
}

fn gf_inv(a: u8) -> u8 {
    let a2   = gf_mul(a, a);
    let a4   = gf_mul(a2, a2);
    let a8   = gf_mul(a4, a4);
    let a16  = gf_mul(a8, a8);
    let a32  = gf_mul(a16, a16);
    let a64  = gf_mul(a32, a32);
    let a128 = gf_mul(a64, a64);
    gf_mul(gf_mul(gf_mul(gf_mul(gf_mul(gf_mul(a128, a64), a32), a16), a8), a4), a2)
}

fn shamir_combine(shares: &[ShamirShare]) -> [u8; 32] {
    let k = shares.len();
    let mut secret = [0u8; 32];
    for byte_pos in 0..32 {
        let mut val = 0u8;
        for i in 0..k {
            let xi = shares[i].index;
            let yi = shares[i].value.get(byte_pos).copied().unwrap_or(0);
            let mut num = 1u8;
            let mut den = 1u8;
            for j in 0..k {
                if i == j {
                    continue;
                }
                let xj = shares[j].index;
                num = gf_mul(num, xj);
                den = gf_mul(den, xi ^ xj);
            }
            val ^= gf_mul(yi, gf_mul(num, gf_inv(den)));
        }
        secret[byte_pos] = val;
    }
    secret
}


fn verify_cert(cert: &ModerationCert, state: &RegistryState) {
    let mut valid = 0u32;
    for vote in &cert.votes {
        assert!(state.moderators.contains(&vote.moderator_pubkey), "unknown moderator");
        let msg = vote_message(&vote.forum_id, &vote.content_hash, &vote.member_tag, &vote.strike_reason);
        let vk  = VerifyingKey::from_bytes(&vote.moderator_pubkey).expect("invalid pubkey");
        let sig_bytes: [u8; 64] = vote.signature.as_slice().try_into().expect("sig must be 64 bytes");
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(&msg, &sig).expect("invalid moderator signature");
        valid += 1;
    }
    assert!(valid >= state.threshold_n, "cert threshold not met");
}

fn process(state: &mut RegistryState, instruction: Instruction) {
    match instruction {
        Instruction::Initialize { forum_id, moderators, threshold_n, threshold_k, stake_required, initial_root } => {
            assert!(state.moderators.is_empty(), "already initialised");
            state.forum_id       = forum_id;
            state.moderators     = moderators;
            state.threshold_n    = threshold_n;
            state.threshold_k    = threshold_k;
            state.stake_required = stake_required;
            state.merkle_root    = initial_root;
        }

        Instruction::Register { commitment, member_tag, stake, shamir_commitments } => {
            assert!(!state.moderators.is_empty(), "not initialised");
            assert!(stake >= state.stake_required, "insufficient stake");
            assert!(!state.revocation_set.contains(&commitment), "commitment revoked");
            assert!(!state.members.iter().any(|m| m.member_tag == member_tag), "already registered");
            assert!(!state.members.iter().any(|m| m.commitment == commitment), "commitment conflict");
            state.members.push(MemberRecord {
                commitment,
                member_tag,
                stake,
                strike_count: 0,
                revoked: false,
                shamir_commitments: shamir_commitments.iter().map(|c| c.to_vec()).collect(),
            });
        }

        Instruction::UpdateMerkleRoot { new_root } => {
            state.merkle_root = new_root;
        }

        Instruction::SubmitModerationCert { cert } => {
            verify_cert(&cert, state);
            if let Some(m) = state.members.iter_mut().find(|m| m.member_tag == cert.member_tag) {
                m.strike_count += 1;
            }
            state.pending_certs.push(cert);
        }

        Instruction::Slash { slash } => {
            assert!(slash.certs.len() as u32 >= state.threshold_k, "slash threshold not met");
            for cert in &slash.certs {
                verify_cert(cert, state);
            }
            let commitment = {
                let member = state.members.iter()
                    .find(|m| m.member_tag == slash.member_tag)
                    .expect("member not found");
                for s in &slash.shares {
                    let stored: [u8; 32] = member.shamir_commitments[(s.index as usize) - 1]
                        .as_slice()
                        .try_into()
                        .expect("share commitment must be 32 bytes");
                    assert!(verify_share(s, &stored), "bad shamir share");
                }
                let id_secret = shamir_combine(&slash.shares);
                assert!(derive_commitment(&id_secret) == member.commitment, "reconstruction mismatch");
                member.commitment
            };
            if let Some(m) = state.members.iter_mut().find(|m| m.member_tag == slash.member_tag) {
                m.revoked = true;
            }
            state.revocation_set.push(commitment);
        }

        Instruction::RejectNullifier { nullifier } => {
            if !state.spent_nullifiers.contains(&nullifier) {
                state.spent_nullifiers.push(nullifier);
            }
        }

        Instruction::VerifyPost { proof } => {
            assert!(proof.merkle_root == state.merkle_root, "merkle root mismatch");
            assert!(!state.spent_nullifiers.contains(&proof.post_nullifier), "nullifier spent");
            assert!(
                !state.members.iter().any(|m| m.member_tag == proof.member_tag && m.revoked),
                "member revoked"
            );
        }
    }
}


fn main() {
    let (ProgramInput { pre_states, instruction }, instruction_data) =
        read_nssa_inputs::<Instruction>();

    let [state_acct] = pre_states
        .try_into()
        .expect("forum registry requires exactly one account");

    let uninitialized = state_acct.account.program_owner == DEFAULT_PROGRAM_ID;

    let mut state: RegistryState = if uninitialized {
        RegistryState::default()
    } else {
        borsh::from_slice(state_acct.account.data.as_ref()).expect("decode registry state")
    };

    process(&mut state, instruction);

    let encoded = borsh::to_vec(&state).expect("encode registry state");
    let mut post_account = state_acct.account.clone();
    post_account.data = encoded.try_into().expect("registry state fits in 100 KiB");

    let post_state = if uninitialized {
        AccountPostState::new_claimed(post_account)
    } else {
        AccountPostState::new(post_account)
    };

    ProgramOutput::new(instruction_data, vec![state_acct], vec![post_state]).write();
}
