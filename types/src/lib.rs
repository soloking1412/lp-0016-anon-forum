use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod serde_sig {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(sig))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let h = String::deserialize(d)?;
        let bytes = hex::decode(&h).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

pub const PREFIX_COMMITMENT: &[u8] = b"forum/v1/commitment:";
pub const PREFIX_MEMBER_TAG: &[u8] = b"forum/v1/member-tag:";
pub const PREFIX_POST_NULL:  &[u8] = b"forum/v1/post-null:";

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MerkleProof {
    pub index:    u64,
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MemberWitness {
    pub id_secret:    [u8; 32],
    pub merkle_proof: MerkleProof,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct PostPublicInputs {
    pub merkle_root:      [u8; 32],
    pub forum_id:         [u8; 32],
    pub ext_nullifier:    [u8; 32],
    pub presenter_pubkey: [u8; 32],
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MembershipProof {
    pub merkle_root:      [u8; 32],
    pub forum_id:         [u8; 32],
    pub member_tag:       [u8; 32],
    pub post_nullifier:   [u8; 32],
    pub ext_nullifier:    [u8; 32],
    pub presenter_pubkey: [u8; 32],
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ShamirShare {
    pub index: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ModeratorVote {
    pub forum_id:         [u8; 32],
    pub content_hash:     [u8; 32],
    pub member_tag:       [u8; 32],
    pub strike_reason:    String,
    pub moderator_pubkey: [u8; 32],
    #[serde(with = "serde_sig")]
    pub signature:        [u8; 64],
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ModerationCert {
    pub forum_id:     [u8; 32],
    pub content_hash: [u8; 32],
    pub member_tag:   [u8; 32],
    pub votes:        Vec<ModeratorVote>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SlashData {
    pub forum_id:   [u8; 32],
    pub member_tag: [u8; 32],
    pub certs:      Vec<ModerationCert>,
    pub shares:     Vec<ShamirShare>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct MemberRecord {
    pub commitment:         [u8; 32],
    pub member_tag:         [u8; 32],
    pub stake:              u64,
    pub strike_count:       u32,
    pub revoked:            bool,
    pub shamir_commitments: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize, Default)]
pub struct RegistryState {
    pub forum_id:         [u8; 32],
    pub merkle_root:      [u8; 32],
    pub moderators:       Vec<[u8; 32]>,
    pub threshold_n:      u32,
    pub threshold_k:      u32,
    pub stake_required:   u64,
    pub members:          Vec<MemberRecord>,
    pub revocation_set:   Vec<[u8; 32]>,
    pub pending_certs:    Vec<ModerationCert>,
    pub spent_nullifiers: Vec<[u8; 32]>,
}

pub fn derive_commitment(id_secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PREFIX_COMMITMENT);
    h.update(id_secret);
    h.finalize().into()
}

pub fn derive_member_tag(id_secret: &[u8; 32], forum_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PREFIX_MEMBER_TAG);
    h.update(id_secret);
    h.update(forum_id);
    h.finalize().into()
}

pub fn derive_post_nullifier(id_secret: &[u8; 32], ext_nullifier: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PREFIX_POST_NULL);
    h.update(id_secret);
    h.update(ext_nullifier);
    h.finalize().into()
}

pub fn hash_leaf(commitment: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(commitment).into()
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

pub fn build_merkle_tree(leaves: &[[u8; 32]]) -> (Vec<[u8; 32]>, [u8; 32]) {
    assert!(!leaves.is_empty() && leaves.len().is_power_of_two());
    let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();
    let mut level = leaf_hashes.clone();
    while level.len() > 1 {
        level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
    }
    (leaf_hashes, level[0])
}

pub fn make_merkle_proof(leaves: &[[u8; 32]], index: usize) -> (MerkleProof, [u8; 32]) {
    assert!(!leaves.is_empty() && leaves.len().is_power_of_two());
    let mut level: Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();

    let root = {
        let mut l = level.clone();
        while l.len() > 1 {
            l = l.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
        }
        l[0]
    };

    let mut siblings = Vec::new();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = if idx & 1 == 0 { idx + 1 } else { idx - 1 };
        siblings.push(level[sibling]);
        level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
        idx >>= 1;
    }
    (MerkleProof { index: index as u64, siblings }, root)
}
