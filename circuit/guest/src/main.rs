#![no_main]

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

risc0_zkvm::guest::entry!(main);

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
struct MerkleProof {
    index:    u64,
    siblings: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
struct MemberWitness {
    id_secret:    [u8; 32],
    merkle_proof: MerkleProof,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
struct PostPublicInputs {
    merkle_root:      [u8; 32],
    forum_id:         [u8; 32],
    ext_nullifier:    [u8; 32],
    presenter_pubkey: [u8; 32],
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
struct MembershipProof {
    merkle_root:      [u8; 32],
    forum_id:         [u8; 32],
    member_tag:       [u8; 32],
    post_nullifier:   [u8; 32],
    ext_nullifier:    [u8; 32],
    presenter_pubkey: [u8; 32],
}

fn sha256_chain(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256_chain(&[left, right])
}

fn verify_merkle_path(commitment: &[u8; 32], proof: &MerkleProof, root: &[u8; 32]) -> bool {
    let mut current: [u8; 32] = Sha256::digest(commitment).into();
    let mut idx = proof.index;
    for sibling in &proof.siblings {
        current = if idx & 1 == 0 {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
        idx >>= 1;
    }
    &current == root
}

fn main() {
    let witness: MemberWitness    = env::read();
    let public:  PostPublicInputs = env::read();

    let commitment = sha256_chain(&[b"forum/v1/commitment:", &witness.id_secret]);

    assert!(
        verify_merkle_path(&commitment, &witness.merkle_proof, &public.merkle_root),
        "Merkle membership proof invalid"
    );

    let member_tag    = sha256_chain(&[b"forum/v1/member-tag:", &witness.id_secret, &public.forum_id]);
    let post_nullifier = sha256_chain(&[b"forum/v1/post-null:", &witness.id_secret, &public.ext_nullifier]);

    let proof = MembershipProof {
        merkle_root:      public.merkle_root,
        forum_id:         public.forum_id,
        member_tag,
        post_nullifier,
        ext_nullifier:    public.ext_nullifier,
        presenter_pubkey: public.presenter_pubkey,
    };
    env::commit_slice(&borsh::to_vec(&proof).expect("borsh encode"));
}
