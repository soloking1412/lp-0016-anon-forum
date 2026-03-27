use anyhow::{Context, Result};
use forum_anon_circuit::{prove_membership, verify_membership};
use forum_anon_types::{MembershipProof, MemberWitness, PostPublicInputs};
use risc0_zkvm::Receipt;

use crate::identity::MemberIdentity;

pub fn prove_post(
    identity: &MemberIdentity,
    merkle_proof: forum_anon_types::MerkleProof,
    merkle_root: [u8; 32],
    forum_id: [u8; 32],
    ext_nullifier: [u8; 32],
    presenter_pubkey: [u8; 32],
) -> Result<Receipt> {
    let witness = MemberWitness { id_secret: identity.id_secret, merkle_proof };
    let public  = PostPublicInputs { merkle_root, forum_id, ext_nullifier, presenter_pubkey };
    prove_membership(&witness, &public).context("membership proof failed")
}

pub fn verify_post(receipt: &Receipt, expected_forum_id: &[u8; 32], expected_root: &[u8; 32]) -> Result<MembershipProof> {
    let proof = verify_membership(receipt).context("invalid membership receipt")?;
    anyhow::ensure!(
        &proof.forum_id == expected_forum_id,
        "forum_id mismatch: expected {}, got {}",
        hex::encode(expected_forum_id),
        hex::encode(proof.forum_id)
    );
    anyhow::ensure!(
        &proof.merkle_root == expected_root,
        "merkle_root mismatch: expected {}, got {}",
        hex::encode(expected_root),
        hex::encode(proof.merkle_root)
    );
    Ok(proof)
}
