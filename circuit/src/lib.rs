use anyhow::{anyhow, Context, Result};
use borsh::BorshDeserialize;
use forum_anon_types::{MembershipProof, MemberWitness, PostPublicInputs};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

// Embed the guest ELF at compile time.
include!(concat!(env!("OUT_DIR"), "/methods.rs"));

/// Generate a Risc0 receipt proving membership and computing nullifiers.
///
/// The receipt's journal contains a borsh-encoded `MembershipProof`.
/// In RISC0_DEV_MODE the proof is a mock; full proofs require a GPU prover.
pub fn prove_membership(
    witness: &MemberWitness,
    public: &PostPublicInputs,
) -> Result<Receipt> {
    // env::write() uses risc0's serde-based encoding; env::read() on the
    // guest side decodes with the same scheme.  We must NOT use write_slice
    // here because that writes raw bytes that the guest would need to read
    // with env::read_slice(), not env::read().
    let env = ExecutorEnv::builder()
        .write(witness)
        .context("write witness")?
        .write(public)
        .context("write public inputs")?
        .build()
        .context("build executor env")?;

    let prover  = default_prover();
    let receipt = prover
        .prove(env, FORUM_ANON_GUEST_ELF)
        .context("prove membership")?
        .receipt;
    Ok(receipt)
}

/// Verify a receipt and decode the journal as `MembershipProof`.
pub fn verify_membership(receipt: &Receipt) -> Result<MembershipProof> {
    receipt
        .verify(FORUM_ANON_GUEST_ID)
        .map_err(|e| anyhow!("receipt verification failed: {e}"))?;

    let proof = MembershipProof::try_from_slice(&receipt.journal.bytes)
        .context("decode membership proof journal")?;
    Ok(proof)
}
