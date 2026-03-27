use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, VerifyingKey};
use forum_anon_shamir::{combine, verify_share, Share};
use forum_anon_types::{
    derive_commitment, ModerationCert, MemberRecord, MembershipProof,
    RegistryState, ShamirShare, SlashData,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("forum already initialised")]
    AlreadyInitialised,
    #[error("member_tag already registered")]
    AlreadyRegistered,
    #[error("commitment already registered")]
    CommitmentConflict,
    #[error("commitment is revoked")]
    Revoked,
    #[error("insufficient stake: need {required}, got {provided}")]
    InsufficientStake { required: u64, provided: u64 },
    #[error("invalid moderator signature at index {index}")]
    BadModeratorSignature { index: usize },
    #[error("cert has {got} valid votes, need {need}")]
    CertThreshold { need: u32, got: u32 },
    #[error("slash has {got} certs, need {need}")]
    SlashThreshold { need: u32, got: u32 },
    #[error("shamir share {index} fails commitment check")]
    BadShamirShare { index: usize },
    #[error("shamir reconstruction did not match commitment")]
    ReconstructionMismatch,
    #[error("member not found")]
    MemberNotFound,
    #[error("duplicate cert in slash batch")]
    DuplicateCert,
    #[error("unknown moderator")]
    UnknownModerator,
    #[error("forum not initialised")]
    NotInitialised,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
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
    UpdateMerkleRoot {
        new_root: [u8; 32],
    },
    SubmitModerationCert {
        cert: ModerationCert,
    },
    Slash {
        slash: SlashData,
    },
    RejectNullifier {
        nullifier: [u8; 32],
    },
    VerifyPost {
        proof: MembershipProof,
    },
}

pub fn process(state: &mut RegistryState, instruction: Instruction) -> Result<(), RegistryError> {
    match instruction {
        Instruction::Initialize {
            forum_id, moderators, threshold_n, threshold_k, stake_required, initial_root,
        } => {
            if !state.moderators.is_empty() {
                return Err(RegistryError::AlreadyInitialised);
            }
            state.forum_id       = forum_id;
            state.moderators     = moderators;
            state.threshold_n    = threshold_n;
            state.threshold_k    = threshold_k;
            state.stake_required = stake_required;
            state.merkle_root    = initial_root;
        }

        Instruction::Register { commitment, member_tag, stake, shamir_commitments } => {
            if state.moderators.is_empty() {
                return Err(RegistryError::NotInitialised);
            }
            if stake < state.stake_required {
                return Err(RegistryError::InsufficientStake {
                    required: state.stake_required,
                    provided: stake,
                });
            }
            if state.revocation_set.contains(&commitment) {
                return Err(RegistryError::Revoked);
            }
            if state.members.iter().any(|m| m.member_tag == member_tag) {
                return Err(RegistryError::AlreadyRegistered);
            }
            if state.members.iter().any(|m| m.commitment == commitment) {
                return Err(RegistryError::CommitmentConflict);
            }
            state.members.push(MemberRecord {
                commitment,
                member_tag,
                stake,
                strike_count: 0,
                revoked: false,
                shamir_commitments: shamir_commitments.into_iter().map(|c| c.to_vec()).collect(),
            });
        }

        Instruction::UpdateMerkleRoot { new_root } => {
            state.merkle_root = new_root;
        }

        Instruction::SubmitModerationCert { cert } => {
            verify_cert(&cert, state)?;
            if let Some(member) = state.members.iter_mut().find(|m| m.member_tag == cert.member_tag) {
                member.strike_count += 1;
            }
            state.pending_certs.push(cert);
        }

        Instruction::Slash { slash } => {
            verify_slash(&slash, state)?;
            execute_slash(&slash, state)?;
        }

        Instruction::RejectNullifier { nullifier } => {
            if !state.spent_nullifiers.contains(&nullifier) {
                state.spent_nullifiers.push(nullifier);
            }
        }

        Instruction::VerifyPost { proof } => {
            if proof.merkle_root != state.merkle_root {
                return Err(RegistryError::MemberNotFound);
            }
            if state.spent_nullifiers.contains(&proof.post_nullifier) {
                return Err(RegistryError::Revoked);
            }
            if state.members.iter().any(|m| m.member_tag == proof.member_tag && m.revoked) {
                return Err(RegistryError::Revoked);
            }
        }
    }
    Ok(())
}

fn vote_message(forum_id: &[u8; 32], content_hash: &[u8; 32], member_tag: &[u8; 32], reason: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"forum/v1/vote:");
    h.update(forum_id);
    h.update(content_hash);
    h.update(member_tag);
    h.update(reason.as_bytes());
    h.finalize().into()
}

fn verify_cert(cert: &ModerationCert, state: &RegistryState) -> Result<(), RegistryError> {
    let mut valid = 0u32;
    for (i, vote) in cert.votes.iter().enumerate() {
        if !state.moderators.contains(&vote.moderator_pubkey) {
            return Err(RegistryError::UnknownModerator);
        }
        let msg = vote_message(&vote.forum_id, &vote.content_hash, &vote.member_tag, &vote.strike_reason);
        let vk  = VerifyingKey::from_bytes(&vote.moderator_pubkey)
            .map_err(|_| RegistryError::BadModeratorSignature { index: i })?;
        let sig = Signature::from_bytes(&vote.signature);
        vk.verify_strict(&msg, &sig)
            .map_err(|_| RegistryError::BadModeratorSignature { index: i })?;
        valid += 1;
    }
    if valid < state.threshold_n {
        return Err(RegistryError::CertThreshold { need: state.threshold_n, got: valid });
    }
    Ok(())
}

fn verify_slash(slash: &SlashData, state: &RegistryState) -> Result<(), RegistryError> {
    let cert_count = slash.certs.len() as u32;
    if cert_count < state.threshold_k {
        return Err(RegistryError::SlashThreshold { need: state.threshold_k, got: cert_count });
    }

    let mut hashes: Vec<[u8; 32]> = slash.certs.iter().map(|c| c.content_hash).collect();
    hashes.sort_unstable();
    hashes.dedup();
    if hashes.len() < cert_count as usize {
        return Err(RegistryError::DuplicateCert);
    }

    for cert in &slash.certs {
        verify_cert(cert, state)?;
    }

    let member = state.members.iter()
        .find(|m| m.member_tag == slash.member_tag)
        .ok_or(RegistryError::MemberNotFound)?;

    for (i, s) in slash.shares.iter().enumerate() {
        if s.index == 0 || s.index as usize > member.shamir_commitments.len() {
            return Err(RegistryError::BadShamirShare { index: i });
        }
        let stored: [u8; 32] = member.shamir_commitments[(s.index - 1) as usize]
            .as_slice()
            .try_into()
            .map_err(|_| RegistryError::BadShamirShare { index: i })?;
        if !verify_share(&shamir_share_from(s), &stored) {
            return Err(RegistryError::BadShamirShare { index: i });
        }
    }
    Ok(())
}

fn execute_slash(slash: &SlashData, state: &mut RegistryState) -> Result<(), RegistryError> {
    let member_idx = state.members.iter()
        .position(|m| m.member_tag == slash.member_tag)
        .ok_or(RegistryError::MemberNotFound)?;

    let shares: Vec<Share> = slash.shares.iter().map(shamir_share_from).collect();
    let id_secret = combine(&shares, slash.shares.len() as u8)
        .map_err(|_| RegistryError::ReconstructionMismatch)?;

    if derive_commitment(&id_secret) != state.members[member_idx].commitment {
        return Err(RegistryError::ReconstructionMismatch);
    }

    let commitment = state.members[member_idx].commitment;
    state.members[member_idx].revoked = true;
    state.revocation_set.push(commitment);
    Ok(())
}

fn shamir_share_from(s: &ShamirShare) -> Share {
    let mut value = [0u8; 32];
    let len = s.value.len().min(32);
    value[..len].copy_from_slice(&s.value[..len]);
    Share { index: s.index, value }
}
