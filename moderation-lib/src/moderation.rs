use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use forum_anon_types::{ModerationCert, ModeratorVote};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModerationError {
    #[error("need {need} votes, have {have}")]
    InsufficientVotes { need: u32, have: u32 },
    #[error("vote {index} has invalid signature")]
    InvalidSignature { index: usize },
    #[error("vote {index} is from an unknown moderator")]
    UnknownModerator { index: usize },
    #[error("votes cover different targets — cannot aggregate")]
    Mismatch,
}

pub fn vote_message(forum_id: &[u8; 32], content_hash: &[u8; 32], member_tag: &[u8; 32], reason: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"forum/v1/vote:");
    h.update(forum_id);
    h.update(content_hash);
    h.update(member_tag);
    h.update(reason.as_bytes());
    h.finalize().into()
}

pub fn draft_vote(
    forum_id: [u8; 32],
    content_hash: [u8; 32],
    member_tag: [u8; 32],
    strike_reason: String,
    signing_key: &SigningKey,
) -> Result<ModeratorVote> {
    let msg = vote_message(&forum_id, &content_hash, &member_tag, &strike_reason);
    let signature: Signature = signing_key.sign(&msg);
    Ok(ModeratorVote {
        forum_id,
        content_hash,
        member_tag,
        strike_reason,
        moderator_pubkey: signing_key.verifying_key().to_bytes(),
        signature: signature.to_bytes(),
    })
}

pub fn aggregate_votes(votes: Vec<ModeratorVote>, threshold_n: u32) -> Result<ModerationCert, ModerationError> {
    if votes.is_empty() || votes.len() < threshold_n as usize {
        return Err(ModerationError::InsufficientVotes { need: threshold_n, have: votes.len() as u32 });
    }
    let first = &votes[0];
    for v in votes.iter().skip(1) {
        if v.forum_id != first.forum_id || v.content_hash != first.content_hash || v.member_tag != first.member_tag {
            return Err(ModerationError::Mismatch);
        }
    }
    Ok(ModerationCert {
        forum_id:     first.forum_id,
        content_hash: first.content_hash,
        member_tag:   first.member_tag,
        votes,
    })
}

pub fn verify_cert(
    cert: &ModerationCert,
    moderator_pubkeys: &[[u8; 32]],
    threshold_n: u32,
) -> Result<(), ModerationError> {
    let mut valid = 0u32;
    for (i, vote) in cert.votes.iter().enumerate() {
        if !moderator_pubkeys.contains(&vote.moderator_pubkey) {
            return Err(ModerationError::UnknownModerator { index: i });
        }
        let msg = vote_message(&vote.forum_id, &vote.content_hash, &vote.member_tag, &vote.strike_reason);
        let vk  = VerifyingKey::from_bytes(&vote.moderator_pubkey)
            .map_err(|_| ModerationError::InvalidSignature { index: i })?;
        let sig = Signature::from_bytes(&vote.signature);
        vk.verify_strict(&msg, &sig)
            .map_err(|_| ModerationError::InvalidSignature { index: i })?;
        valid += 1;
    }
    if valid < threshold_n {
        return Err(ModerationError::InsufficientVotes { need: threshold_n, have: valid });
    }
    Ok(())
}
