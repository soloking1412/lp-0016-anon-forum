use anyhow::{Context, Result};
use forum_anon_shamir::combine;
use forum_anon_types::{derive_commitment, ModerationCert, ShamirShare, SlashData};

use crate::identity::share_to_raw;

pub fn build_slash(
    forum_id: [u8; 32],
    member_tag: [u8; 32],
    certs: Vec<ModerationCert>,
    shares: Vec<ShamirShare>,
) -> SlashData {
    SlashData { forum_id, member_tag, certs, shares }
}

pub fn reconstruct_and_verify(shares: &[ShamirShare], commitment: &[u8; 32]) -> Result<[u8; 32]> {
    let raw: Vec<_> = shares.iter().map(share_to_raw).collect();
    let id_secret = combine(&raw, raw.len() as u8).context("shamir reconstruction failed")?;
    anyhow::ensure!(
        &derive_commitment(&id_secret) == commitment,
        "reconstructed id_secret does not match commitment"
    );
    Ok(id_secret)
}
