use anyhow::{Context, Result};
use forum_anon_shamir::{commit_share, split, Share};
use forum_anon_types::{derive_commitment, derive_member_tag, ShamirShare};
use rand::RngCore;

pub struct MemberIdentity {
    pub id_secret: [u8; 32],
}

impl MemberIdentity {
    pub fn generate(rng: &mut impl RngCore) -> Self {
        let mut id_secret = [0u8; 32];
        rng.fill_bytes(&mut id_secret);
        Self { id_secret }
    }

    pub fn from_secret(id_secret: [u8; 32]) -> Self {
        Self { id_secret }
    }

    pub fn commitment(&self) -> [u8; 32] {
        derive_commitment(&self.id_secret)
    }

    pub fn member_tag(&self, forum_id: &[u8; 32]) -> [u8; 32] {
        derive_member_tag(&self.id_secret, forum_id)
    }
}

pub fn split_identity(
    identity: &MemberIdentity,
    threshold: u8,
    total: u8,
    rng: &mut impl RngCore,
) -> Result<(Vec<ShamirShare>, Vec<[u8; 32]>)> {
    let (raw_shares, commitments) = split(&identity.id_secret, threshold, total, rng)
        .context("shamir split failed")?;

    let shares = raw_shares.iter().map(|s| ShamirShare {
        index: s.index,
        value: s.value.to_vec(),
    }).collect();

    Ok((shares, commitments))
}

pub fn verify_share(share: &ShamirShare, commitment: &[u8; 32]) -> bool {
    commit_share(&share_to_raw(share)) == *commitment
}

pub(crate) fn share_to_raw(s: &ShamirShare) -> Share {
    let mut value = [0u8; 32];
    let len = s.value.len().min(32);
    value[..len].copy_from_slice(&s.value[..len]);
    Share { index: s.index, value }
}
