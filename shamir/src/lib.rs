use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub index: u8,
    pub value: [u8; 32],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShamirError {
    #[error("threshold must be ≥ 2 and ≤ total")]
    InvalidThreshold,
    #[error("total participants must be ≤ 254")]
    TooManyParticipants,
    #[error("need at least {0} shares to reconstruct")]
    InsufficientShares(u8),
    #[error("duplicate share index {0}")]
    DuplicateIndex(u8),
    #[error("share index 0 is not allowed")]
    ZeroIndex,
}

#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

#[inline]
fn gf_inv(a: u8) -> u8 {
    assert!(a != 0, "GF(256) inverse of zero");
    let a2   = gf_mul(a, a);
    let a4   = gf_mul(a2, a2);
    let a8   = gf_mul(a4, a4);
    let a16  = gf_mul(a8, a8);
    let a32  = gf_mul(a16, a16);
    let a64  = gf_mul(a32, a32);
    let a128 = gf_mul(a64, a64);
    gf_mul(gf_mul(gf_mul(gf_mul(gf_mul(gf_mul(a128, a64), a32), a16), a8), a4), a2)
}

fn poly_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = gf_add(gf_mul(result, x), c);
    }
    result
}

pub fn split(
    secret: &[u8; 32],
    threshold: u8,
    total: u8,
    rng: &mut impl RngCore,
) -> Result<(Vec<Share>, Vec<[u8; 32]>), ShamirError> {
    if threshold < 2 || threshold > total {
        return Err(ShamirError::InvalidThreshold);
    }
    if total as usize > 254 {
        return Err(ShamirError::TooManyParticipants);
    }

    let k = threshold as usize;
    let n = total as usize;

    let mut polys: Vec<Vec<u8>> = Vec::with_capacity(32);
    for &s in secret.iter() {
        let mut coeffs = vec![0u8; k];
        coeffs[0] = s;
        rng.fill_bytes(&mut coeffs[1..]);
        polys.push(coeffs);
    }

    let mut shares: Vec<Share> = Vec::with_capacity(n);
    for i in 1..=(n as u8) {
        let mut value = [0u8; 32];
        for (byte_pos, poly) in polys.iter().enumerate() {
            value[byte_pos] = poly_eval(poly, i);
        }
        shares.push(Share { index: i, value });
    }

    let commitments: Vec<[u8; 32]> = shares.iter().map(commit_share).collect();
    Ok((shares, commitments))
}

pub fn combine(shares: &[Share], threshold: u8) -> Result<[u8; 32], ShamirError> {
    if (shares.len() as u8) < threshold {
        return Err(ShamirError::InsufficientShares(threshold));
    }
    for s in shares {
        if s.index == 0 {
            return Err(ShamirError::ZeroIndex);
        }
    }
    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if !seen.insert(s.index) {
            return Err(ShamirError::DuplicateIndex(s.index));
        }
    }

    let work = &shares[..threshold as usize];
    let xs: Vec<u8> = work.iter().map(|s| s.index).collect();

    let mut secret = [0u8; 32];
    for (byte_pos, out) in secret.iter_mut().enumerate() {
        let ys: Vec<u8> = work.iter().map(|s| s.value[byte_pos]).collect();
        *out = lagrange_at_zero(&xs, &ys);
    }
    Ok(secret)
}

fn lagrange_at_zero(xs: &[u8], ys: &[u8]) -> u8 {
    let k = xs.len();
    let mut result = 0u8;
    for i in 0..k {
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..k {
            if i == j {
                continue;
            }
            num = gf_mul(num, xs[j]);
            den = gf_mul(den, gf_add(xs[i], xs[j]));
        }
        result = gf_add(result, gf_mul(ys[i], gf_mul(num, gf_inv(den))));
    }
    result
}

pub fn commit_share(share: &Share) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"forum/v1/share-commit:");
    h.update([share.index]);
    h.update(share.value);
    h.finalize().into()
}

pub fn verify_share(share: &Share, commitment: &[u8; 32]) -> bool {
    &commit_share(share) == commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    #[test]
    fn split_combine_roundtrip_2_of_3() {
        let secret = random_secret();
        let (shares, commitments) = split(&secret, 2, 3, &mut OsRng).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(commitments.len(), 3);

        assert_eq!(combine(&shares[0..2], 2).unwrap(), secret);
        assert_eq!(combine(&[shares[0].clone(), shares[2].clone()], 2).unwrap(), secret);
        assert_eq!(combine(&shares[1..3], 2).unwrap(), secret);
    }

    #[test]
    fn split_combine_roundtrip_3_of_5() {
        let secret = random_secret();
        let (shares, _) = split(&secret, 3, 5, &mut OsRng).unwrap();
        for i in 0..5 {
            for j in (i + 1)..5 {
                for k in (j + 1)..5 {
                    let result = combine(
                        &[shares[i].clone(), shares[j].clone(), shares[k].clone()],
                        3,
                    )
                    .unwrap();
                    assert_eq!(result, secret, "failed for shares {i},{j},{k}");
                }
            }
        }
    }

    #[test]
    fn insufficient_shares_returns_error() {
        let secret = random_secret();
        let (shares, _) = split(&secret, 3, 5, &mut OsRng).unwrap();
        assert_eq!(combine(&shares[0..2], 3).unwrap_err(), ShamirError::InsufficientShares(3));
    }

    #[test]
    fn one_share_does_not_reveal_secret() {
        let secret = random_secret();
        let (shares, _) = split(&secret, 3, 5, &mut OsRng).unwrap();
        assert!(matches!(combine(&shares[0..1], 3).unwrap_err(), ShamirError::InsufficientShares(3)));
    }

    #[test]
    fn commitment_verification_passes() {
        let secret = random_secret();
        let (shares, commitments) = split(&secret, 2, 3, &mut OsRng).unwrap();
        for (share, commitment) in shares.iter().zip(commitments.iter()) {
            assert!(verify_share(share, commitment));
        }
    }

    #[test]
    fn tampered_share_fails_verification() {
        let secret = random_secret();
        let (mut shares, commitments) = split(&secret, 2, 3, &mut OsRng).unwrap();
        shares[0].value[0] ^= 0xff;
        assert!(!verify_share(&shares[0], &commitments[0]));
    }

    #[test]
    fn invalid_threshold_rejected() {
        let secret = random_secret();
        assert!(split(&secret, 0, 3, &mut OsRng).is_err());
        assert!(split(&secret, 1, 3, &mut OsRng).is_err());
        assert!(split(&secret, 4, 3, &mut OsRng).is_err());
    }

    #[test]
    fn duplicate_index_rejected() {
        let secret = random_secret();
        let (shares, _) = split(&secret, 2, 3, &mut OsRng).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert_eq!(combine(&dup, 2).unwrap_err(), ShamirError::DuplicateIndex(1));
    }

    #[test]
    fn wrong_shares_do_not_reconstruct_secret() {
        let secret1 = random_secret();
        let secret2 = random_secret();
        let (shares1, _) = split(&secret1, 2, 3, &mut OsRng).unwrap();
        let (shares2, _) = split(&secret2, 2, 3, &mut OsRng).unwrap();
        let mixed = vec![shares1[0].clone(), shares2[1].clone()];
        let result = combine(&mixed, 2).unwrap();
        assert_ne!(result, secret1);
        assert_ne!(result, secret2);
    }
}
