use forum_anon_shamir::{combine, split, verify_share};
use rand::rngs::OsRng;

fn random_secret() -> [u8; 32] {
    use rand::RngCore;
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

#[test]
fn roundtrip_2_of_3() {
    let secret = random_secret();
    let (shares, commits) = split(&secret, 2, 3, &mut OsRng).unwrap();
    for (s, c) in shares.iter().zip(commits.iter()) {
        assert!(verify_share(s, c));
    }
    assert_eq!(combine(&shares[0..2], 2).unwrap(), secret);
    assert_eq!(combine(&[shares[0].clone(), shares[2].clone()], 2).unwrap(), secret);
}

#[test]
fn roundtrip_3_of_5() {
    let secret = random_secret();
    let (shares, _) = split(&secret, 3, 5, &mut OsRng).unwrap();
    for i in 0..5 {
        for j in (i + 1)..5 {
            for k in (j + 1)..5 {
                let r = combine(&[shares[i].clone(), shares[j].clone(), shares[k].clone()], 3).unwrap();
                assert_eq!(r, secret);
            }
        }
    }
}

#[test]
fn insufficient_shares_fails() {
    let secret = random_secret();
    let (shares, _) = split(&secret, 3, 5, &mut OsRng).unwrap();
    assert!(combine(&shares[0..2], 3).is_err());
}

#[test]
fn tampered_share_fails_verification() {
    let secret = random_secret();
    let (mut shares, commits) = split(&secret, 2, 3, &mut OsRng).unwrap();
    shares[0].value[0] ^= 0xff;
    assert!(!verify_share(&shares[0], &commits[0]));
}
