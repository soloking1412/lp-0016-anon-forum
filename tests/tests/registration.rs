use forum_anon_moderation::identity::{split_identity, MemberIdentity};
use forum_anon_types::derive_commitment;
use rand::rngs::OsRng;

#[test]
fn identity_commitment_deterministic() {
    let id_secret = [0x42u8; 32];
    let a = MemberIdentity::from_secret(id_secret);
    let b = MemberIdentity::from_secret(id_secret);
    assert_eq!(a.commitment(), b.commitment());
}

#[test]
fn member_tag_differs_per_forum() {
    let id = MemberIdentity::generate(&mut OsRng);
    let forum1 = [1u8; 32];
    let forum2 = [2u8; 32];
    assert_ne!(id.member_tag(&forum1), id.member_tag(&forum2));
}

#[test]
fn commitment_does_not_reveal_member_tag() {
    let id = MemberIdentity::generate(&mut OsRng);
    let forum = [0u8; 32];
    // commitment and member_tag must differ (trivial but guards against identity bugs)
    assert_ne!(id.commitment(), id.member_tag(&forum));
}

#[test]
fn shamir_split_and_verify_shares() {
    let id = MemberIdentity::generate(&mut OsRng);
    let (shares, commits) = split_identity(&id, 3, 5, &mut OsRng).unwrap();
    assert_eq!(shares.len(), 5);
    assert_eq!(commits.len(), 5);

    for (s, c) in shares.iter().zip(commits.iter()) {
        assert!(forum_anon_moderation::identity::verify_share(s, c));
    }
}

#[test]
fn shamir_reconstruction_matches_commitment() {
    use forum_anon_moderation::slash::reconstruct_and_verify;
    let id = MemberIdentity::generate(&mut OsRng);
    let commitment = id.commitment();
    let (shares, _) = split_identity(&id, 3, 5, &mut OsRng).unwrap();
    let reconstructed = reconstruct_and_verify(&shares[0..3], &commitment).unwrap();
    assert_eq!(reconstructed, id.id_secret);
}
