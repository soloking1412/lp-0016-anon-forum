use ed25519_dalek::SigningKey;
use forum_anon_moderation::{
    identity::{split_identity, MemberIdentity},
    moderation::{aggregate_votes, draft_vote},
    slash::{build_slash, reconstruct_and_verify},
};
use forum_anon_registry::{process, Instruction};
use forum_anon_types::{RegistryState, ShamirShare};
use rand::rngs::OsRng;

fn setup_forum(threshold_k: u32, threshold_n: u32, mod_keys: &[SigningKey]) -> RegistryState {
    let mut state = RegistryState::default();
    let moderators: Vec<[u8; 32]> = mod_keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    process(
        &mut state,
        Instruction::Initialize {
            forum_id: [0u8; 32],
            moderators,
            threshold_n,
            threshold_k,
            stake_required: 0,
            initial_root: [0u8; 32],
        },
    )
    .unwrap();
    state
}

#[test]
fn slash_reconstructs_and_revokes() {
    let mod_keys: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let mut state = setup_forum(3, 2, &mod_keys);

    let identity = MemberIdentity::generate(&mut OsRng);
    let (shares, commits) = split_identity(&identity, 3, 5, &mut OsRng).unwrap();

    // Register member.
    process(
        &mut state,
        Instruction::Register {
            commitment: identity.commitment(),
            member_tag: identity.member_tag(&[0u8; 32]),
            stake: 0,
            shamir_commitments: commits.clone(),
        },
    )
    .unwrap();

    let forum_id = [0u8; 32];
    let member_tag = identity.member_tag(&forum_id);
    let content_hashes = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];

    // Generate K=3 certs.
    let mut certs = Vec::new();
    for ch in &content_hashes {
        let votes: Vec<_> = mod_keys[0..2].iter().map(|k| {
            draft_vote(forum_id, *ch, member_tag, "offensive".to_string(), k).unwrap()
        }).collect();
        let cert = aggregate_votes(votes, 2).unwrap();
        process(&mut state, Instruction::SubmitModerationCert { cert: cert.clone() }).unwrap();
        certs.push(cert);
    }

    // Build slash with K=3 shares.
    let slash_shares: Vec<ShamirShare> = shares[0..3].to_vec();
    let slash = build_slash(forum_id, member_tag, certs, slash_shares);

    process(&mut state, Instruction::Slash { slash }).unwrap();

    // Commitment should now be revoked.
    assert!(state.revocation_set.contains(&identity.commitment()));
    assert!(state.members.iter().any(|m| m.revoked));
}

#[test]
fn insufficient_certs_fails_slash() {
    let mod_keys: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let mut state = setup_forum(3, 2, &mod_keys);

    let identity = MemberIdentity::generate(&mut OsRng);
    let (shares, commits) = split_identity(&identity, 3, 5, &mut OsRng).unwrap();
    let forum_id = [0u8; 32];
    let member_tag = identity.member_tag(&forum_id);

    process(
        &mut state,
        Instruction::Register {
            commitment: identity.commitment(),
            member_tag,
            stake: 0,
            shamir_commitments: commits,
        },
    )
    .unwrap();

    // Only 2 certs but K=3 required.
    let mut certs = Vec::new();
    for ch in &[[0x01u8; 32], [0x02u8; 32]] {
        let votes: Vec<_> = mod_keys[0..2].iter().map(|k| {
            draft_vote(forum_id, *ch, member_tag, "spam".to_string(), k).unwrap()
        }).collect();
        certs.push(aggregate_votes(votes, 2).unwrap());
    }

    let slash = build_slash(forum_id, member_tag, certs, shares[0..3].to_vec());
    assert!(process(&mut state, Instruction::Slash { slash }).is_err());
}

#[test]
fn wrong_shares_fail_slash() {
    let mod_keys: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let mut state = setup_forum(3, 2, &mod_keys);

    let identity = MemberIdentity::generate(&mut OsRng);
    let (_, commits) = split_identity(&identity, 3, 5, &mut OsRng).unwrap();
    let forum_id = [0u8; 32];
    let member_tag = identity.member_tag(&forum_id);

    process(
        &mut state,
        Instruction::Register {
            commitment: identity.commitment(),
            member_tag,
            stake: 0,
            shamir_commitments: commits,
        },
    )
    .unwrap();

    // Generate a different identity's shares — wrong shares.
    let other_identity = MemberIdentity::generate(&mut OsRng);
    let (wrong_shares, _) = split_identity(&other_identity, 3, 5, &mut OsRng).unwrap();

    let mut certs = Vec::new();
    for ch in &[[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]] {
        let votes: Vec<_> = mod_keys[0..2].iter().map(|k| {
            draft_vote(forum_id, *ch, member_tag, "spam".to_string(), k).unwrap()
        }).collect();
        certs.push(aggregate_votes(votes, 2).unwrap());
    }

    let slash = build_slash(forum_id, member_tag, certs, wrong_shares[0..3].to_vec());
    assert!(process(&mut state, Instruction::Slash { slash }).is_err());
}

#[test]
fn off_chain_verify_slash_roundtrip() {
    let identity = MemberIdentity::generate(&mut OsRng);
    let commitment = identity.commitment();
    let (shares, _) = split_identity(&identity, 3, 5, &mut OsRng).unwrap();

    let id_secret = reconstruct_and_verify(&shares[0..3], &commitment).unwrap();
    assert_eq!(id_secret, identity.id_secret);
}
