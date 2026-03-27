use ed25519_dalek::SigningKey;
use forum_anon_circuit::{prove_membership, verify_membership};
use forum_anon_moderation::{
    identity::{split_identity, MemberIdentity},
    moderation::{aggregate_votes, draft_vote},
    slash::{build_slash, reconstruct_and_verify},
};
use forum_anon_registry::{process, Instruction};
use forum_anon_types::{make_merkle_proof, MemberWitness, PostPublicInputs, RegistryState};
use rand::rngs::OsRng;

fn setup_forum(mod_keys: &[SigningKey], threshold_n: u32, threshold_k: u32) -> RegistryState {
    let mut state = RegistryState::default();
    let moderators: Vec<[u8; 32]> = mod_keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    process(&mut state, Instruction::Initialize {
        forum_id: [0u8; 32],
        moderators,
        threshold_n,
        threshold_k,
        stake_required: 0,
        initial_root: [0u8; 32],
    }).unwrap();
    state
}

#[test]
fn full_lifecycle() {
    let mod_keys: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let mut state = setup_forum(&mod_keys, 2, 3);

    let identity = MemberIdentity::generate(&mut OsRng);
    let (shares, commits) = split_identity(&identity, 3, 5, &mut OsRng).unwrap();
    let forum_id   = [0u8; 32];
    let member_tag = identity.member_tag(&forum_id);

    process(&mut state, Instruction::Register {
        commitment: identity.commitment(),
        member_tag,
        stake: 0,
        shamir_commitments: commits,
    }).unwrap();

    let leaves = [identity.commitment(), [0u8; 32], [0u8; 32], [0u8; 32]];
    let (merkle_proof, root) = make_merkle_proof(&leaves, 0);
    process(&mut state, Instruction::UpdateMerkleRoot { new_root: root }).unwrap();

    let ext_nullifier = [0xEEu8; 32];
    let presenter_pk  = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let witness = MemberWitness { id_secret: identity.id_secret, merkle_proof };
    let public  = PostPublicInputs { merkle_root: root, forum_id, ext_nullifier, presenter_pubkey: presenter_pk };
    let receipt = prove_membership(&witness, &public).unwrap();
    let proof   = verify_membership(&receipt).unwrap();
    assert_eq!(proof.member_tag, member_tag);
    assert!(!state.revocation_set.contains(&identity.commitment()));

    let content_hashes = [[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
    for ch in &content_hashes {
        let votes: Vec<_> = mod_keys[0..2].iter().map(|k| {
            draft_vote(forum_id, *ch, member_tag, "violates rules".to_string(), k).unwrap()
        }).collect();
        let cert = aggregate_votes(votes, 2).unwrap();
        process(&mut state, Instruction::SubmitModerationCert { cert }).unwrap();
    }

    let member = state.members.iter().find(|m| m.member_tag == member_tag).unwrap();
    assert_eq!(member.strike_count, 3);

    let certs       = state.pending_certs.clone();
    let slash_shares = shares[0..3].to_vec();
    let slash = build_slash(forum_id, member_tag, certs, slash_shares);
    process(&mut state, Instruction::Slash { slash }).unwrap();

    assert!(state.revocation_set.contains(&identity.commitment()));
    assert!(state.members.iter().any(|m| m.member_tag == member_tag && m.revoked));

    let result = process(&mut state, Instruction::Register {
        commitment: identity.commitment(),
        member_tag,
        stake: 0,
        shamir_commitments: vec![],
    });
    assert!(result.is_err());

    let id_secret = reconstruct_and_verify(&shares[0..3], &identity.commitment()).unwrap();
    assert_eq!(id_secret, identity.id_secret);
}

#[test]
fn post_rejected_after_revocation() {
    let mod_keys: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let mut state = setup_forum(&mod_keys, 2, 3);

    let identity  = MemberIdentity::generate(&mut OsRng);
    let (shares, commits) = split_identity(&identity, 3, 5, &mut OsRng).unwrap();
    let forum_id  = [0u8; 32];
    let member_tag = identity.member_tag(&forum_id);

    process(&mut state, Instruction::Register {
        commitment: identity.commitment(),
        member_tag,
        stake: 0,
        shamir_commitments: commits,
    }).unwrap();

    let leaves = [identity.commitment(), [0u8; 32], [0u8; 32], [0u8; 32]];
    let (merkle_proof, root) = make_merkle_proof(&leaves, 0);
    process(&mut state, Instruction::UpdateMerkleRoot { new_root: root }).unwrap();

    // Prove a valid post before revocation.
    let ext_nullifier = [0xAAu8; 32];
    let presenter_pk  = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let witness = MemberWitness { id_secret: identity.id_secret, merkle_proof };
    let public  = PostPublicInputs { merkle_root: root, forum_id, ext_nullifier, presenter_pubkey: presenter_pk };
    let receipt = prove_membership(&witness, &public).unwrap();
    let proof   = verify_membership(&receipt).unwrap();

    // Pre-revocation: VerifyPost must succeed.
    assert!(process(&mut state, Instruction::VerifyPost { proof: proof.clone() }).is_ok());

    // Accumulate K=3 certs and slash.
    let content_hashes = [[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
    for ch in &content_hashes {
        let votes: Vec<_> = mod_keys[0..2].iter().map(|k| {
            draft_vote(forum_id, *ch, member_tag, "violation".to_string(), k).unwrap()
        }).collect();
        let cert = aggregate_votes(votes, 2).unwrap();
        process(&mut state, Instruction::SubmitModerationCert { cert }).unwrap();
    }
    let certs = state.pending_certs.clone();
    let slash = build_slash(forum_id, member_tag, certs, shares[0..3].to_vec());
    process(&mut state, Instruction::Slash { slash }).unwrap();

    assert!(state.revocation_set.contains(&identity.commitment()));

    // Post-revocation: the same proof (same member_tag) must now be rejected.
    assert!(process(&mut state, Instruction::VerifyPost { proof }).is_err());
}

#[test]
fn different_k_n_parameters() {
    // Instance 1: K=5, N=3, M=7 (strict forum).
    let mod_keys: Vec<SigningKey> = (0..7).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let mut state = RegistryState::default();
    let moderators: Vec<[u8; 32]> = mod_keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    process(&mut state, Instruction::Initialize {
        forum_id: [0xFFu8; 32],
        moderators,
        threshold_n: 3,
        threshold_k: 5,
        stake_required: 500,
        initial_root: [0u8; 32],
    }).unwrap();

    // N=3 required per cert; 2 votes must be insufficient.
    let identity  = MemberIdentity::generate(&mut OsRng);
    let (_, commits) = split_identity(&identity, 5, 7, &mut OsRng).unwrap();
    let forum_id  = [0xFFu8; 32];
    let member_tag = identity.member_tag(&forum_id);
    process(&mut state, Instruction::Register {
        commitment: identity.commitment(),
        member_tag,
        stake: 500,
        shamir_commitments: commits,
    }).unwrap();

    let two_votes: Vec<_> = mod_keys[0..2].iter().map(|k| {
        draft_vote(forum_id, [0x01u8; 32], member_tag, "spam".to_string(), k).unwrap()
    }).collect();
    assert!(aggregate_votes(two_votes, 3).is_err());

    // Three votes must succeed.
    let three_votes: Vec<_> = mod_keys[0..3].iter().map(|k| {
        draft_vote(forum_id, [0x01u8; 32], member_tag, "spam".to_string(), k).unwrap()
    }).collect();
    assert!(aggregate_votes(three_votes, 3).is_ok());
}

#[test]
fn different_members_have_different_member_tags() {
    let forum_id = [0u8; 32];
    let a = MemberIdentity::generate(&mut OsRng);
    let b = MemberIdentity::generate(&mut OsRng);
    assert_ne!(a.member_tag(&forum_id), b.member_tag(&forum_id));
    assert_ne!(a.commitment(), b.commitment());
}

#[test]
fn same_member_different_forums_different_tags() {
    let id = MemberIdentity::generate(&mut OsRng);
    assert_ne!(id.member_tag(&[0x01u8; 32]), id.member_tag(&[0x02u8; 32]));
}
