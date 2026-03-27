use forum_anon_circuit::{prove_membership, verify_membership};
use forum_anon_moderation::identity::MemberIdentity;
use forum_anon_types::{derive_post_nullifier, make_merkle_proof, MemberWitness, PostPublicInputs};
use rand::rngs::OsRng;

fn gen_presenter_pubkey() -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    SigningKey::generate(&mut OsRng).verifying_key().to_bytes()
}

#[test]
fn prove_and_verify_membership() {
    let identity = MemberIdentity::generate(&mut OsRng);
    let commitment = identity.commitment();
    let forum_id = [0xABu8; 32];
    let ext_nullifier = [0xCDu8; 32];

    // Build a small Merkle tree with the member at index 0.
    let leaves = [commitment, [0u8; 32], [0u8; 32], [0u8; 32]];
    let (merkle_proof, root) = make_merkle_proof(&leaves, 0);

    let witness = MemberWitness { id_secret: identity.id_secret, merkle_proof };
    let public  = PostPublicInputs {
        merkle_root: root,
        forum_id,
        ext_nullifier,
        presenter_pubkey: gen_presenter_pubkey(),
    };

    let receipt = prove_membership(&witness, &public).unwrap();
    let proof   = verify_membership(&receipt).unwrap();

    assert_eq!(proof.merkle_root, root);
    assert_eq!(proof.forum_id, forum_id);
    assert_eq!(proof.ext_nullifier, ext_nullifier);

    // member_tag must equal the expected derivation.
    let expected_tag = identity.member_tag(&forum_id);
    assert_eq!(proof.member_tag, expected_tag);

    // post_nullifier must equal the expected derivation.
    let expected_null = derive_post_nullifier(&identity.id_secret, &ext_nullifier);
    assert_eq!(proof.post_nullifier, expected_null);
}

#[test]
fn different_topics_produce_different_nullifiers() {
    let identity = MemberIdentity::generate(&mut OsRng);
    let commitment = identity.commitment();
    let forum_id = [0x01u8; 32];

    let leaves = [commitment, [0u8; 32], [0u8; 32], [0u8; 32]];
    let (merkle_proof1, root) = make_merkle_proof(&leaves, 0);
    let (merkle_proof2, _)    = make_merkle_proof(&leaves, 0);

    let topic1 = [0x01u8; 32];
    let topic2 = [0x02u8; 32];

    let witness1 = MemberWitness { id_secret: identity.id_secret, merkle_proof: merkle_proof1 };
    let witness2 = MemberWitness { id_secret: identity.id_secret, merkle_proof: merkle_proof2 };
    let pk = gen_presenter_pubkey();

    let r1 = prove_membership(&witness1, &PostPublicInputs { merkle_root: root, forum_id, ext_nullifier: topic1, presenter_pubkey: pk }).unwrap();
    let r2 = prove_membership(&witness2, &PostPublicInputs { merkle_root: root, forum_id, ext_nullifier: topic2, presenter_pubkey: pk }).unwrap();

    let p1 = verify_membership(&r1).unwrap();
    let p2 = verify_membership(&r2).unwrap();

    // Same member, different topics → different nullifiers (unlinkable).
    assert_ne!(p1.post_nullifier, p2.post_nullifier);
    // Same member, same forum → identical member_tag (traceable within forum).
    assert_eq!(p1.member_tag, p2.member_tag);
}

#[test]
fn wrong_merkle_root_fails_proof() {
    let identity = MemberIdentity::generate(&mut OsRng);
    let commitment = identity.commitment();

    let leaves = [commitment, [0u8; 32], [0u8; 32], [0u8; 32]];
    let (merkle_proof, _real_root) = make_merkle_proof(&leaves, 0);

    let wrong_root = [0xFFu8; 32];
    let witness = MemberWitness { id_secret: identity.id_secret, merkle_proof };
    let public  = PostPublicInputs {
        merkle_root: wrong_root,
        forum_id: [0u8; 32],
        ext_nullifier: [0u8; 32],
        presenter_pubkey: gen_presenter_pubkey(),
    };

    // The guest asserts the Merkle path is valid — should panic/fail.
    assert!(prove_membership(&witness, &public).is_err());
}
