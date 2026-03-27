use ed25519_dalek::SigningKey;
use forum_anon_moderation::moderation::{aggregate_votes, draft_vote, verify_cert};
use rand::rngs::OsRng;

fn make_moderator() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn forum_id() -> [u8; 32] { [0xAAu8; 32] }
fn content_hash() -> [u8; 32] { [0xBBu8; 32] }
fn member_tag() -> [u8; 32] { [0xCCu8; 32] }

#[test]
fn single_vote_below_threshold_rejected() {
    let mod_key = make_moderator();
    let vote = draft_vote(
        forum_id(), content_hash(), member_tag(),
        "spam".to_string(), &mod_key,
    ).unwrap();

    let result = aggregate_votes(vec![vote], 2);
    assert!(result.is_err());
}

#[test]
fn n_votes_forms_valid_cert() {
    let keys: Vec<SigningKey> = (0..3).map(|_| make_moderator()).collect();
    let votes: Vec<_> = keys.iter().map(|k| {
        draft_vote(forum_id(), content_hash(), member_tag(), "spam".to_string(), k).unwrap()
    }).collect();

    let pubkeys: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let cert = aggregate_votes(votes, 2).unwrap();
    verify_cert(&cert, &pubkeys, 2).unwrap();
}

#[test]
fn extra_votes_still_valid() {
    let keys: Vec<SigningKey> = (0..5).map(|_| make_moderator()).collect();
    let votes: Vec<_> = keys.iter().map(|k| {
        draft_vote(forum_id(), content_hash(), member_tag(), "spam".to_string(), k).unwrap()
    }).collect();

    let pubkeys: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let cert = aggregate_votes(votes, 3).unwrap();
    verify_cert(&cert, &pubkeys, 3).unwrap();
}

#[test]
fn unknown_moderator_rejected() {
    let good_key = make_moderator();
    let bad_key  = make_moderator();
    let vote = draft_vote(
        forum_id(), content_hash(), member_tag(),
        "spam".to_string(), &bad_key,
    ).unwrap();

    let cert = aggregate_votes(vec![vote], 1).unwrap();
    let only_good = vec![good_key.verifying_key().to_bytes()];
    assert!(verify_cert(&cert, &only_good, 1).is_err());
}

#[test]
fn mismatched_votes_cannot_aggregate() {
    let k1 = make_moderator();
    let k2 = make_moderator();
    let v1 = draft_vote(forum_id(), content_hash(), member_tag(), "spam".to_string(), &k1).unwrap();
    // Different content_hash
    let v2 = draft_vote(forum_id(), [0xDDu8; 32], member_tag(), "spam".to_string(), &k2).unwrap();
    assert!(aggregate_votes(vec![v1, v2], 2).is_err());
}
