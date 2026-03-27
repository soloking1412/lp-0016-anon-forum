use axum::{
    extract::{Query, State},
    http::{HeaderValue, Method},
    routing::{get, post},
    Json, Router,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::SigningKey;
use forum_anon_moderation::{
    identity::{split_identity, MemberIdentity},
    membership::prove_post,
    moderation::{aggregate_votes, draft_vote},
    slash::build_slash,
};
use forum_anon_types::{make_merkle_proof, MembershipProof, ModerationCert, ModeratorVote, ShamirShare};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

fn parse32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32-byte hex".to_string())
}

fn parse64(s: &str) -> Result<[u8; 64], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 64-byte hex".to_string())
}

fn api_err(e: impl std::fmt::Display) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

type ApiResult<T> = Result<Json<T>, (axum::http::StatusCode, String)>;

// ── wire types ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct KeygenResp {
    id_secret_hex: String,
    commitment: String,
}

#[derive(Deserialize)]
struct RegisterReq {
    id_secret_hex: String,
    forum_id: String,
    threshold: u8,
    total: u8,
}

#[derive(Serialize)]
struct RegisterResp {
    commitment: String,
    member_tag: String,
    shamir_commitments: Vec<String>,
    shares: Vec<ShareJson>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ShareJson {
    index: u8,
    value: String,
}

#[derive(Deserialize)]
struct ProvePostReq {
    id_secret_hex: String,
    forum_id: String,
    topic_id: String,
    merkle_root: String,
    leaf_index: usize,
    num_leaves: usize,
}

#[derive(Serialize)]
struct ProvePostResp {
    member_tag: String,
    post_nullifier: String,
    merkle_root: String,
    receipt_hex: String,
}

#[derive(Deserialize)]
struct ModerateReq {
    moderator_key_hex: String,
    forum_id: String,
    content_hash: String,
    member_tag: String,
    reason: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct VoteJson {
    forum_id: String,
    content_hash: String,
    member_tag: String,
    strike_reason: String,
    moderator_pubkey: String,
    signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct CertJson {
    forum_id: String,
    content_hash: String,
    member_tag: String,
    votes: Vec<VoteJson>,
}

#[derive(Deserialize)]
struct AggregateCertReq {
    votes: Vec<VoteJson>,
    threshold_n: u32,
}

#[derive(Deserialize)]
struct SlashReq {
    forum_id: String,
    member_tag: String,
    certs: Vec<CertJson>,
    shares: Vec<ShareJson>,
}

#[derive(Serialize)]
struct SlashResp {
    slash_json: String,
}

#[derive(Deserialize)]
struct CertsQuery {
    forum_id: Option<String>,
}

// ── conversions ──────────────────────────────────────────────────────────────

fn vote_to_json(v: &ModeratorVote) -> VoteJson {
    VoteJson {
        forum_id:        hex::encode(v.forum_id),
        content_hash:    hex::encode(v.content_hash),
        member_tag:      hex::encode(v.member_tag),
        strike_reason:   v.strike_reason.clone(),
        moderator_pubkey: hex::encode(v.moderator_pubkey),
        signature:       hex::encode(v.signature),
    }
}

fn cert_to_json(c: &ModerationCert) -> CertJson {
    CertJson {
        forum_id:     hex::encode(c.forum_id),
        content_hash: hex::encode(c.content_hash),
        member_tag:   hex::encode(c.member_tag),
        votes:        c.votes.iter().map(vote_to_json).collect(),
    }
}

fn json_to_vote(v: &VoteJson) -> Result<ModeratorVote, String> {
    Ok(ModeratorVote {
        forum_id:        parse32(&v.forum_id)?,
        content_hash:    parse32(&v.content_hash)?,
        member_tag:      parse32(&v.member_tag)?,
        strike_reason:   v.strike_reason.clone(),
        moderator_pubkey: parse32(&v.moderator_pubkey)?,
        signature:       parse64(&v.signature)?,
    })
}

fn json_to_cert(c: &CertJson) -> Result<ModerationCert, String> {
    Ok(ModerationCert {
        forum_id:     parse32(&c.forum_id)?,
        content_hash: parse32(&c.content_hash)?,
        member_tag:   parse32(&c.member_tag)?,
        votes:        c.votes.iter().map(json_to_vote).collect::<Result<_, _>>()?,
    })
}

// ── state ────────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
struct ForumEntry {
    forum_id_hex:  String,
    account_id:    [u8; 32],
    threshold_k:   u32,
    threshold_n:   u32,
    moderators:    Vec<[u8; 32]>,
    commitments:   Vec<[u8; 32]>,  // registered member commitments (merkle leaves)
    merkle_root:   [u8; 32],
    deploy_tx:     String,
}

#[derive(Clone)]
struct AppState {
    certs:  Arc<Mutex<Vec<CertJson>>>,
    forums: Arc<Mutex<HashMap<String, ForumEntry>>>,  // key = forum_id hex
}

// ── handlers ─────────────────────────────────────────────────────────────────

async fn keygen() -> ApiResult<KeygenResp> {
    let identity = MemberIdentity::generate(&mut OsRng);
    Ok(Json(KeygenResp {
        id_secret_hex: hex::encode(identity.id_secret),
        commitment:    hex::encode(identity.commitment()),
    }))
}

#[derive(Serialize)]
struct ModKeyResp {
    signing_key_hex: String,   // 32-byte seed — keep private, used in Moderation tab
    pubkey_hex:      String,   // 32-byte verifying key — paste into Create Forum
}

async fn generate_mod_key() -> ApiResult<ModKeyResp> {
    let sk = SigningKey::generate(&mut OsRng);
    Ok(Json(ModKeyResp {
        signing_key_hex: hex::encode(sk.to_bytes()),
        pubkey_hex:      hex::encode(sk.verifying_key().to_bytes()),
    }))
}

async fn register(Json(req): Json<RegisterReq>) -> ApiResult<RegisterResp> {
    let secret   = parse32(&req.id_secret_hex).map_err(api_err)?;
    let forum_id = parse32(&req.forum_id).map_err(api_err)?;
    let identity = MemberIdentity::from_secret(secret);

    let (shares, commitments) =
        split_identity(&identity, req.threshold, req.total, &mut OsRng).map_err(api_err)?;

    Ok(Json(RegisterResp {
        commitment:         hex::encode(identity.commitment()),
        member_tag:         hex::encode(identity.member_tag(&forum_id)),
        shamir_commitments: commitments.iter().map(hex::encode).collect(),
        shares: shares
            .iter()
            .map(|s| ShareJson { index: s.index, value: hex::encode(&s.value) })
            .collect(),
    }))
}

async fn prove_post_handler(Json(req): Json<ProvePostReq>) -> ApiResult<ProvePostResp> {
    if req.leaf_index >= req.num_leaves || !req.num_leaves.is_power_of_two() {
        return Err(api_err("leaf_index out of range or num_leaves not a power of two"));
    }

    let secret      = parse32(&req.id_secret_hex).map_err(api_err)?;
    let forum_id    = parse32(&req.forum_id).map_err(api_err)?;
    let merkle_root = parse32(&req.merkle_root).map_err(api_err)?;
    let topic_id    = parse32(&req.topic_id).map_err(api_err)?;

    let identity   = MemberIdentity::from_secret(secret);
    let commitment = identity.commitment();

    let mut leaves = vec![[0u8; 32]; req.num_leaves];
    leaves[req.leaf_index] = commitment;
    let (merkle_proof, computed_root) = make_merkle_proof(&leaves, req.leaf_index);

    if computed_root != merkle_root {
        return Err(api_err(format!(
            "merkle_root mismatch: computed {}, expected {}",
            hex::encode(computed_root),
            hex::encode(merkle_root),
        )));
    }

    let presenter_key  = SigningKey::generate(&mut OsRng);
    let ext_nullifier: [u8; 32] = Sha256::digest(topic_id).into();

    let receipt = prove_post(
        &identity,
        merkle_proof,
        merkle_root,
        forum_id,
        ext_nullifier,
        presenter_key.verifying_key().to_bytes(),
    )
    .map_err(|e| {
        eprintln!("[prove-post ERROR] {e:#}");
        api_err(format!("{e:#}"))
    })?;

    let proof: MembershipProof =
        BorshDeserialize::try_from_slice(&receipt.journal.bytes).map_err(api_err)?;

    Ok(Json(ProvePostResp {
        member_tag:    hex::encode(proof.member_tag),
        post_nullifier: hex::encode(proof.post_nullifier),
        merkle_root:   hex::encode(proof.merkle_root),
        receipt_hex:   hex::encode(&receipt.journal.bytes),
    }))
}

async fn moderate(Json(req): Json<ModerateReq>) -> ApiResult<VoteJson> {
    let key_bytes: [u8; 32] = hex::decode(&req.moderator_key_hex)
        .map_err(api_err)?
        .try_into()
        .map_err(|_| api_err("moderator key must be 32 bytes"))?;
    let signing_key  = SigningKey::from_bytes(&key_bytes);
    let forum_id     = parse32(&req.forum_id).map_err(api_err)?;
    let content_hash = parse32(&req.content_hash).map_err(api_err)?;
    let member_tag   = parse32(&req.member_tag).map_err(api_err)?;

    let vote = draft_vote(forum_id, content_hash, member_tag, req.reason, &signing_key)
        .map_err(api_err)?;
    Ok(Json(vote_to_json(&vote)))
}

async fn aggregate_cert(
    State(state): State<AppState>,
    Json(req): Json<AggregateCertReq>,
) -> ApiResult<CertJson> {
    let votes: Vec<ModeratorVote> =
        req.votes.iter().map(json_to_vote).collect::<Result<_, _>>().map_err(api_err)?;
    let cert      = aggregate_votes(votes, req.threshold_n).map_err(api_err)?;
    let cert_json = cert_to_json(&cert);
    state.certs.lock().unwrap().push(cert_json.clone());
    Ok(Json(cert_json))
}

async fn slash(Json(req): Json<SlashReq>) -> ApiResult<SlashResp> {
    let forum_id   = parse32(&req.forum_id).map_err(api_err)?;
    let member_tag = parse32(&req.member_tag).map_err(api_err)?;
    let certs: Vec<ModerationCert> =
        req.certs.iter().map(json_to_cert).collect::<Result<_, _>>().map_err(api_err)?;
    let shares: Vec<ShamirShare> = req
        .shares
        .iter()
        .map(|s| {
            Ok(ShamirShare {
                index: s.index,
                value: hex::decode(&s.value).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(api_err)?;

    let slash_data = build_slash(forum_id, member_tag, certs, shares);
    Ok(Json(SlashResp {
        slash_json: serde_json::to_string_pretty(&slash_data).map_err(api_err)?,
    }))
}

async fn list_certs(
    State(state): State<AppState>,
    Query(q): Query<CertsQuery>,
) -> Json<Vec<CertJson>> {
    let certs = state.certs.lock().unwrap();
    let result: Vec<CertJson> = match &q.forum_id {
        Some(fid) => certs.iter().filter(|c| c.forum_id == *fid).cloned().collect(),
        None      => certs.clone(),
    };
    Json(result)
}

// ── entry point ──────────────────────────────────────────────────────────────

pub async fn run(port: u16) -> anyhow::Result<()> {
    let state = AppState {
        certs:  Arc::new(Mutex::new(Vec::new())),
        forums: Arc::new(Mutex::new(HashMap::new())),
    };

    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:3000".parse::<HeaderValue>().expect("valid origin"),
            "http://localhost:5173".parse::<HeaderValue>().expect("valid origin"),
        ])
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(tower_http::cors::Any);

    let app = Router::new()
        .route("/keygen",            post(keygen))
        .route("/generate-mod-key", post(generate_mod_key))
        .route("/register",          post(register))
        .route("/prove-post",        post(prove_post_handler))
        .route("/moderate",          post(moderate))
        .route("/aggregate-cert",    post(aggregate_cert))
        .route("/slash",             post(slash))
        .route("/certs",             get(list_certs))
        // ── on-chain endpoints ──────────────────────────────────────────────
        .route("/deploy-forum",      post(deploy_forum))
        .route("/register-onchain",  post(register_onchain))
        .route("/submit-post",       post(submit_post_onchain))
        .route("/submit-cert",       post(submit_cert_onchain))
        .route("/slash-onchain",     post(slash_onchain))
        .route("/forums",            get(list_forums))
        .layer(cors)
        .with_state(state);

    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("daemon listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// On-chain transaction helpers
// ═══════════════════════════════════════════════════════════════════════════════

const REGISTRY_PROGRAM_ID: [u32; 8] = [
    1909169956, 2313131218, 3219152519, 3402869729,
    1590750509, 2066446164, 1519591204, 2113149490,
];

// Borsh-serialisable NSSATransaction::Public skeleton (matches LEZ wire format)
#[derive(BorshSerialize)]
struct NssaMessage {
    program_id:       [u32; 8],
    account_ids:      Vec<[u8; 32]>,
    nonces:           Vec<u128>,
    instruction_data: Vec<u32>,
}

#[derive(BorshSerialize)]
struct NssaWitnessSet {
    signatures_and_public_keys: Vec<([u8; 64], [u8; 32])>,
}

#[derive(BorshSerialize)]
struct NssaPublicTx {
    message:     NssaMessage,
    witness_set: NssaWitnessSet,
}

// Enum variant 0 = Public
#[derive(BorshSerialize)]
enum NssaTransaction {
    Public(NssaPublicTx),
}

// Registry-guest-compatible instruction (signatures as Vec<u8>, matching guest types)
#[derive(Serialize, Deserialize)]
struct RegModeratorVote {
    forum_id:         [u8; 32],
    content_hash:     [u8; 32],
    member_tag:       [u8; 32],
    strike_reason:    String,
    moderator_pubkey: [u8; 32],
    signature:        Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct RegModerationCert {
    forum_id:     [u8; 32],
    content_hash: [u8; 32],
    member_tag:   [u8; 32],
    votes:        Vec<RegModeratorVote>,
}

#[derive(Serialize, Deserialize)]
struct RegShamirShare {
    index: u8,
    value: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct RegSlashData {
    forum_id:   [u8; 32],
    member_tag: [u8; 32],
    certs:      Vec<RegModerationCert>,
    shares:     Vec<RegShamirShare>,
}

#[derive(Serialize, Deserialize)]
struct RegMembershipProof {
    merkle_root:      [u8; 32],
    forum_id:         [u8; 32],
    member_tag:       [u8; 32],
    post_nullifier:   [u8; 32],
    ext_nullifier:    [u8; 32],
    presenter_pubkey: [u8; 32],
}

#[derive(Serialize, Deserialize)]
enum RegInstruction {
    Initialize {
        forum_id:       [u8; 32],
        moderators:     Vec<[u8; 32]>,
        threshold_n:    u32,
        threshold_k:    u32,
        stake_required: u64,
        initial_root:   [u8; 32],
    },
    Register {
        commitment:         [u8; 32],
        member_tag:         [u8; 32],
        stake:              u64,
        shamir_commitments: Vec<[u8; 32]>,
    },
    UpdateMerkleRoot { new_root: [u8; 32] },
    SubmitModerationCert { cert: RegModerationCert },
    Slash { slash: RegSlashData },
    RejectNullifier { nullifier: [u8; 32] },
    VerifyPost { proof: RegMembershipProof },
}

async fn send_instruction(
    account_id: [u8; 32],
    instruction: &RegInstruction,
) -> anyhow::Result<String> {
    let instruction_data: Vec<u32> = risc0_zkvm::serde::to_vec(instruction)
        .map_err(|e| anyhow::anyhow!("serde: {e}"))?;

    let tx = NssaTransaction::Public(NssaPublicTx {
        message: NssaMessage {
            program_id:       REGISTRY_PROGRAM_ID,
            account_ids:      vec![account_id],
            nonces:           vec![],
            instruction_data,
        },
        witness_set: NssaWitnessSet {
            signatures_and_public_keys: vec![],
        },
    });

    let tx_bytes = borsh::to_vec(&tx)?;
    let b64 = B64.encode(&tx_bytes);

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post("http://127.0.0.1:3040")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method":  "sendTransaction",
            "params":  [b64],
            "id":      1
        }))
        .send().await?
        .json().await?;

    if let Some(err) = resp.get("error") {
        anyhow::bail!("sequencer: {err}");
    }

    let hash = match resp.get("result") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(v) => serde_json::to_string(v).unwrap_or_default(),
        None => "(no hash returned)".to_string(),
    };
    Ok(hash)
}

// Compute a 4-leaf merkle root from the first 4 (or fewer, zero-padded) commitments
fn compute_merkle_root(commitments: &[[u8; 32]]) -> ([u8; 32], Vec<[u8; 32]>) {
    let mut leaves = vec![[0u8; 32]; 4];
    for (i, c) in commitments.iter().take(4).enumerate() {
        leaves[i] = *c;
    }
    let (_, root) = make_merkle_proof(&leaves, 0);
    (root, leaves)
}

// ═══════════════════════════════════════════════════════════════════════════════
// On-chain endpoint handlers
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct DeployForumReq {
    forum_id:    Option<String>,  // optional, random if omitted
    threshold_k: u32,
    threshold_n: u32,
    moderators:  Vec<String>,     // hex-encoded Ed25519 pubkeys
}

#[derive(Serialize)]
struct DeployForumResp {
    tx_hash:    String,
    forum_id:   String,
    account_id: String,
    threshold_k: u32,
    threshold_n: u32,
}

async fn deploy_forum(
    State(state): State<AppState>,
    Json(req): Json<DeployForumReq>,
) -> ApiResult<DeployForumResp> {
    let forum_id: [u8; 32] = match req.forum_id {
        Some(ref s) => parse32(s).map_err(api_err)?,
        None => {
            let mut b = [0u8; 32];
            rand::Rng::fill(&mut rand::rngs::OsRng, &mut b);
            b
        }
    };

    let mut account_id = [0u8; 32];
    rand::Rng::fill(&mut rand::rngs::OsRng, &mut account_id);

    let moderators: Vec<[u8; 32]> = req.moderators.iter()
        .map(|s| parse32(s))
        .collect::<Result<_, _>>()
        .map_err(api_err)?;

    let instr = RegInstruction::Initialize {
        forum_id,
        moderators: moderators.clone(),
        threshold_n: req.threshold_n,
        threshold_k: req.threshold_k,
        stake_required: 100,
        initial_root: [0u8; 32],
    };

    let tx_hash = send_instruction(account_id, &instr).await.map_err(api_err)?;
    let forum_id_hex = hex::encode(forum_id);

    let entry = ForumEntry {
        forum_id_hex: forum_id_hex.clone(),
        account_id,
        threshold_k: req.threshold_k,
        threshold_n: req.threshold_n,
        moderators,
        commitments: vec![],
        merkle_root: [0u8; 32],
        deploy_tx: tx_hash.clone(),
    };
    state.forums.lock().unwrap().insert(forum_id_hex.clone(), entry);

    Ok(Json(DeployForumResp {
        tx_hash,
        forum_id:    forum_id_hex,
        account_id:  hex::encode(account_id),
        threshold_k: req.threshold_k,
        threshold_n: req.threshold_n,
    }))
}

#[derive(Deserialize)]
struct RegisterOnChainReq {
    id_secret_hex: String,
    forum_id:      String,
    stake:         u64,
    threshold:     u8,
    total:         u8,
}

#[derive(Serialize)]
struct RegisterOnChainResp {
    register_tx:  String,
    root_tx:      String,
    commitment:   String,
    member_tag:   String,
    merkle_root:  String,
    leaf_index:   usize,
    shares:       Vec<ShareJson>,
}

async fn register_onchain(
    State(state): State<AppState>,
    Json(req): Json<RegisterOnChainReq>,
) -> ApiResult<RegisterOnChainResp> {
    let secret   = parse32(&req.id_secret_hex).map_err(api_err)?;
    let forum_id = parse32(&req.forum_id).map_err(api_err)?;
    let identity = MemberIdentity::from_secret(secret);
    let commitment = identity.commitment();
    let member_tag = identity.member_tag(&forum_id);

    let (shares, shamir_commitments) =
        split_identity(&identity, req.threshold, req.total, &mut rand::rngs::OsRng)
            .map_err(api_err)?;

    // Look up forum account
    let (account_id, leaf_index, new_root) = {
        let mut forums = state.forums.lock().unwrap();
        let entry = forums.get_mut(&req.forum_id)
            .ok_or_else(|| api_err("forum not found — deploy first"))?;
        let leaf_index = entry.commitments.len();
        entry.commitments.push(commitment);
        let (root, _) = compute_merkle_root(&entry.commitments);
        entry.merkle_root = root;
        (entry.account_id, leaf_index, root)
    };

    // Register tx
    let instr_reg = RegInstruction::Register {
        commitment,
        member_tag,
        stake: req.stake,
        shamir_commitments: shamir_commitments.clone(),
    };
    let register_tx = send_instruction(account_id, &instr_reg).await.map_err(api_err)?;

    // Update merkle root tx
    let instr_root = RegInstruction::UpdateMerkleRoot { new_root };
    let root_tx = send_instruction(account_id, &instr_root).await.map_err(api_err)?;

    Ok(Json(RegisterOnChainResp {
        register_tx,
        root_tx,
        commitment:  hex::encode(commitment),
        member_tag:  hex::encode(member_tag),
        merkle_root: hex::encode(new_root),
        leaf_index,
        shares: shares.iter().map(|s| ShareJson {
            index: s.index,
            value: hex::encode(&s.value),
        }).collect(),
    }))
}

#[derive(Deserialize)]
struct SubmitPostOnChainReq {
    forum_id:       String,
    receipt_hex:    String,  // journal bytes from /prove-post
}

#[derive(Serialize)]
struct SubmitPostOnChainResp {
    tx_hash:        String,
    post_nullifier: String,
    member_tag:     String,
}

async fn submit_post_onchain(
    State(state): State<AppState>,
    Json(req): Json<SubmitPostOnChainReq>,
) -> ApiResult<SubmitPostOnChainResp> {
    let journal_bytes = hex::decode(&req.receipt_hex).map_err(api_err)?;
    let proof: forum_anon_types::MembershipProof =
        BorshDeserialize::try_from_slice(&journal_bytes).map_err(api_err)?;

    let account_id = {
        let forums = state.forums.lock().unwrap();
        forums.get(&req.forum_id)
            .ok_or_else(|| api_err("forum not found"))?
            .account_id
    };

    let instr = RegInstruction::VerifyPost {
        proof: RegMembershipProof {
            merkle_root:      proof.merkle_root,
            forum_id:         proof.forum_id,
            member_tag:       proof.member_tag,
            post_nullifier:   proof.post_nullifier,
            ext_nullifier:    proof.ext_nullifier,
            presenter_pubkey: proof.presenter_pubkey,
        },
    };

    let tx_hash = send_instruction(account_id, &instr).await.map_err(api_err)?;

    Ok(Json(SubmitPostOnChainResp {
        tx_hash,
        post_nullifier: hex::encode(proof.post_nullifier),
        member_tag:     hex::encode(proof.member_tag),
    }))
}

#[derive(Deserialize)]
struct SubmitCertOnChainReq {
    forum_id: String,
    cert:     CertJson,
}

#[derive(Serialize)]
struct SubmitCertOnChainResp {
    tx_hash: String,
}

async fn submit_cert_onchain(
    State(state): State<AppState>,
    Json(req): Json<SubmitCertOnChainReq>,
) -> ApiResult<SubmitCertOnChainResp> {
    let account_id = {
        let forums = state.forums.lock().unwrap();
        forums.get(&req.forum_id)
            .ok_or_else(|| api_err("forum not found"))?
            .account_id
    };

    let cert = json_to_cert(&req.cert).map_err(api_err)?;
    let reg_cert = RegModerationCert {
        forum_id:     cert.forum_id,
        content_hash: cert.content_hash,
        member_tag:   cert.member_tag,
        votes: cert.votes.iter().map(|v| RegModeratorVote {
            forum_id:         v.forum_id,
            content_hash:     v.content_hash,
            member_tag:       v.member_tag,
            strike_reason:    v.strike_reason.clone(),
            moderator_pubkey: v.moderator_pubkey,
            signature:        v.signature.to_vec(),
        }).collect(),
    };

    let instr = RegInstruction::SubmitModerationCert { cert: reg_cert };
    let tx_hash = send_instruction(account_id, &instr).await.map_err(api_err)?;

    // Store cert in audit trail
    state.certs.lock().unwrap().push(cert_to_json(&cert));

    Ok(Json(SubmitCertOnChainResp { tx_hash }))
}

#[derive(Deserialize)]
struct SlashOnChainReq {
    forum_id:   String,
    member_tag: String,
    certs:      Vec<CertJson>,
    shares:     Vec<ShareJson>,
}

#[derive(Serialize)]
struct SlashOnChainResp {
    tx_hash: String,
}

async fn slash_onchain(
    State(state): State<AppState>,
    Json(req): Json<SlashOnChainReq>,
) -> ApiResult<SlashOnChainResp> {
    let account_id = {
        let forums = state.forums.lock().unwrap();
        forums.get(&req.forum_id)
            .ok_or_else(|| api_err("forum not found"))?
            .account_id
    };

    let forum_id   = parse32(&req.forum_id).map_err(api_err)?;
    let member_tag = parse32(&req.member_tag).map_err(api_err)?;

    let certs: Vec<forum_anon_types::ModerationCert> = req.certs.iter()
        .map(json_to_cert).collect::<Result<_, _>>().map_err(api_err)?;
    let reg_certs: Vec<RegModerationCert> = certs.iter().map(|c| RegModerationCert {
        forum_id:     c.forum_id,
        content_hash: c.content_hash,
        member_tag:   c.member_tag,
        votes: c.votes.iter().map(|v| RegModeratorVote {
            forum_id:         v.forum_id,
            content_hash:     v.content_hash,
            member_tag:       v.member_tag,
            strike_reason:    v.strike_reason.clone(),
            moderator_pubkey: v.moderator_pubkey,
            signature:        v.signature.to_vec(),
        }).collect(),
    }).collect();

    let reg_shares: Vec<RegShamirShare> = req.shares.iter().map(|s| {
        Ok(RegShamirShare {
            index: s.index,
            value: hex::decode(&s.value).map_err(|e| e.to_string())?,
        })
    }).collect::<Result<_, String>>().map_err(api_err)?;

    let instr = RegInstruction::Slash {
        slash: RegSlashData { forum_id, member_tag, certs: reg_certs, shares: reg_shares },
    };
    let tx_hash = send_instruction(account_id, &instr).await.map_err(api_err)?;

    Ok(Json(SlashOnChainResp { tx_hash }))
}

async fn list_forums(State(state): State<AppState>) -> Json<Vec<ForumEntry>> {
    Json(state.forums.lock().unwrap().values().cloned().collect())
}
