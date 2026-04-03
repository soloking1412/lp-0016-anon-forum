mod daemon;
mod waku;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use forum_anon_moderation::{
    identity::{split_identity, MemberIdentity},
    membership::prove_post,
    moderation::{aggregate_votes, draft_vote},
    slash::{build_slash, reconstruct_and_verify},
};
use forum_anon_types::{make_merkle_proof, ModerationCert, ModeratorVote, ShamirShare};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "forum-anon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    Register {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        forum: [u8; 32],
        #[arg(long, default_value = "1000")]
        stake: u64,
        #[arg(long, default_value = "5")]
        total: u8,
        #[arg(long, default_value = "3")]
        threshold: u8,
    },
    Post {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        forum: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        topic: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        root: [u8; 32],
        #[arg(long)]
        leaf_index: usize,
        #[arg(long)]
        num_leaves: usize,
        #[arg(long)]
        out: PathBuf,
    },
    Moderate {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        forum: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        post_hash: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        member_tag: [u8; 32],
        #[arg(long)]
        reason: String,
        #[arg(long)]
        out: PathBuf,
    },
    AggregateCert {
        #[arg(long, num_args = 1..)]
        votes: Vec<PathBuf>,
        #[arg(long, default_value = "2")]
        threshold_n: u32,
        #[arg(long)]
        out: PathBuf,
    },
    Slash {
        #[arg(long, value_parser = parse_hex32)]
        forum: [u8; 32],
        #[arg(long, value_parser = parse_hex32)]
        member_tag: [u8; 32],
        #[arg(long, num_args = 1..)]
        certs: Vec<PathBuf>,
        #[arg(long, num_args = 1..)]
        shares: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    VerifyShare {
        #[arg(long)]
        share: PathBuf,
        #[arg(long, value_parser = parse_hex32)]
        commitment: [u8; 32],
    },
    VerifySlash {
        #[arg(long, num_args = 1..)]
        shares: Vec<PathBuf>,
        #[arg(long, value_parser = parse_hex32)]
        commitment: [u8; 32],
    },
    Daemon {
        #[arg(long, default_value = "3101")]
        port: u16,
    },
}

#[derive(serde::Deserialize)]
struct ShareFile {
    index: u8,
    value: String,
}

fn share_file_to_shamir(sf: ShareFile) -> Result<ShamirShare> {
    let value = hex::decode(&sf.value).context("decode share value hex")?;
    Ok(ShamirShare { index: sf.index, value })
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    bytes.try_into().map_err(|_| "expected 32-byte hex string".to_string())
}

fn load_signing_key(path: &PathBuf) -> Result<SigningKey> {
    let bytes = std::fs::read(path).context("read key file")?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen { out } => {
            let identity = MemberIdentity::generate(&mut OsRng);
            std::fs::write(&out, identity.id_secret).context("write key file")?;
            println!("commitment: {}", hex::encode(identity.commitment()));
        }

        Command::Register { key, forum, stake, total, threshold } => {
            let secret: [u8; 32] = std::fs::read(&key).context("read key")?
                .try_into().map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
            let identity = MemberIdentity::from_secret(secret);
            let (shares, commitments) = split_identity(&identity, threshold, total, &mut OsRng)?;

            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "commitment": hex::encode(identity.commitment()),
                "member_tag": hex::encode(identity.member_tag(&forum)),
                "stake": stake,
                "shamir_commitments": commitments.iter().map(hex::encode).collect::<Vec<_>>(),
                "shares": shares.iter().map(|s| serde_json::json!({
                    "index": s.index,
                    "value": hex::encode(&s.value),
                })).collect::<Vec<_>>(),
            }))?);
        }

        Command::Post { key, forum, topic, root, leaf_index, num_leaves, out } => {
            let secret: [u8; 32] = std::fs::read(&key).context("read key")?
                .try_into().map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
            let identity = MemberIdentity::from_secret(secret);
            let commitment = identity.commitment();

            anyhow::ensure!(leaf_index < num_leaves, "leaf_index out of range");
            anyhow::ensure!(num_leaves.is_power_of_two(), "num_leaves must be a power of two");

            let mut leaves = vec![[0u8; 32]; num_leaves];
            leaves[leaf_index] = commitment;
            let (merkle_proof, computed_root) = make_merkle_proof(&leaves, leaf_index);
            anyhow::ensure!(
                computed_root == root,
                "root mismatch: computed {}, expected {}",
                hex::encode(computed_root),
                hex::encode(root)
            );

            let presenter_key = SigningKey::generate(&mut OsRng);
            let ext_nullifier: [u8; 32] = Sha256::digest(topic).into();

            let receipt = prove_post(
                &identity, merkle_proof, root, forum, ext_nullifier,
                presenter_key.verifying_key().to_bytes(),
            )?;

            std::fs::write(&out, borsh::to_vec(&receipt.journal.bytes)?).context("write receipt")?;
            println!("proof written to {}", out.display());
        }

        Command::Moderate { key, forum, post_hash, member_tag, reason, out } => {
            let signing_key = load_signing_key(&key)?;
            let vote = draft_vote(forum, post_hash, member_tag, reason, &signing_key)?;
            std::fs::write(&out, serde_json::to_string_pretty(&vote)?).context("write vote")?;
            println!("vote written to {}", out.display());
        }

        Command::AggregateCert { votes, threshold_n, out } => {
            let mut parsed: Vec<ModeratorVote> = Vec::new();
            for path in &votes {
                let json = std::fs::read_to_string(path).context("read vote file")?;
                parsed.push(serde_json::from_str(&json).context("parse vote")?);
            }
            let cert = aggregate_votes(parsed, threshold_n).map_err(|e| anyhow::anyhow!("{e}"))?;
            std::fs::write(&out, serde_json::to_string_pretty(&cert)?).context("write cert")?;
            println!("cert written to {}", out.display());
        }

        Command::Slash { forum, member_tag, certs, shares, out } => {
            let mut parsed_certs: Vec<ModerationCert> = Vec::new();
            for path in &certs {
                let json = std::fs::read_to_string(path).context("read cert")?;
                parsed_certs.push(serde_json::from_str(&json).context("parse cert")?);
            }
            let mut parsed_shares: Vec<ShamirShare> = Vec::new();
            for path in &shares {
                let json = std::fs::read_to_string(path).context("read share")?;
                let sf: ShareFile = serde_json::from_str(&json).context("parse share")?;
                parsed_shares.push(share_file_to_shamir(sf)?);
            }
            let slash = build_slash(forum, member_tag, parsed_certs, parsed_shares);
            std::fs::write(&out, serde_json::to_string_pretty(&slash)?).context("write slash")?;
            println!("slash written to {}", out.display());
        }

        Command::VerifyShare { share, commitment } => {
            let json = std::fs::read_to_string(&share).context("read share")?;
            let sf: ShareFile = serde_json::from_str(&json).context("parse share")?;
            let s = share_file_to_shamir(sf)?;
            if forum_anon_moderation::identity::verify_share(&s, &commitment) {
                println!("VALID");
            } else {
                anyhow::bail!("INVALID");
            }
        }

        Command::VerifySlash { shares, commitment } => {
            let mut parsed: Vec<ShamirShare> = Vec::new();
            for path in &shares {
                let json = std::fs::read_to_string(path).context("read share")?;
                let sf: ShareFile = serde_json::from_str(&json).context("parse share")?;
                parsed.push(share_file_to_shamir(sf)?);
            }
            let id_secret = reconstruct_and_verify(&parsed, &commitment)?;
            println!("ok — id_secret: {}", hex::encode(id_secret));
        }

        Command::Daemon { port } => {
            daemon::run(port).await?;
        }
    }

    Ok(())
}
