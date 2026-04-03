// send-forum-tx — send an Initialize instruction to the forum registry on LEZ.
//
// Usage:
//   send-forum-tx <account_id_b58> <forum_id_hex> <K> <N> <moderator_pubkey_hex...>
//
// Example:
//   send-forum-tx CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r aabb...ff 3 2 <pub_key_1> <pub_key_2>

use anyhow::{Context, Result, bail};
use common::transaction::NSSATransaction;
use nssa::{AccountId, public_transaction::{Message, WitnessSet}, PublicTransaction};
use sequencer_service_rpc::{RpcClient as _, SequencerClientBuilder};
use serde::{Serialize, Deserialize};
use std::str::FromStr;

// The forum registry program ID (computed from the ELF ImageID)
// ImageID hex: 249fcb71d294df89875ee0bfe1abd3ca2dedd05e54772b7b241f935a321af47d
const PROGRAM_ID: [u32; 8] = [
    1909169956, 2313131218, 3219152519, 3402869729,
    1590750509, 2066446164, 1519591204, 2113149490,
];

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s).context("hex decode")?;
    b.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", s.len() / 2))
}

// Mirror the Instruction enum from the guest (must match exactly)
#[derive(Serialize, Deserialize)]
enum Instruction {
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
    SubmitModerationCert { cert: serde_json::Value },
    Slash { slash: serde_json::Value },
    RejectNullifier { nullifier: [u8; 32] },
    VerifyPost { proof: serde_json::Value },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        bail!("Usage: send-forum-tx <account_id_b58> <forum_id_hex> <K> <N> <moderator_pubkey_hex...>");
    }

    let account_id_str = &args[1];
    let forum_id_hex   = &args[2];
    let threshold_k: u32 = args[3].parse().context("K")?;
    let threshold_n: u32 = args[4].parse().context("N")?;
    let moderators: Vec<[u8; 32]> = args[5..]
        .iter()
        .map(|s| parse_hex32(s))
        .collect::<Result<_>>()?;

    let forum_id = parse_hex32(forum_id_hex)?;
    let account_id = AccountId::from_str(account_id_str).context("invalid account_id")?;

    let instruction = Instruction::Initialize {
        forum_id,
        moderators,
        threshold_n,
        threshold_k,
        stake_required: 100,
        initial_root: [0u8; 32],
    };

    // Serialize instruction with risc0 serde (Vec<u32>)
    let instruction_data = risc0_zkvm::serde::to_vec(&instruction)
        .context("serialize instruction")?;

    println!("Forum ID:     {forum_id_hex}");
    println!("Account ID:   {account_id_str}");
    println!("threshold_k:  {threshold_k}");
    println!("threshold_n:  {threshold_n}");
    println!("Instruction:  {} u32 words", instruction_data.len());

    // Construct public transaction
    let message = Message::new_preserialized(
        PROGRAM_ID,
        vec![account_id],
        vec![],  // nonces – uninitialized account needs none
        instruction_data,
    );

    let witness_set = WitnessSet::for_message(&message, &[]);  // no signers needed
    let tx = PublicTransaction::new(message, witness_set);
    let nssa_tx = NSSATransaction::Public(tx);

    let client = SequencerClientBuilder::default().build("http://127.0.0.1:3040").context("build client")?;

    println!("\nSending to sequencer at http://127.0.0.1:3040 ...");
    match client.send_transaction(nssa_tx).await {
        Ok(hash) => {
            println!("✅ Transaction submitted! Hash: {}", hex::encode(hash.0));
            println!("\nProgram ID (hex): 249fcb71d294df89875ee0bfe1abd3ca2dedd05e54772b7b241f935a321af47d");
            println!("Forum account:    {account_id_str}");
        }
        Err(e) => {
            println!("❌ Error: {e}");
        }
    }

    Ok(())
}
