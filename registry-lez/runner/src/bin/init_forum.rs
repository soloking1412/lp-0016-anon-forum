// init-forum — sends an Initialize transaction to the forum registry on LEZ.
//
// Usage:
//   init-forum <program_id_hex> <account_id> <forum_id_hex> <K> <N> <M>
//
// Example:
//   init-forum abc123... PublicABC... aabb...ff 3 2 3

use anyhow::{Context, Result, bail};
use borsh::BorshSerialize;
use std::env;

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s).context("hex decode")?;
    b.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

#[derive(BorshSerialize)]
enum Instruction {
    Initialize {
        forum_id:       [u8; 32],
        moderators:     Vec<[u8; 32]>,
        threshold_n:    u32,
        threshold_k:    u32,
        stake_required: u64,
        initial_root:   [u8; 32],
    },
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 7 {
        bail!("Usage: init-forum <program_id_hex> <account_id> <forum_id_hex> <K> <N> <moderator_pubkey_hex...>");
    }

    let program_id_hex = &args[1];
    let account_id     = &args[2];
    let forum_id_hex   = &args[3];
    let threshold_k: u32 = args[4].parse().context("K")?;
    let threshold_n: u32 = args[5].parse().context("N")?;
    let moderators: Vec<[u8; 32]> = args[6..].iter()
        .map(|s| parse_hex32(s))
        .collect::<Result<_>>()?;

    let forum_id = parse_hex32(forum_id_hex)?;
    let program_id_bytes = hex::decode(program_id_hex).context("program_id hex")?;

    let instruction = Instruction::Initialize {
        forum_id,
        moderators,
        threshold_n,
        threshold_k,
        stake_required: 100,
        initial_root: [0u8; 32],
    };

    let encoded = borsh::to_vec(&instruction)?;

    println!("forum_id:    {}", forum_id_hex);
    println!("threshold_k: {threshold_k}");
    println!("threshold_n: {threshold_n}");
    println!("instruction: {} bytes borsh-encoded", encoded.len());
    println!();
    println!("Run from logos-execution-zone directory:");
    println!("  NSSA_WALLET_HOME_DIR=wallet/configs/debug \\");
    println!("  cargo run --release -p wallet -- \\");
    println!("    execute-program {} {} {}", program_id_hex, account_id, hex::encode(&encoded));

    Ok(())
}
