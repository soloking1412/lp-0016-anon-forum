#![no_main]

use borsh::{BorshDeserialize, BorshSerialize};
use forum_anon_registry::{process, Instruction};
use forum_anon_types::RegistryState;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    // Inputs are borsh-encoded: state bytes first, then instruction bytes.
    let state_bytes: Vec<u8>       = env::read();
    let instruction_bytes: Vec<u8> = env::read();

    let mut state: RegistryState =
        RegistryState::try_from_slice(&state_bytes).expect("deserialize state");
    let instruction: Instruction =
        Instruction::try_from_slice(&instruction_bytes).expect("deserialize instruction");

    process(&mut state, instruction).expect("instruction failed");

    env::commit_slice(&borsh::to_vec(&state).expect("serialize state"));
}
