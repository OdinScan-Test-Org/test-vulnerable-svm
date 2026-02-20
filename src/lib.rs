//! Vulnerable Token Vault -- intentionally insecure Solana program for testing.

pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, pubkey::Pubkey,
};

// Vuln #12: Hardcoded private key in source code
static ADMIN_PRIVATE_KEY: &str =
    "5K3YzMRAeLwUHKp2obczZ8pesM7RsGTz7CGKV4CVqzCGJMBHGkU2uiWmbPfSGJcN";

entrypoint!(process_instruction);

/// Program entrypoint.
fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    processor::process(program_id, accounts, instruction_data)
}
