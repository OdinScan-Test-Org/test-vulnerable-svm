//! State definitions for the vulnerable token vault.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

/// Vault state stored on-chain.
#[derive(BorshSerialize, BorshDeserialize, Debug, Default)]
pub struct VaultState {
    /// Whether this account has been initialized.
    pub is_initialized: bool,

    /// Authority that controls the vault.
    pub authority: Pubkey,

    /// Token mint address.
    pub token_mint: Pubkey,

    /// Total tokens deposited.
    pub total_deposited: u64,

    /// Reward rate (basis points).
    pub reward_rate: u64,

    /// PDA bump seed.
    pub bump: u8,
}

/// Per-user deposit record.
#[derive(BorshSerialize, BorshDeserialize, Debug, Default)]
pub struct UserRecord {
    /// Whether this record is initialized.
    pub is_initialized: bool,

    /// Owner of this record.
    pub owner: Pubkey,

    /// Amount deposited.
    pub deposited_amount: u64,

    /// Accumulated rewards.
    pub pending_rewards: u64,

    /// Last interaction slot.
    pub last_slot: u64,
}

impl VaultState {
    /// Size of the serialized vault state.
    pub const LEN: usize = 1 + 32 + 32 + 8 + 8 + 1;
}

impl UserRecord {
    /// Size of the serialized user record.
    pub const LEN: usize = 1 + 32 + 8 + 8 + 8;
}
