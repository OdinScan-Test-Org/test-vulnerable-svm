//! Instruction definitions for the vulnerable token vault.

use borsh::{BorshDeserialize, BorshSerialize};

/// Instructions supported by the token vault program.
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum VaultInstruction {
    /// Initializes a new vault account.
    /// Accounts expected:
    /// 0. `[writable]` Vault account
    /// 1. `[]` Authority
    /// 2. `[]` System program
    Initialize {
        /// Bump seed for PDA derivation.
        bump: u8,
    },

    /// Deposits tokens into the vault.
    /// Accounts expected:
    /// 0. `[writable]` Vault account
    /// 1. `[writable]` User token account (source)
    /// 2. `[writable]` Vault token account (destination)
    /// 3. `[signer]` User authority
    /// 4. `[]` Token program
    Deposit {
        /// Amount to deposit.
        amount: u64,
    },

    /// Withdraws tokens from the vault.
    /// Accounts expected:
    /// 0. `[writable]` Vault account
    /// 1. `[writable]` Vault token account (source)
    /// 2. `[writable]` User token account (destination)
    /// 3. `[]` Authority
    /// 4. `[]` Token program
    Withdraw {
        /// Amount to withdraw.
        amount: u64,
    },

    /// Transfers tokens between two users.
    /// Accounts expected:
    /// 0. `[writable]` Vault account
    /// 1. `[writable]` Sender record
    /// 2. `[writable]` Receiver record
    /// 3. `[]` Authority
    Transfer {
        /// Amount to transfer.
        amount: u64,
    },

    /// Distributes rewards to all remaining accounts.
    /// Accounts expected:
    /// 0. `[writable]` Vault account
    /// 1+ `[writable]` Recipient accounts
    DistributeRewards,

    /// Mints new tokens (admin only -- but missing signer check).
    /// Accounts expected:
    /// 0. `[]` Mint account
    /// 1. `[writable]` Destination token account
    /// 2. `[]` Mint authority
    /// 3. `[]` Token program
    MintTokens {
        /// Amount to mint.
        amount: u64,
    },
}
