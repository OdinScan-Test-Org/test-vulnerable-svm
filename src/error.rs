//! Error types for the vulnerable token vault program.

use solana_program::program_error::ProgramError;
use thiserror::Error;

/// Custom error types for the token vault.
#[derive(Error, Debug)]
pub enum VaultError {
    /// Account is already initialized.
    #[error("Account already initialized")]
    AlreadyInitialized,

    /// Account is not initialized.
    #[error("Account not initialized")]
    NotInitialized,

    /// Insufficient funds for withdrawal.
    #[error("Insufficient funds")]
    InsufficientFunds,

    /// Invalid instruction data.
    #[error("Invalid instruction")]
    InvalidInstruction,

    /// Arithmetic overflow.
    #[error("Arithmetic overflow")]
    Overflow,

    /// Invalid account provided.
    #[error("Invalid account")]
    InvalidAccount,
}

impl From<VaultError> for ProgramError {
    fn from(e: VaultError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
