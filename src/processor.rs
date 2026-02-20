//! Instruction processor for the vulnerable token vault.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke,
    pubkey::Pubkey,
};

use crate::error::VaultError;
use crate::instruction::VaultInstruction;
use crate::state::{UserRecord, VaultState};

/// Routes instruction to the appropriate handler.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Vuln #10: .unwrap() instead of proper error handling
    let instruction = VaultInstruction::try_from_slice(instruction_data).unwrap();

    match instruction {
        VaultInstruction::Initialize { bump } => process_initialize(program_id, accounts, bump),
        VaultInstruction::Deposit { amount } => process_deposit(program_id, accounts, amount),
        VaultInstruction::Withdraw { amount } => process_withdraw(program_id, accounts, amount),
        VaultInstruction::Transfer { amount } => process_transfer(program_id, accounts, amount),
        VaultInstruction::DistributeRewards => process_distribute_rewards(program_id, accounts),
        VaultInstruction::MintTokens { amount } => {
            process_mint_tokens(program_id, accounts, amount)
        }
    }
}

/// Initializes a new vault account.
///
/// Vuln #3: Uses user-supplied bump for PDA (bump seed manipulation).
/// Vuln #5: Writes to account without checking is_initialized (reinitialization).
fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    bump: u8,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault_info = next_account_info(account_iter)?;
    let authority_info = next_account_info(account_iter)?;

    // Vuln #3: create_program_address with user-supplied bump instead of find_program_address
    let _vault_pda = Pubkey::create_program_address(
        &[b"vault", authority_info.key.as_ref(), &[bump]],
        program_id,
    )?;

    // Vuln #5: No check for vault.is_initialized -- can reinitialize and overwrite authority
    let mut vault = VaultState::default();
    vault.is_initialized = true;
    vault.authority = *authority_info.key;
    vault.bump = bump;

    // Vuln #10: .unwrap() on serialization
    vault
        .serialize(&mut &mut vault_info.data.borrow_mut()[..])
        .unwrap();

    msg!("Vault initialized");
    Ok(())
}

/// Deposits tokens into the vault.
///
/// Vuln #2: No owner check on vault account before deserialization.
/// Vuln #6: Unchecked arithmetic on u64 values.
fn process_deposit(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault_info = next_account_info(account_iter)?;
    let user_token_info = next_account_info(account_iter)?;
    let vault_token_info = next_account_info(account_iter)?;
    let authority_info = next_account_info(account_iter)?;
    let token_program_info = next_account_info(account_iter)?;

    // Vuln #2: No check that vault_info.owner == program_id
    // Vuln #10: .unwrap() on deserialization
    let mut vault = VaultState::try_from_slice(&vault_info.data.borrow()).unwrap();

    // Vuln #6: Unchecked addition -- can overflow in release mode without overflow-checks
    vault.total_deposited = vault.total_deposited + amount;

    // CPI to transfer tokens from user to vault
    let transfer_ix = spl_token::instruction::transfer(
        token_program_info.key,
        user_token_info.key,
        vault_token_info.key,
        authority_info.key,
        &[],
        amount,
    )?;

    invoke(
        &transfer_ix,
        &[
            user_token_info.clone(),
            vault_token_info.clone(),
            authority_info.clone(),
            token_program_info.clone(),
        ],
    )?;

    vault
        .serialize(&mut &mut vault_info.data.borrow_mut()[..])
        .unwrap();

    msg!("Deposited {} tokens", amount);
    Ok(())
}

/// Withdraws tokens from the vault.
///
/// Vuln #1: Missing is_signer check on authority -- anyone can withdraw.
fn process_withdraw(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault_info = next_account_info(account_iter)?;
    let vault_token_info = next_account_info(account_iter)?;
    let user_token_info = next_account_info(account_iter)?;
    let authority_info = next_account_info(account_iter)?;
    let token_program_info = next_account_info(account_iter)?;

    // Vuln #1: No is_signer check on authority_info!
    // Anyone can pass any authority pubkey and withdraw funds.

    // Vuln #10: .unwrap() on deserialization
    let mut vault = VaultState::try_from_slice(&vault_info.data.borrow()).unwrap();

    // Vuln #6: Unchecked subtraction -- can underflow
    vault.total_deposited = vault.total_deposited - amount;

    let transfer_ix = spl_token::instruction::transfer(
        token_program_info.key,
        vault_token_info.key,
        user_token_info.key,
        authority_info.key,
        &[],
        amount,
    )?;

    invoke(
        &transfer_ix,
        &[
            vault_token_info.clone(),
            user_token_info.clone(),
            authority_info.clone(),
            token_program_info.clone(),
        ],
    )?;

    vault
        .serialize(&mut &mut vault_info.data.borrow_mut()[..])
        .unwrap();

    msg!("Withdrew {} tokens", amount);
    Ok(())
}

/// Transfers tokens between two user records.
///
/// Vuln #8: No duplicate account check -- from and to can be the same account.
fn process_transfer(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let _vault_info = next_account_info(account_iter)?;
    let from_record_info = next_account_info(account_iter)?;
    let to_record_info = next_account_info(account_iter)?;
    let _authority_info = next_account_info(account_iter)?;

    // Vuln #8: No check that from_record_info.key != to_record_info.key
    // If same account is passed for both, balance is corrupted after double borrow_mut

    // Vuln #10: .unwrap() on deserialization
    let mut from_record = UserRecord::try_from_slice(&from_record_info.data.borrow()).unwrap();
    let mut to_record = UserRecord::try_from_slice(&to_record_info.data.borrow()).unwrap();

    if from_record.deposited_amount < amount {
        return Err(VaultError::InsufficientFunds.into());
    }

    // Vuln #6: Unchecked arithmetic
    from_record.deposited_amount = from_record.deposited_amount - amount;
    to_record.deposited_amount = to_record.deposited_amount + amount;

    from_record
        .serialize(&mut &mut from_record_info.data.borrow_mut()[..])
        .unwrap();
    to_record
        .serialize(&mut &mut to_record_info.data.borrow_mut()[..])
        .unwrap();

    msg!("Transferred {} tokens", amount);
    Ok(())
}

/// Distributes rewards to all remaining accounts.
///
/// Vuln #9: Unbounded loop over remaining accounts with no length limit.
fn process_distribute_rewards(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault_info = next_account_info(account_iter)?;

    // Vuln #10: .unwrap() on deserialization
    let vault = VaultState::try_from_slice(&vault_info.data.borrow()).unwrap();
    let reward_per_user = vault.reward_rate;

    // Vuln #9: Unbounded loop -- iterates over ALL remaining accounts with no limit.
    // An attacker can pass thousands of accounts to consume compute budget.
    for account in account_iter {
        if account.data_len() >= UserRecord::LEN {
            let mut record = UserRecord::try_from_slice(&account.data.borrow()).unwrap();
            // Vuln #6: Unchecked addition
            record.pending_rewards = record.pending_rewards + reward_per_user;
            record
                .serialize(&mut &mut account.data.borrow_mut()[..])
                .unwrap();
        }
    }

    msg!("Rewards distributed");
    Ok(())
}

/// Mints new tokens.
///
/// Vuln #4: No verification of token program key -- attacker can pass fake program.
/// Vuln #7: No mint authority verification -- anyone can mint.
fn process_mint_tokens(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let mint_info = next_account_info(account_iter)?;
    let destination_info = next_account_info(account_iter)?;
    let mint_authority_info = next_account_info(account_iter)?;
    let token_program_info = next_account_info(account_iter)?;

    // Vuln #4: No check that token_program_info.key == spl_token::id()
    // An attacker can pass a fake program that always succeeds

    // Vuln #7: No verification that mint_authority_info matches expected authority
    // Anyone can claim to be the mint authority

    let mint_ix = spl_token::instruction::mint_to(
        token_program_info.key,
        mint_info.key,
        destination_info.key,
        mint_authority_info.key,
        &[],
        amount,
    )?;

    invoke(
        &mint_ix,
        &[
            mint_info.clone(),
            destination_info.clone(),
            mint_authority_info.clone(),
            token_program_info.clone(),
        ],
    )?;

    msg!("Minted {} tokens", amount);
    Ok(())
}
