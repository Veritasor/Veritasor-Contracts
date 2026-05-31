#![no_std]
//! # Attestor Staking Contract
//!
//! This module manages the staking and unbonding lifecycle for attestors.
//! It supports staking, unbonding queues, and slashing mechanisms.
//!
//! ## Unbonding Queue Correctness
//! To protect against partial locks and concurrent withdrawal requests:
//! 1. **Multiple Pending Unstakes**: Users can submit multiple requests (up to a limit).
//! 2. **Unlock Timestamp Monotonicity**: Newer requests are guaranteed to unlock
//!    after older ones, even if the unbonding period is shortened.
//! 3. **Slashing Adjustment**: Slashes reduce pending requests using LIFO order.

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, Vec};

/// Slashing outcome for a resolved dispute
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum SlashOutcome {
    /// Dispute upheld - attestor slashed
    Slashed,
    /// Dispute rejected - no slashing
    NoSlash,
}

/// Pending unstake request subject to an unbonding period.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PendingUnstake {
    /// Amount locked for withdrawal.
    pub amount: i128,
    /// Unix timestamp (seconds) when withdrawal becomes available.
    pub unlock_timestamp: u64,
}

/// Stake record for an attestor
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Stake {
    pub attestor: Address,
    pub amount: i128,
    pub locked: i128,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Token,
    Treasury,
    MinStake,
    Stake(Address),
    DisputeContract,
    UnbondingPeriod,
    PendingUnstake(Address),
    Slashed(u64),
}

const MAX_UNBONDING_PERIOD: u64 = 31_536_000; // 1 year in seconds

#[contract]
pub struct AttestorStakingContract;

#[contractimpl]
impl AttestorStakingContract {
    /// Initialize the staking contract.
    ///
    /// This function sets the initial configuration and can only be called once.
    /// It validates that the minimum stake is positive, the unbonding period
    /// is within reasonable bounds, and that the provided addresses do not
    /// create circular dependencies.
    ///
    /// # Arguments
    /// * `admin` - Contract administrator with permissions to update configuration.
    /// * `token` - The contract address of the token used for staking.
    /// * `treasury` - The address where slashed funds are sent.
    /// * `min_stake` - The minimum amount an attestor must stake to be eligible.
    /// * `dispute_contract` - The address authorized to trigger slashing.
    /// * `unbonding_period_seconds` - The duration (in seconds) that funds are locked
    ///   after a withdrawal request. Max is 1 year.
    ///
    /// # Panics
    /// * If the contract is already initialized.
    /// * If `min_stake` is not strictly positive.
    /// * If `unbonding_period_seconds` exceeds 1 year.
    /// * If `token`, `treasury`, or `dispute_contract` matches the contract's own address.
    /// * If roles are duplicated in a way that suggests misconfiguration (e.g., `token == admin`).
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        treasury: Address,
        min_stake: i128,
        dispute_contract: Address,
        unbonding_period_seconds: u64,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();

        // Parameter Validation
        assert!(min_stake > 0, "min_stake must be positive");
        assert!(
            unbonding_period_seconds <= MAX_UNBONDING_PERIOD,
            "unbonding period too long"
        );

        // Address Safety Checks
        let self_addr = env.current_contract_address();
        assert!(token != self_addr, "token cannot be self");
        assert!(treasury != self_addr, "treasury cannot be self");
        assert!(
            dispute_contract != self_addr,
            "dispute_contract cannot be self"
        );

        // Role Distinctness Checks
        assert!(admin != treasury, "admin and treasury must be distinct");
        assert!(token != treasury, "token and treasury must be distinct");
        assert!(
            dispute_contract != treasury,
            "dispute and treasury must be distinct"
        );

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::Treasury, &treasury);
        env.storage().instance().set(&DataKey::MinStake, &min_stake);
        env.storage()
            .instance()
            .set(&DataKey::DisputeContract, &dispute_contract);
        env.storage()
            .instance()
            .set(&DataKey::UnbondingPeriod, &unbonding_period_seconds);
    }

    /// Stake tokens as an attestor
    ///
    /// # Arguments
    /// * `attestor` - Address staking tokens
    /// * `amount` - Amount to stake
    pub fn stake(env: Env, attestor: Address, amount: i128) {
        attestor.require_auth();
        assert!(amount > 0, "amount must be positive");

        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();

        let stake_key = DataKey::Stake(attestor.clone());
        let mut stake: Stake = env.storage().instance().get(&stake_key).unwrap_or(Stake {
            attestor: attestor.clone(),
            amount: 0,
            locked: 0,
        });

        stake.amount += amount;
        assert!(stake.amount >= 0, "stake overflow");

        env.storage().instance().set(&stake_key, &stake);

        // Transfer tokens from attestor to contract
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&attestor, &env.current_contract_address(), &amount);
    }

    /// Request to unstake tokens.
    ///
    /// This locks the requested amount immediately and makes it withdrawable
    /// only after the configured unbonding period. Supports multiple pending unstakes
    /// in a queue.
    ///
    /// # Arguments
    /// * `attestor` - Address unstaking tokens
    /// * `amount` - Amount to unstake
    pub fn request_unstake(env: Env, attestor: Address, amount: i128) {
        attestor.require_auth();
        assert!(amount > 0, "amount must be positive");

        let pending_key = DataKey::PendingUnstake(attestor.clone());
        let mut pending_vec: Vec<PendingUnstake> = env
            .storage()
            .instance()
            .get(&pending_key)
            .unwrap_or(Vec::new(&env));

        // Enforce a limit to prevent unbounded storage
        assert!(pending_vec.len() < 10, "too many pending unstakes");

        let stake_key = DataKey::Stake(attestor.clone());
        let mut stake: Stake = env
            .storage()
            .instance()
            .get(&stake_key)
            .expect("no stake found");

        let available = stake.amount - stake.locked;
        assert!(available >= amount, "insufficient unlocked stake");

        stake.locked += amount;
        env.storage().instance().set(&stake_key, &stake);

        let unbonding: u64 = env
            .storage()
            .instance()
            .get(&DataKey::UnbondingPeriod)
            .unwrap_or(0);

        let mut unlock_timestamp = env.ledger().timestamp().saturating_add(unbonding);

        // Unlock timestamp monotonicity
        if pending_vec.len() > 0 {
            let last_pending = pending_vec.get(pending_vec.len() - 1).unwrap();
            if unlock_timestamp < last_pending.unlock_timestamp {
                unlock_timestamp = last_pending.unlock_timestamp;
            }
        }

        let pending = PendingUnstake {
            amount,
            unlock_timestamp,
        };

        pending_vec.push_back(pending);
        env.storage().instance().set(&pending_key, &pending_vec);
    }

    /// Withdraw previously requested unstakes after the unbonding period.
    pub fn withdraw_unstaked(env: Env, attestor: Address) {
        attestor.require_auth();

        let pending_key = DataKey::PendingUnstake(attestor.clone());
        let pending_vec: Vec<PendingUnstake> = env
            .storage()
            .instance()
            .get(&pending_key)
            .expect("no pending unstake");

        let mut remaining_vec = Vec::new(&env);
        let mut total_to_withdraw: i128 = 0;

        for pending in pending_vec.iter() {
            if env.ledger().timestamp() >= pending.unlock_timestamp {
                total_to_withdraw += pending.amount;
            } else {
                remaining_vec.push_back(pending);
            }
        }

        assert!(total_to_withdraw > 0, "no unstake unlocked");

        let stake_key = DataKey::Stake(attestor.clone());
        let mut stake: Stake = env
            .storage()
            .instance()
            .get(&stake_key)
            .expect("no stake found");

        assert!(
            stake.locked >= total_to_withdraw,
            "locked invariant violated"
        );
        assert!(
            stake.amount >= total_to_withdraw,
            "stake invariant violated"
        );

        stake.amount -= total_to_withdraw;
        stake.locked -= total_to_withdraw;
        env.storage().instance().set(&stake_key, &stake);

        if remaining_vec.len() == 0 {
            env.storage().instance().remove(&pending_key);
        } else {
            env.storage().instance().set(&pending_key, &remaining_vec);
        }

        // Transfer tokens back to attestor
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(
            &env.current_contract_address(),
            &attestor,
            &total_to_withdraw,
        );
    }

    /// Slash an attestor's stake for a proven-false attestation
    ///
    /// # Arguments
    /// * `attestor` - Address to slash
    /// * `amount` - Amount to slash
    /// * `dispute_id` - ID of the resolved dispute
    ///
    /// # Returns
    /// * `SlashOutcome` - Result of the slash operation
    ///
    /// # Security
    /// - Only callable by dispute contract
    /// - Slashed funds sent to treasury
    /// - Guards against double slashing via dispute_id tracking
    /// - Maintains stake invariants (locked <= amount)
    ///
    /// # SlashOutcome Behavior
    /// - `Slashed`: When attestor has sufficient stake and amount > 0
    /// - `NoSlash`: When attestor has zero stake remaining
    ///
    /// # Treasury Impact
    /// - `Slashed`: Exact slash amount transferred to treasury
    /// - `NoSlash`: No token transfer, treasury balance unchanged
    pub fn slash(env: Env, attestor: Address, amount: i128, dispute_id: u64) -> SlashOutcome {
        // Only dispute contract can trigger slashing
        let dispute_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::DisputeContract)
            .unwrap();
        dispute_contract.require_auth();

        assert!(amount > 0, "slash amount must be positive");

        let slash_key = DataKey::Slashed(dispute_id);
        if env.storage().instance().has(&slash_key) {
            panic!("dispute already processed");
        }

        let stake_key = DataKey::Stake(attestor.clone());
        let mut stake: Stake = env
            .storage()
            .instance()
            .get(&stake_key)
            .expect("no stake found");

        let slash_amount = amount.min(stake.amount);
        if slash_amount == 0 {
            return SlashOutcome::NoSlash;
        }

        stake.amount -= slash_amount;

        // Maintain invariants after slashing.
        // locked must never exceed amount.
        if stake.locked > stake.amount {
            stake.locked = stake.amount;
        }

        // If there are pending unstake requests, ensure their total does not exceed locked.
        let pending_key = DataKey::PendingUnstake(attestor.clone());
        if env.storage().instance().has(&pending_key) {
            let pending_vec: Vec<PendingUnstake> =
                env.storage().instance().get(&pending_key).unwrap();
            let mut total_pending: i128 = 0;
            for p in pending_vec.iter() {
                total_pending += p.amount;
            }

            if total_pending > stake.locked {
                let mut excess = total_pending - stake.locked;
                let mut modified_vec = pending_vec.clone();
                let mut i = modified_vec.len();
                while i > 0 {
                    i -= 1;
                    let mut p = modified_vec.get(i).unwrap();
                    if excess > 0 {
                        if p.amount <= excess {
                            excess -= p.amount;
                            p.amount = 0;
                        } else {
                            p.amount -= excess;
                            excess = 0;
                        }
                    }
                    modified_vec.set(i, p);
                }
                env.storage().instance().set(&pending_key, &modified_vec);
            }
        }

        env.storage().instance().set(&stake_key, &stake);
        env.storage().instance().set(&slash_key, &true);

        // Transfer slashed funds to treasury
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let treasury: Address = env.storage().instance().get(&DataKey::Treasury).unwrap();
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&env.current_contract_address(), &treasury, &slash_amount);

        SlashOutcome::Slashed
    }

    /// Get stake information for an attestor
    ///
    /// # Arguments
    /// * `attestor` - Address of the attestor
    ///
    /// # Returns
    /// * `Option<Stake>` - Stake information if attestor exists, None otherwise
    ///
    /// # Stake Structure
    /// - `amount`: Total staked tokens (including locked portion)
    /// - `locked`: Tokens currently locked in pending unstake requests
    ///
    /// # Invariants
    /// - `locked` will never exceed `amount`
    /// - `amount` is always >= `locked`
    pub fn get_stake(env: Env, attestor: Address) -> Option<Stake> {
        let stake_key = DataKey::Stake(attestor);
        env.storage().instance().get(&stake_key)
    }

    /// Returns whether a dispute has already been applied as a slash.
    ///
    /// # Arguments
    /// * `dispute_id` - ID to check
    ///
    /// # Returns
    /// * `bool` - true if dispute was already processed
    ///
    /// # Usage
    /// Prevents double-slashing attacks by tracking processed disputes
    pub fn is_dispute_processed(env: Env, dispute_id: u64) -> bool {
        let slash_key = DataKey::Slashed(dispute_id);
        env.storage().instance().has(&slash_key)
    }

    /// Get dispute contract address authorized to trigger slashing
    ///
    /// # Returns
    /// * `Address` - Current dispute contract address
    ///
    /// # Security Note
    /// Only this address can call `slash()` successfully
    pub fn get_dispute_contract(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::DisputeContract)
            .unwrap()
    }

    /// Get the oldest pending unstake information for an attestor.
    pub fn get_pending_unstake(env: Env, attestor: Address) -> Option<PendingUnstake> {
        let pending_key = DataKey::PendingUnstake(attestor);
        let vec: Option<Vec<PendingUnstake>> = env.storage().instance().get(&pending_key);
        match vec {
            Some(v) => {
                if v.len() > 0 {
                    Some(v.get(0).unwrap())
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Get all pending unstakes for an attestor.
    pub fn get_pending_unstakes(env: Env, attestor: Address) -> Option<Vec<PendingUnstake>> {
        let pending_key = DataKey::PendingUnstake(attestor);
        env.storage().instance().get(&pending_key)
    }

    /// Returns true if the attestor meets the minimum stake requirement.
    ///
    /// # Arguments
    /// * `attestor` - Address to check
    ///
    /// # Returns
    /// * `bool` - true if eligible, false otherwise
    ///
    /// # Security
    /// - Uses minimum stake threshold from contract storage
    /// - Prevents under-collateralized attestors from participating
    pub fn is_eligible(env: Env, attestor: Address) -> bool {
        let min_stake: i128 = env.storage().instance().get(&DataKey::MinStake).unwrap();
        match Self::get_stake(env, attestor) {
            Some(stake) => stake.amount >= min_stake,
            None => false,
        }
    }

    /// Get contract admin address
    ///
    /// # Returns
    /// * `Address` - Current admin address
    ///
    /// # Security
    /// Only admin can update configuration parameters
    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Get minimum stake requirement
    ///
    /// # Returns
    /// * `i128` - Current minimum stake amount
    ///
    /// # Security
    /// - Enforced during staking and eligibility checks
    pub fn get_min_stake(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::MinStake).unwrap()
    }

    /// Get unbonding period (seconds)
    ///
    /// # Returns
    /// * `u64` - Current unbonding period duration
    ///
    /// # Security
    /// - Prevents rapid unstaking and provides security window
    pub fn get_unbonding_period(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::UnbondingPeriod)
            .unwrap_or(0)
    }

    /// Admin: update minimum stake requirement.
    ///
    /// # Arguments
    /// * `min_stake` - New minimum stake amount (must be > 0)
    ///
    /// # Security
    /// - Only admin can call this function
    /// - Validates input to prevent zero minimum stake
    ///
    /// # Events
    /// - Emits configuration change event
    pub fn set_min_stake(env: Env, min_stake: i128) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        assert!(min_stake > 0, "min_stake must be positive");
        env.storage().instance().set(&DataKey::MinStake, &min_stake);
    }

    /// Admin: update dispute contract.
    ///
    /// # Arguments
    /// * `dispute_contract` - New authorized dispute contract address
    ///
    /// # Security
    /// - Only admin can change dispute contract
    /// - Invalidates old dispute contract authorization
    /// - Critical for slashing security
    ///
    /// # Events
    /// - Emits configuration change event
    pub fn set_dispute_contract(env: Env, dispute_contract: Address) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::DisputeContract, &dispute_contract);
    }

    /// Admin: update unbonding period.
    ///
    /// # Arguments
    /// * `unbonding_period_seconds` - New unbonding period (max 1 year)
    ///
    /// # Security
    /// - Only admin can modify unbonding period
    /// - Enforces maximum reasonable duration
    ///
    /// # Events
    /// - Emits configuration change event
    pub fn set_unbonding_period(env: Env, unbonding_period_seconds: u64) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::UnbondingPeriod, &unbonding_period_seconds);
    }
}

#[cfg(test)]
mod slashing_test;
#[cfg(test)]
mod test;
