#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

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
}

#[contract]
pub struct AttestorStakingContract;

#[contractimpl]
impl AttestorStakingContract {
    /// Initialize the staking contract
    ///
    /// # Arguments
    /// * `admin` - Contract administrator
    /// * `token` - Token contract address for staking
    /// * `treasury` - Address to receive slashed funds
    /// * `min_stake` - Minimum stake required for attestors
    /// * `dispute_contract` - Dispute resolution contract address
    /// * `unbonding_period_seconds` - Time lock before unstake withdrawal is available
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
        assert!(min_stake > 0, "min_stake must be positive");

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
    /// only after the configured unbonding period.
    ///
    /// # Arguments
    /// * `attestor` - Address unstaking tokens
    /// * `amount` - Amount to unstake
    pub fn request_unstake(env: Env, attestor: Address, amount: i128) {
        attestor.require_auth();
        assert!(amount > 0, "amount must be positive");

        let pending_key = DataKey::PendingUnstake(attestor.clone());
        assert!(!env.storage().instance().has(&pending_key), "pending unstake exists");

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
        let unlock_timestamp = env.ledger().timestamp().saturating_add(unbonding);
        let pending = PendingUnstake {
            amount,
            unlock_timestamp,
        };
        env.storage().instance().set(&pending_key, &pending);
    }

    /// Withdraw previously requested unstake after the unbonding period.
    pub fn withdraw_unstaked(env: Env, attestor: Address) {
        attestor.require_auth();

        let pending_key = DataKey::PendingUnstake(attestor.clone());
        let pending: PendingUnstake = env
            .storage()
            .instance()
            .get(&pending_key)
            .expect("no pending unstake");
        assert!(
            env.ledger().timestamp() >= pending.unlock_timestamp,
            "unstake not yet unlocked"
        );

        let stake_key = DataKey::Stake(attestor.clone());
        let mut stake: Stake = env
            .storage()
            .instance()
            .get(&stake_key)
            .expect("no stake found");
        assert!(stake.locked >= pending.amount, "locked invariant violated");
        assert!(stake.amount >= pending.amount, "stake invariant violated");

        stake.amount -= pending.amount;
        stake.locked -= pending.amount;
        env.storage().instance().set(&stake_key, &stake);
        env.storage().instance().remove(&pending_key);

        // Transfer tokens back to attestor
        let token: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&env.current_contract_address(), &attestor, &pending.amount);
    }

    /// Slash an attestor's stake for a proven-false attestation
    ///
    /// # Arguments
    /// * `attestor` - Address to slash
    /// * `amount` - Amount to slash
    /// * `dispute_id` - ID of the resolved dispute
    ///
    /// # Security
    /// - Only callable by dispute contract
    /// - Slashed funds sent to treasury
    /// - Guards against double slashing via dispute_id tracking
    pub fn slash(env: Env, attestor: Address, amount: i128, dispute_id: u64) -> SlashOutcome {
        // Only dispute contract can trigger slashing
        let dispute_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::DisputeContract)
            .unwrap();
        dispute_contract.require_auth();

        assert!(amount > 0, "slash amount must be positive");

        // Check for double slashing using contracttype-compatible key
        #[contracttype]
        #[derive(Clone)]
        enum SlashKey {
            Slashed(u64),
        }

        let slash_key = SlashKey::Slashed(dispute_id);
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

        // If there is a pending unstake request, ensure it does not exceed locked.
        let pending_key = DataKey::PendingUnstake(attestor.clone());
        if env.storage().instance().has(&pending_key) {
            let mut pending: PendingUnstake = env.storage().instance().get(&pending_key).unwrap();
            if pending.amount > stake.locked {
                pending.amount = stake.locked;
                env.storage().instance().set(&pending_key, &pending);
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
    pub fn get_stake(env: Env, attestor: Address) -> Option<Stake> {
        let stake_key = DataKey::Stake(attestor);
        env.storage().instance().get(&stake_key)
    }

    /// Get pending unstake information for an attestor.
    pub fn get_pending_unstake(env: Env, attestor: Address) -> Option<PendingUnstake> {
        let pending_key = DataKey::PendingUnstake(attestor);
        env.storage().instance().get(&pending_key)
    }

    /// Returns true if the attestor meets the minimum stake requirement.
    pub fn is_eligible(env: Env, attestor: Address) -> bool {
        let min_stake: i128 = env.storage().instance().get(&DataKey::MinStake).unwrap();
        match Self::get_stake(env, attestor) {
            Some(stake) => stake.amount >= min_stake,
            None => false,
        }
    }

    /// Get contract admin
    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    /// Get minimum stake requirement
    pub fn get_min_stake(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::MinStake).unwrap()
    }

    /// Get unbonding period (seconds).
    pub fn get_unbonding_period(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::UnbondingPeriod)
            .unwrap_or(0)
    }

    /// Admin: update minimum stake requirement.
    pub fn set_min_stake(env: Env, min_stake: i128) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        assert!(min_stake > 0, "min_stake must be positive");
        env.storage().instance().set(&DataKey::MinStake, &min_stake);
    }

    /// Admin: update dispute contract.
    pub fn set_dispute_contract(env: Env, dispute_contract: Address) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::DisputeContract, &dispute_contract);
    }

    /// Admin: update unbonding period.
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
