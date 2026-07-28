//! # Flat Fee Mechanism for Attestations
//!
//! This module implements a flat fee mechanism for the Veritasor attestation protocol.
//! Fees are collected in a specified token and sent to a collector address.
//!
//! ## Invariants
//! - If `enabled` is true and `amount > 0`, fee collection is mandatory.
//! - Insufficient balance will cause the transaction to panic, preventing
//!   unpaid attestations.
//! - DAO configuration overrides local contract configuration if set.

use soroban_sdk::{contracttype, token, Address, Env, Symbol, Val, Vec};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct FlatFeeConfig {
    /// Token contract used for fee payment.
    pub token: Address,
    /// Destination address that receives collected fees.
    pub collector: Address,
    /// Flat fee amount in the token's smallest unit.
    pub amount: i128,
    /// Master switch - when `false`, all flat fees are disabled.
    pub enabled: bool,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CollectorRotationProposal {
    /// Current collector address proposing the rotation.
    pub old_collector: Address,
    /// Proposed new collector address.
    pub new_collector: Address,
    /// Token contract used for the flat fee.
    pub token: Address,
    /// Amount of token transferred into escrow at proposal time.
    pub escrowed_amount: i128,
}

#[contracttype]
#[derive(Clone)]
pub enum FlatFeeDataKey {
    /// Core flat fee configuration (`FlatFeeConfig`).
    FlatFeeConfig,
    /// Protocol DAO contract address controlling fee configuration.
    Dao,
    /// Pending collector rotation proposal.
    CollectorRotationProposal,
}

/// Retrieve the current flat fee configuration from instance storage.
pub fn get_flat_fee_config(env: &Env) -> Option<FlatFeeConfig> {
    env.storage().instance().get(&FlatFeeDataKey::FlatFeeConfig)
}

/// Store a new flat fee configuration in instance storage.
pub fn set_flat_fee_config(env: &Env, config: &FlatFeeConfig) {
    env.storage()
        .instance()
        .set(&FlatFeeDataKey::FlatFeeConfig, config);
}

/// Read the pending collector rotation proposal.
pub fn get_collector_rotation_proposal(env: &Env) -> Option<CollectorRotationProposal> {
    env.storage()
        .instance()
        .get(&FlatFeeDataKey::CollectorRotationProposal)
}

/// Store the pending collector rotation proposal.
pub fn set_collector_rotation_proposal(env: &Env, proposal: &CollectorRotationProposal) {
    env.storage()
        .instance()
        .set(&FlatFeeDataKey::CollectorRotationProposal, proposal);
}

/// Remove any pending collector rotation proposal.
pub fn remove_collector_rotation_proposal(env: &Env) {
    env.storage()
        .instance()
        .remove(&FlatFeeDataKey::CollectorRotationProposal);
}

/// Returns true when a collector rotation proposal is pending.
pub fn has_pending_collector_rotation(env: &Env) -> bool {
    env.storage()
        .instance()
        .has(&FlatFeeDataKey::CollectorRotationProposal)
}

/// Set the Protocol DAO contract address.
pub fn set_dao(env: &Env, dao: &Address) {
    env.storage().instance().set(&FlatFeeDataKey::Dao, dao);
}

/// Get the Protocol DAO contract address if set.
pub fn get_dao(env: &Env) -> Option<Address> {
    env.storage().instance().get(&FlatFeeDataKey::Dao)
}

/// Returns the effective collector address for the flat fee config.
pub fn get_effective_flat_fee_collector(env: &Env) -> Option<Address> {
    get_effective_flat_fee_config(env).map(|config| config.collector)
}

/// Read the pending collector rotation proposal.
pub fn get_pending_collector_rotation(env: &Env) -> Option<CollectorRotationProposal> {
    get_collector_rotation_proposal(env)
}

/// Propose a new collector address and transfer existing collector-held fees into escrow.

/// The current collector must authorize this call. If the collector already held
/// a balance of the configured flat fee token, that balance is transferred into
/// the contract and held until the proposed new collector accepts.
pub fn propose_collector_rotation(
    env: &Env,
    caller: &Address,
    new_collector: &Address,
) {
    caller.require_auth();
    let config = get_flat_fee_config(env).expect("flat fee not configured");
    assert!(
        get_dao(env).is_none(),
        "collector rotation unavailable when DAO override is active"
    );
    assert!(
        !has_pending_collector_rotation(env),
        "collector rotation already pending"
    );
    assert!(
        caller == &config.collector,
        "only current collector may propose rotation"
    );

    let client = token::Client::new(env, &config.token);
    let escrowed_amount = client.balance(&config.collector);
    if escrowed_amount > 0 {
        client.transfer(&config.collector, &env.current_contract_address(), &escrowed_amount);
    }
    let proposal = CollectorRotationProposal {
        old_collector: config.collector.clone(),
        new_collector: new_collector.clone(),
        token: config.token.clone(),
        escrowed_amount,
    };
    set_collector_rotation_proposal(env, &proposal);
}

/// Accept a pending collector rotation and release escrowed funds to the new collector.
pub fn accept_collector_rotation(env: &Env, caller: &Address) {
    caller.require_auth();
    let proposal = get_collector_rotation_proposal(env)
        .expect("no pending collector rotation");
    assert!(
        caller == &proposal.new_collector,
        "only proposed new collector may accept rotation"
    );

    let mut config = get_flat_fee_config(env).expect("flat fee not configured");
    assert!(
        config.collector == proposal.old_collector,
        "collector configuration changed since proposal"
    );
    config.collector = proposal.new_collector.clone();
    set_flat_fee_config(env, &config);

    if proposal.escrowed_amount > 0 {
        let client = token::Client::new(env, &proposal.token);
        client.transfer(
            &env.current_contract_address(),
            &proposal.new_collector,
            &proposal.escrowed_amount,
        );
    }
    remove_collector_rotation_proposal(env);
}

/// Retrieve the effective flat fee configuration, checking DAO override first.
pub fn get_effective_flat_fee_config(env: &Env) -> Option<FlatFeeConfig> {
    if let Some(config) = get_flat_fee_config_from_dao(env) {
        return Some(config);
    }
    get_flat_fee_config(env)
}

fn get_flat_fee_config_from_dao(env: &Env) -> Option<FlatFeeConfig> {
    let dao = get_dao(env)?;
    let func = Symbol::new(env, "get_attestation_flat_fee_config");
    let args = Vec::<Val>::new(env);
    let opt: Option<(Address, Address, i128, bool)> = env.invoke_contract(&dao, &func, args);
    opt.map(|(token, collector, amount, enabled)| FlatFeeConfig {
        token,
        collector,
        amount,
        enabled,
    })
}

/// Calculate the flat fee to be paid.
///
/// Returns the amount from the effective configuration if enabled.
pub fn calculate_flat_fee(env: &Env) -> i128 {
    match get_effective_flat_fee_config(env) {
        Some(c) if c.enabled => c.amount,
        _ => 0,
    }
}

/// Collect the flat fee by transferring tokens from the payer to the collector.
///
/// # Panics
/// Panics if the payer has an insufficient balance or if the token transfer fails.
/// This ensures consistent accounting: no attestation can be recorded without
/// the required fee being successfully transferred.
///
/// # Returns
/// The amount of fee collected (0 if disabled or amount is 0).
pub fn collect_flat_fee(env: &Env, payer: &Address) -> i128 {
    let config = match get_effective_flat_fee_config(env) {
        Some(c) if c.enabled && c.amount > 0 => c,
        _ => return 0,
    };

    let client = token::Client::new(env, &config.token);

    // Explicit authorization check is handled by the caller or token contract.
    // If balance is insufficient, transfer will panic in the token contract.
    client.transfer(payer, &config.collector, &config.amount);

    config.amount
}
