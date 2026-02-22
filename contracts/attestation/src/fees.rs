//! # Flat Fee Mechanism for Attestations
//! 
//! This module implements a simple flat fee mechanism for the Veritasor attestation protocol.
//! Fees are collected in a specified token and sent to a treasury address.

use soroban_sdk::{contracttype, token, Address, Env};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct FlatFeeConfig {
    /// Token contract used for fee payment.
    pub token: Address,
    /// Destination address that receives collected fees.
    pub treasury: Address,
    /// Flat fee amount in the token's smallest unit.
    pub amount: i128,
    /// Master switch - when `false`, all flat fees are disabled.
    pub enabled: bool,
}

#[contracttype]
#[derive(Clone)]
pub enum FlatFeeDataKey {
    /// Core flat fee configuration (`FlatFeeConfig`).
    FlatFeeConfig,
}

/// Retrieve the current flat fee configuration from instance storage.
/// 
/// # Arguments
/// * `env` - The Soroban environment.
/// 
/// # Returns
/// * `Option<FlatFeeConfig>` - The stored configuration if it exists.
pub fn get_flat_fee_config(env: &Env) -> Option<FlatFeeConfig> {
    env.storage().instance().get(&FlatFeeDataKey::FlatFeeConfig)
}

/// Store a new flat fee configuration in instance storage.
/// 
/// # Arguments
/// * `env` - The Soroban environment.
/// * `config` - The flat fee configuration to store.
pub fn set_flat_fee_config(env: &Env, config: &FlatFeeConfig) {
    env.storage().instance().set(&FlatFeeDataKey::FlatFeeConfig, config);
}

/// Collect the flat fee by transferring tokens from the payer to the treasury.
/// 
/// # Arguments
/// * `env` - The Soroban environment.
/// * `payer` - The address of the party paying the fee.
/// 
/// # Returns
/// * `i128` - The amount of fee collected (0 if disabled or amount is 0).
pub fn collect_flat_fee(env: &Env, payer: &Address) -> i128 {
    let config = match get_flat_fee_config(env) {
        Some(c) if c.enabled && c.amount > 0 => c,
        _ => return 0,
    };

    let client = token::Client::new(env, &config.token);
    client.transfer(payer, &config.treasury, &config.amount);

    config.amount
}
