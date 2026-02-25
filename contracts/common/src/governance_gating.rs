
use soroban_sdk::{contracttype, token, Address, Env, Vec};

// ════════════════════════════════════════════════════════════════════
//  Storage Types
// ════════════════════════════════════════════════════════════════════

/// Storage keys for governance state
#[contracttype]
#[derive(Clone)]
pub enum GovernanceKey {
    /// Governance token contract address
    GovernanceToken,
    /// Minimum token balance required for governance actions
    GovernanceThreshold,
    /// Delegated voting power: delegator -> delegate
    Delegation(Address),
    /// Total voting power delegated to an address
    DelegatedPower(Address),
    /// Governance enabled flag
    GovernanceEnabled,
}

/// Governance configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct GovernanceConfig {
    /// Token contract address
    pub token: Address,
    /// Minimum token balance required for governance actions
    pub threshold: i128,
    /// Whether governance is enabled
    pub enabled: bool,
}

// ════════════════════════════════════════════════════════════════════
//  Configuration
// ════════════════════════════════════════════════════════════════════

/// Initialize governance with token and threshold.
///
/// # Parameters
/// - `token`: Governance token contract address
/// - `threshold`: Minimum token balance required for governance actions
/// - `enabled`: Whether governance is enabled from the start
///
/// # Panics
/// - If governance is already initialized
/// - If threshold is negative
pub fn initialize_governance(env: &Env, token: &Address, threshold: i128, enabled: bool) {
    if env
        .storage()
        .instance()
        .has(&GovernanceKey::GovernanceToken)
    {
        panic!("governance already initialized");
    }
    assert!(threshold >= 0, "threshold must be non-negative");

    let config = GovernanceConfig {
        token: token.clone(),
        threshold,
        enabled,
    };

    env.storage()
        .instance()
        .set(&GovernanceKey::GovernanceToken, token);
    env.storage()
        .instance()
        .set(&GovernanceKey::GovernanceThreshold, &threshold);
    env.storage()
        .instance()
        .set(&GovernanceKey::GovernanceEnabled, &enabled);
}

/// Get the current governance configuration.
pub fn get_governance_config(env: &Env) -> Option<GovernanceConfig> {
    let token = env
        .storage()
        .instance()
        .get(&GovernanceKey::GovernanceToken)?;
    let threshold = env
        .storage()
        .instance()
        .get(&GovernanceKey::GovernanceThreshold)?;
    let enabled = env
        .storage()
        .instance()
        .get(&GovernanceKey::GovernanceEnabled)
        .unwrap_or(false);

    Some(GovernanceConfig {
        token,
        threshold,
        enabled,
    })
}

/// Update governance threshold.
///
/// # Panics
/// - If governance is not initialized
/// - If threshold is negative
pub fn set_governance_threshold(env: &Env, threshold: i128) {
    assert!(
        env.storage()
            .instance()
            .has(&GovernanceKey::GovernanceToken),
        "governance not initialized"
    );
    assert!(threshold >= 0, "threshold must be non-negative");

    env.storage()
        .instance()
        .set(&GovernanceKey::GovernanceThreshold, &threshold);
}

/// Enable or disable governance.
pub fn set_governance_enabled(env: &Env, enabled: bool) {
    assert!(
        env.storage()
            .instance()
            .has(&GovernanceKey::GovernanceToken),
        "governance not initialized"
    );

    env.storage()
        .instance()
        .set(&GovernanceKey::GovernanceEnabled, &enabled);
}

// ════════════════════════════════════════════════════════════════════
//  Voting Power & Delegation
// ════════════════════════════════════════════════════════════════════

/// Get the total voting power of an address (balance + delegated power).
///
/// # Returns
/// - Token balance + sum of delegated voting power
pub fn get_voting_power(env: &Env, address: &Address) -> i128 {
    let config = match get_governance_config(env) {
        Some(c) => c,
        None => return 0,
    };

    let token_client = token::Client::new(env, &config.token);
    let balance = token_client.balance(address);

    let delegated = env
        .storage()
        .instance()
        .get(&GovernanceKey::DelegatedPower(address.clone()))
        .unwrap_or(0i128);

    balance + delegated
}

/// Delegate voting power to another address.
///
/// # Parameters
/// - `delegator`: Address delegating their voting power
/// - `delegate`: Address receiving the delegated voting power
///
/// # Notes
/// - Delegator must authorize the transaction
/// - Previous delegation is automatically revoked
/// - Delegation does not transfer tokens, only voting power
pub fn delegate_voting_power(env: &Env, delegator: &Address, delegate: &Address) {
    delegator.require_auth();

    let config = get_governance_config(env).expect("governance not initialized");

    // Get delegator's token balance
    let token_client = token::Client::new(env, &config.token);
    let balance = token_client.balance(delegator);

    // Revoke previous delegation if exists
    if let Some(old_delegate) = env
        .storage()
        .instance()
        .get::<GovernanceKey, Address>(&GovernanceKey::Delegation(delegator.clone()))
    {
        let old_power: i128 = env
            .storage()
            .instance()
            .get(&GovernanceKey::DelegatedPower(old_delegate.clone()))
            .unwrap_or(0);
        env.storage().instance().set(
            &GovernanceKey::DelegatedPower(old_delegate),
            &(old_power - balance),
        );
    }

    // Set new delegation
    env.storage()
        .instance()
        .set(&GovernanceKey::Delegation(delegator.clone()), delegate);

    // Update delegate's voting power
    let current_power: i128 = env
        .storage()
        .instance()
        .get(&GovernanceKey::DelegatedPower(delegate.clone()))
        .unwrap_or(0);
    env.storage().instance().set(
        &GovernanceKey::DelegatedPower(delegate.clone()),
        &(current_power + balance),
    );
}

/// Revoke voting power delegation.
///
/// # Parameters
/// - `delegator`: Address revoking their delegation
///
/// # Notes
/// - Delegator must authorize the transaction
pub fn revoke_delegation(env: &Env, delegator: &Address) {
    delegator.require_auth();

    let delegate: Option<Address> = env
        .storage()
        .instance()
        .get(&GovernanceKey::Delegation(delegator.clone()));

    if let Some(delegate) = delegate {
        let config = get_governance_config(env).expect("governance not initialized");
        let token_client = token::Client::new(env, &config.token);
        let balance = token_client.balance(delegator);

        // Update delegate's voting power
        let current_power: i128 = env
            .storage()
            .instance()
            .get(&GovernanceKey::DelegatedPower(delegate.clone()))
            .unwrap_or(0);
        env.storage().instance().set(
            &GovernanceKey::DelegatedPower(delegate),
            &(current_power - balance),
        );

        // Remove delegation
        env.storage()
            .instance()
            .remove(&GovernanceKey::Delegation(delegator.clone()));
    }
}

/// Get the address that a delegator has delegated to.
pub fn get_delegate(env: &Env, delegator: &Address) -> Option<Address> {
    env.storage()
        .instance()
        .get(&GovernanceKey::Delegation(delegator.clone()))
}

// ════════════════════════════════════════════════════════════════════
//  Access Control
// ════════════════════════════════════════════════════════════════════

/// Check if an address meets the governance threshold.
///
/// # Returns
/// - `true` if governance is disabled OR address has sufficient voting power
/// - `false` otherwise
pub fn has_governance_power(env: &Env, address: &Address) -> bool {
    let config = match get_governance_config(env) {
        Some(c) => c,
        None => return false,
    };

    if !config.enabled {
        return false;
    }

    get_voting_power(env, address) >= config.threshold
}

/// Require that an address meets the governance threshold.
///
/// # Panics
/// - If governance is enabled and address does not have sufficient voting power
pub fn require_governance_threshold(env: &Env, address: &Address) {
    address.require_auth();

    let config = match get_governance_config(env) {
        Some(c) => c,
        None => return, // No governance configured, allow operation
    };

    if !config.enabled {
        return; // Governance disabled, allow operation
    }

    let voting_power = get_voting_power(env, address);
    assert!(
        voting_power >= config.threshold,
        "insufficient governance voting power: {} < {}",
        voting_power,
        config.threshold
    );
}

/// Check if governance is initialized and enabled.
pub fn is_governance_enabled(env: &Env) -> bool {
    get_governance_config(env)
        .map(|c| c.enabled)
        .unwrap_or(false)
}
