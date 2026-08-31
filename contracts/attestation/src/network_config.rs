//! # Local Network Configuration
//!
//! Minimal on-chain network configuration used by the archival
//! lazy-rehydration read path (`get_attestation` / `get_business_attestations`)
//! to size persistent-storage TTL extensions.
//!
//! No configuration can currently be written from this contract, so the
//! defaults below always apply. They match the persistent-entry TTL bounds
//! used across the test-suite `LedgerInfo` fixtures (`min 10`, `max
//! 3_110_400` ledgers).

use soroban_sdk::Env;

/// Persistent-storage TTL bounds applied when rehydrating archived entries.
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkConfig {
    /// Minimum TTL (in ledgers) applied when extending persistent entries.
    pub min_persistent_entry_ttl: u32,
    /// Maximum TTL (in ledgers) allowed when extending persistent entries.
    pub max_entry_ttl: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            min_persistent_entry_ttl: 10,
            max_entry_ttl: 3_110_400,
        }
    }
}

/// Read the current network configuration.
///
/// Always returns the default configuration because this contract does not
/// expose a setter; the values are stable across the lifetime of a deployment.
pub fn get_config(_env: &Env) -> NetworkConfig {
    NetworkConfig::default()
}
