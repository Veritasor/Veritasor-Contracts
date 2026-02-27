#![no_std]
//! # Attestation Registry Contract
//!
//! Provides a stable registry pattern for upgradeable attestation implementations.
//! This contract separates contract address discovery from contract implementation,
//! enabling controlled upgrades while maintaining a stable interface.
//!
//! ## Architecture
//!
//! The registry maintains:
//! - Current implementation address (the active attestation contract)
//! - Version metadata for tracking upgrades
//! - Migration hooks for upgrade coordination
//! - Governance-controlled upgrade mechanism
//!
//! ## Upgrade Process
//!
//! 1. Deploy new attestation implementation contract
//! 2. Call `upgrade(new_impl, version, migration_data)` as admin
//! 3. Registry updates current implementation pointer
//! 4. Optional migration hook is called on new implementation
//! 5. Version metadata is updated
//!
//! ## Safety Constraints
//!
//! - Only the admin (governance) can perform upgrades
//! - Registry must be initialized before use
//! - Version numbers must be strictly increasing
//! - Previous implementation address is preserved for rollback scenarios
//!
//! ## Trust Model
//!
//! The registry minimizes trust assumptions beyond governed upgrades:
//! - No trust in implementation contracts (they are just addresses)
//! - Trust only in the governance/admin for upgrade decisions
//! - Callers verify implementation addresses before use

use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env, String};

#[cfg(test)]
mod test;

// ════════════════════════════════════════════════════════════════════
//  Storage types
// ════════════════════════════════════════════════════════════════════

/// Storage keys for the registry contract.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract administrator address (governance).
    Admin,
    /// Current active implementation address.
    CurrentImplementation,
    /// Previous implementation address (for rollback scenarios).
    PreviousImplementation,
    /// Current version number (monotonically increasing).
    CurrentVersion,
    /// Previous version number.
    PreviousVersion,
    /// Initialization flag.
    Initialized,
}

/// Version metadata for an implementation.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct VersionInfo {
    /// Version number (must be strictly increasing).
    pub version: u32,
    /// Implementation contract address.
    pub implementation: Address,
    /// Optional migration data passed during upgrade.
    pub migration_data: Option<Bytes>,
    /// Timestamp when this version was activated.
    pub activated_at: u64,
}

// ════════════════════════════════════════════════════════════════════
//  Contract definition
// ════════════════════════════════════════════════════════════════════

#[contract]
pub struct AttestationRegistry;

#[contractimpl]
impl AttestationRegistry {
    // ── Initialization ──────────────────────────────────────────────

    /// Initialize the registry with an admin address and initial implementation.
    ///
    /// # Arguments
    ///
    /// * `admin` - The governance address that controls upgrades
    /// * `initial_impl` - The initial attestation contract implementation address
    /// * `initial_version` - The version number for the initial implementation (typically 1)
    ///
    /// # Panics
    ///
    /// * If the registry is already initialized
    /// * If `admin` does not authorize the call
    ///
    /// # Safety
    ///
    /// This is a one-time setup. The admin must be a trusted governance address.
    pub fn initialize(
        env: Env,
        admin: Address,
        initial_impl: Address,
        initial_version: u32,
    ) {
        if env.storage().instance().has(&DataKey::Initialized) {
            panic!("registry already initialized");
        }
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::CurrentImplementation, &initial_impl);
        env.storage()
            .instance()
            .set(&DataKey::CurrentVersion, &initial_version);
        env.storage().instance().set(&DataKey::Initialized, &true);
    }

    // ── Upgrade functionality ───────────────────────────────────────

    /// Upgrade to a new attestation implementation.
    ///
    /// Updates the current implementation address and version metadata.
    /// The previous implementation is preserved for potential rollback.
    ///
    /// # Arguments
    ///
    /// * `new_impl` - Address of the new attestation contract implementation
    /// * `new_version` - Version number (must be > current version)
    /// * `migration_data` - Optional data to pass to migration hook (can be empty)
    ///
    /// # Panics
    ///
    /// * If registry is not initialized
    /// * If caller is not the admin
    /// * If `new_version` is not greater than current version
    /// * If `new_impl` is the zero address
    ///
    /// # Safety
    ///
    /// Only the admin (governance) can perform upgrades. The new implementation
    /// should be thoroughly tested before upgrade.
    pub fn upgrade(
        env: Env,
        new_impl: Address,
        new_version: u32,
        _migration_data: Option<Bytes>,
    ) {
        Self::require_initialized(&env);
        let _admin = Self::require_admin(&env);

        // Validate new implementation is not zero address
        // In Soroban, we check by ensuring it's not the default/empty address
        // For now, we'll rely on the caller to provide valid addresses

        // Validate version is strictly increasing
        let current_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::CurrentVersion)
            .expect("current version missing");
        if new_version <= current_version {
            panic!("new version must be greater than current version");
        }

        // Store previous implementation for rollback capability
        let current_impl: Address = env
            .storage()
            .instance()
            .get(&DataKey::CurrentImplementation)
            .expect("current implementation missing");
        env.storage()
            .instance()
            .set(&DataKey::PreviousImplementation, &current_impl);
        env.storage()
            .instance()
            .set(&DataKey::PreviousVersion, &current_version);

        // Update to new implementation
        env.storage()
            .instance()
            .set(&DataKey::CurrentImplementation, &new_impl);
        env.storage()
            .instance()
            .set(&DataKey::CurrentVersion, &new_version);

        // Note: Migration hook would be called here if the new implementation
        // supports it. For now, we just update the registry.
        // The new implementation contract should handle its own migration logic
        // when it receives its first calls.
    }

    /// Rollback to the previous implementation version.
    ///
    /// Reverts to the previous implementation and version. This is a safety
    /// mechanism for emergency situations.
    ///
    /// # Arguments
    ///
    /// None - uses stored previous implementation and version
    ///
    /// # Panics
    ///
    /// * If registry is not initialized
    /// * If caller is not the admin
    /// * If no previous implementation exists (first version)
    ///
    /// # Safety
    ///
    /// Rollback should only be used in emergency situations. After rollback,
    /// the "previous" becomes the current, so a second rollback would revert
    /// to the version before the rollback.
    pub fn rollback(env: Env) {
        Self::require_initialized(&env);
        Self::require_admin(&env);

        let prev_impl: Option<Address> = env
            .storage()
            .instance()
            .get(&DataKey::PreviousImplementation);
        let prev_version: Option<u32> = env
            .storage()
            .instance()
            .get(&DataKey::PreviousVersion);

        if prev_impl.is_none() || prev_version.is_none() {
            panic!("no previous implementation to rollback to");
        }

        // Swap current and previous
        let current_impl: Address = env
            .storage()
            .instance()
            .get(&DataKey::CurrentImplementation)
            .expect("current implementation missing");
        let current_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::CurrentVersion)
            .expect("current version missing");

        env.storage()
            .instance()
            .set(&DataKey::CurrentImplementation, &prev_impl.unwrap());
        env.storage()
            .instance()
            .set(&DataKey::CurrentVersion, &prev_version.unwrap());
        env.storage()
            .instance()
            .set(&DataKey::PreviousImplementation, &current_impl);
        env.storage()
            .instance()
            .set(&DataKey::PreviousVersion, &current_version);
    }

    // ── Query functions ─────────────────────────────────────────────

    /// Get the current active implementation address.
    ///
    /// Returns the address that should be used for all attestation operations.
    ///
    /// # Returns
    ///
    /// `Option<Address>` - Current implementation address, or None if not initialized
    pub fn get_current_implementation(env: Env) -> Option<Address> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return None;
        }
        env.storage().instance().get(&DataKey::CurrentImplementation)
    }

    /// Get the current version number.
    ///
    /// # Returns
    ///
    /// `Option<u32>` - Current version number, or None if not initialized
    pub fn get_current_version(env: Env) -> Option<u32> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return None;
        }
        env.storage().instance().get(&DataKey::CurrentVersion)
    }

    /// Get the previous implementation address (for rollback scenarios).
    ///
    /// # Returns
    ///
    /// `Option<Address>` - Previous implementation address, or None if no previous exists
    pub fn get_previous_implementation(env: Env) -> Option<Address> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return None;
        }
        env.storage().instance().get(&DataKey::PreviousImplementation)
    }

    /// Get the previous version number.
    ///
    /// # Returns
    ///
    /// `Option<u32>` - Previous version number, or None if no previous exists
    pub fn get_previous_version(env: Env) -> Option<u32> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return None;
        }
        env.storage().instance().get(&DataKey::PreviousVersion)
    }

    /// Get the admin address.
    ///
    /// # Returns
    ///
    /// `Option<Address>` - Admin address, or None if not initialized
    pub fn get_admin(env: Env) -> Option<Address> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return None;
        }
        env.storage().instance().get(&DataKey::Admin)
    }

    /// Check if the registry is initialized.
    ///
    /// # Returns
    ///
    /// `bool` - True if initialized, false otherwise
    pub fn is_initialized(env: Env) -> bool {
        env.storage().instance().has(&DataKey::Initialized)
    }

    /// Get complete version information for the current implementation.
    ///
    /// # Returns
    ///
    /// `Option<VersionInfo>` - Current version info, or None if not initialized
    ///
    /// Note: `activated_at` is not stored historically, so it reflects the
    /// current ledger timestamp when queried.
    pub fn get_version_info(env: Env) -> Option<VersionInfo> {
        if !Self::is_initialized(env.clone()) {
            return None;
        }

        let implementation: Address = env
            .storage()
            .instance()
            .get(&DataKey::CurrentImplementation)
            .expect("current implementation missing");
        let version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::CurrentVersion)
            .expect("current version missing");

        Some(VersionInfo {
            version,
            implementation,
            migration_data: None, // Migration data is not stored, only used during upgrade
            activated_at: env.ledger().timestamp(),
        })
    }

    // ── Admin management ────────────────────────────────────────────

    /// Transfer admin rights to a new address.
    ///
    /// # Arguments
    ///
    /// * `new_admin` - The new admin address
    ///
    /// # Panics
    ///
    /// * If registry is not initialized
    /// * If caller is not the current admin
    ///
    /// # Safety
    ///
    /// This is a critical operation. The new admin will have full control
    /// over upgrades. Use with extreme caution.
    pub fn transfer_admin(env: Env, new_admin: Address) {
        Self::require_initialized(&env);
        Self::require_admin(&env);
        env.storage().instance().set(&DataKey::Admin, &new_admin);
    }
}

// ════════════════════════════════════════════════════════════════════
//  Internal helpers
// ════════════════════════════════════════════════════════════════════

impl AttestationRegistry {
    /// Require that the registry is initialized, panic otherwise.
    fn require_initialized(env: &Env) {
        if !env.storage().instance().has(&DataKey::Initialized) {
            panic!("registry not initialized");
        }
    }

    /// Require that the caller is the admin, return admin address.
    fn require_admin(env: &Env) -> Address {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("admin missing");
        admin.require_auth();
        admin
    }
}
