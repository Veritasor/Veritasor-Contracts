#![no_std]
// Tests rely on `std` (e.g. `vec!`, `.collect()`); pull it in only when
// building the test harness so the contract crate remains `no_std`.
#[cfg(test)]
extern crate std;

// # Attestation Registry Contract
//
// Provides a stable registry pattern for upgradeable attestation implementations.
//
// ## Architecture
//
// The registry maintains:
// - Current implementation address (the active attestation contract)
// - Version metadata for tracking upgrades
// - Migration hooks for upgrade coordination
// - Governance-controlled upgrade mechanism
// - Duplicate-key protection for attestation keys
//
// ## Upgrade Process
//
// 1. Deploy new attestation implementation contract
// 2. Call `upgrade(new_impl, version, migration_data)` as admin
// 3. Registry updates current implementation pointer
// 4. Optional migration hook is called on new implementation
// 5. Version metadata is updated
//
// ## Duplicate-Key Protection
//
// The registry enforces that each `(attester, key)` pair can only be registered
// once. Callers invoke `register_attestation_key` before writing to the
// implementation contract; the registry rejects any attempt to reuse a key.
// This prevents replay attacks and accidental overwrites at the registry layer.
//
// ## Safety Constraints
//
// - Only the admin (governance) can perform upgrades
// - Registry must be initialized before use
// - Version numbers must be strictly increasing
// - Previous implementation address is preserved for rollback scenarios
// - Attestation keys are globally unique per `(attester, key)` pair
//
// ## Trust Model
//
// The registry minimizes trust assumptions beyond governed upgrades:
// - No trust in implementation contracts (they are just addresses)
// - Trust only in the governance/admin for upgrade decisions
// - Callers verify implementation addresses before use

use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env, String};

#[cfg(test)]
mod get_previous_version_test;
#[cfg(test)]
mod get_current_implementation_test;
#[cfg(test)]
mod registry_batch_consistency_test;
#[cfg(test)]
mod rollback_adversarial_test;
#[cfg(test)]
mod test;
#[cfg(test)]
mod get_current_implementation_adversarial_test;
#[cfg(test)]
mod validate_implementation_test;

// ════════════════════════════════════════════════════════════════════
//  Storage types
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod get_current_implementation_test;
/// Storage keys for the registry contract.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract administrator address (governance).
    Admin,
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// Current active implementation address.
    CurrentImplementation,
    /// Previous implementation address (for rollback scenarios).
    PreviousImplementation,
    /// Current version number (monotonically increasing).
    CurrentVersion,
#[cfg(test)]
mod get_current_implementation_test;
    /// Previous version number.
    PreviousVersion,
    /// Initialization flag.
    Initialized,
    /// Duplicate-key guard: marks a `(attester, key)` pair as registered.
    /// Value is the ledger timestamp at registration time.
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    AttestationKey(Address, String),
}

/// Version metadata for an implementation.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
#[cfg(test)]
mod get_current_implementation_test;
pub struct VersionInfo {
    /// Version number (must be strictly increasing).
    pub version: u32,
    /// Implementation contract address.
    pub implementation: Address,
    /// Optional migration data passed during upgrade.
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    pub migration_data: Option<Bytes>,
    /// Timestamp when this version was activated.
    pub activated_at: u64,
}

// ════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod get_current_implementation_test;
//  Contract definition
// ════════════════════════════════════════════════════════════════════

#[contract]
pub struct AttestationRegistry;

#[cfg(test)]
mod get_current_implementation_adversarial_test;
#[contractimpl]
impl AttestationRegistry {
    // ── Initialization ──────────────────────────────────────────────

    /// Initialize the registry with an admin address and initial implementation.
    ///
#[cfg(test)]
mod get_current_implementation_test;
    /// # Arguments
    ///
    /// * `admin` - The governance address that controls upgrades
    /// * `initial_impl` - The initial attestation contract implementation address
    /// * `initial_version` - The version number for the initial implementation (typically 1)
    ///
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// # Panics
    ///
    /// * If the registry is already initialized
    /// * If `admin` does not authorize the call
    ///
    /// # Safety
#[cfg(test)]
mod get_current_implementation_test;
    ///
    /// This is a one-time setup. The admin must be a trusted governance address.
    pub fn initialize(env: Env, admin: Address, initial_impl: Address, initial_version: u32) {
        if env.storage().instance().has(&DataKey::Initialized) {
            panic!("registry already initialized");
        }
        admin.require_auth();

#[cfg(test)]
mod get_current_implementation_adversarial_test;
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::CurrentImplementation, &initial_impl);
        env.storage()
            .instance()
#[cfg(test)]
mod get_current_implementation_test;
            .set(&DataKey::CurrentVersion, &initial_version);
        env.storage().instance().set(&DataKey::Initialized, &true);
    }

    // ── Upgrade functionality ───────────────────────────────────────

    /// Validate that an implementation address is safe to register.
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    ///
    /// Returns `true` if the address passes basic safety checks:
    /// - Not the same as the current implementation (avoids pointless upgrades)
    /// - Not the admin address (prevents accidental self-referential wiring)
    ///
    /// Cross-contract validation is limited at the registry layer because
#[cfg(test)]
mod get_current_implementation_test;
    /// Soroban does not expose a way to check if an arbitrary `Address`
    /// is a deployed contract without invoking it. Callers should verify
    /// the address out-of-band or call `validate_implementation` before
    /// invoking `upgrade`.
    pub fn validate_implementation(env: Env, candidate: Address) -> bool {
        if !Self::is_initialized(env.clone()) {
#[cfg(test)]
mod get_current_implementation_adversarial_test;
            // Not initialized — only check that candidate is non-trivial
            return true;
        }

        let current_impl: Option<Address> = env
            .storage()
            .instance()
#[cfg(test)]
mod get_current_implementation_test;
            .get(&DataKey::CurrentImplementation);
        if let Some(current) = current_impl {
            if candidate == current {
                return false; // Same as current — not a real upgrade
            }
        }

#[cfg(test)]
mod get_current_implementation_adversarial_test;
        let admin: Option<Address> = env.storage().instance().get(&DataKey::Admin);
        if let Some(a) = admin {
            if candidate == a {
                return false; // Prevents wiring the registry to its own admin
            }
        }

#[cfg(test)]
mod get_current_implementation_test;
        true
    }

    /// Upgrade to a new attestation implementation.
    ///
    /// Updates the current implementation address and version metadata.
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// The previous implementation is preserved for potential rollback.
    ///
    /// # Arguments
    ///
    /// * `new_impl` - Address of the new attestation contract implementation
    /// * `new_version` - Version number (must be > current version)
    /// * `migration_data` - Optional data to pass to migration hook (can be empty)
#[cfg(test)]
mod get_current_implementation_test;
    ///
    /// # Panics
    ///
    /// * If registry is not initialized
    /// * If caller is not the admin
    /// * If `new_version` is not greater than current version
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// * If `new_impl` is the same as the current implementation (no-op upgrade)
    /// * If `new_impl` equals the admin address (prevents circular wiring)
    ///
    /// # Safety
    ///
    /// Only the admin (governance) can perform upgrades. The new implementation
    /// should be thoroughly tested before upgrade. Callers should invoke
    /// `validate_implementation` before calling this function to catch common
#[cfg(test)]
mod get_current_implementation_test;
    /// misconfigurations.
    pub fn upgrade(env: Env, new_impl: Address, new_version: u32, _migration_data: Option<Bytes>) {
        Self::require_initialized(&env);
        let _admin = Self::require_admin(&env);

        // Validate new implementation address safety
        if !Self::validate_implementation(env.clone(), new_impl.clone()) {
#[cfg(test)]
mod get_current_implementation_adversarial_test;
            panic!("invalid implementation address");
        }

        // Validate version is strictly increasing
        let current_version: u32 = env
            .storage()
            .instance()
#[cfg(test)]
mod get_current_implementation_test;
            .get(&DataKey::CurrentVersion)
            .expect("current version missing");
        if new_version <= current_version {
            panic!("new version must be greater than current version");
        }

        // Store previous implementation for rollback capability
        let current_impl: Address = env
#[cfg(test)]
mod get_current_implementation_adversarial_test;
            .storage()
            .instance()
            .get(&DataKey::CurrentImplementation)
            .expect("current implementation missing");
        env.storage()
            .instance()
            .set(&DataKey::PreviousImplementation, &current_impl);
#[cfg(test)]
mod get_current_implementation_test;
        env.storage()
            .instance()
            .set(&DataKey::PreviousVersion, &current_version);

        // Update to new implementation
        env.storage()
            .instance()
            .set(&DataKey::CurrentImplementation, &new_impl);
#[cfg(test)]
mod get_current_implementation_adversarial_test;
        env.storage()
            .instance()
            .set(&DataKey::CurrentVersion, &new_version);

        // Note: Migration hook would be called here if the new implementation
        // supports it. For now, we just update the registry.
        // The new implementation contract should handle its own migration logic
#[cfg(test)]
mod get_current_implementation_test;
        // when it receives its first calls.
    }

    /// Rollback to the previous implementation version.
    ///
    /// Reverts to the previous implementation and version. This is a safety
    /// mechanism for emergency situations.
    ///
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// # Arguments
    ///
    /// None - uses stored previous implementation and version
    ///
    /// # Panics
    ///
    /// * If registry is not initialized
#[cfg(test)]
mod get_current_implementation_test;
    /// * If caller is not the admin
    /// * If no previous implementation exists (first version)
    ///
    /// # Safety
    ///
    /// Rollback should only be used in emergency situations. After rollback,
    /// the "previous" becomes the current, so a second rollback would revert
    /// to the version before the rollback.
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    pub fn rollback(env: Env) {
        Self::require_initialized(&env);
        Self::require_admin(&env);

        let prev_impl: Option<Address> = env
            .storage()
            .instance()
#[cfg(test)]
mod get_current_implementation_test;
            .get(&DataKey::PreviousImplementation);
        let prev_version: Option<u32> = env.storage().instance().get(&DataKey::PreviousVersion);

        if prev_impl.is_none() || prev_version.is_none() {
            panic!("no previous implementation to rollback to");
        }

#[cfg(test)]
mod get_current_implementation_adversarial_test;
        // Swap current and previous
        let current_impl: Address = env
            .storage()
            .instance()
            .get(&DataKey::CurrentImplementation)
            .expect("current implementation missing");
        let current_version: u32 = env
#[cfg(test)]
mod get_current_implementation_test;
            .storage()
            .instance()
            .get(&DataKey::CurrentVersion)
            .expect("current version missing");

        env.storage()
            .instance()
#[cfg(test)]
mod get_current_implementation_adversarial_test;
            .set(&DataKey::CurrentImplementation, &prev_impl.unwrap());
        env.storage()
            .instance()
            .set(&DataKey::CurrentVersion, &prev_version.unwrap());
        env.storage()
            .instance()
#[cfg(test)]
mod get_current_implementation_test;
            .set(&DataKey::PreviousImplementation, &current_impl);
        env.storage()
            .instance()
            .set(&DataKey::PreviousVersion, &current_version);
    }

    // ── Query functions ─────────────────────────────────────────────
#[cfg(test)]
mod get_current_implementation_adversarial_test;

    /// Get the current active implementation address.
    ///
    /// Returns the address that should be used for all attestation operations.
    ///
    /// # Returns
    ///
    /// `Option<Address>` - Current implementation address, or None if not initialized
#[cfg(test)]
mod get_current_implementation_test;
    pub fn get_current_implementation(env: Env) -> Option<Address> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return None;
        }
        env.storage()
            .instance()
            .get(&DataKey::CurrentImplementation)
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    }

    /// Get the current version number.
    ///
    /// # Returns
    ///
    /// `Option<u32>` - Current version number, or None if not initialized
#[cfg(test)]
mod get_current_implementation_test;
    pub fn get_current_version(env: Env) -> Option<u32> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return None;
        }
        env.storage().instance().get(&DataKey::CurrentVersion)
    }

#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// Get the previous implementation address (for rollback scenarios).
    ///
    /// # Returns
    ///
    /// `Option<Address>` - Previous implementation address, or None if no previous exists
    pub fn get_previous_implementation(env: Env) -> Option<Address> {
        if !env.storage().instance().has(&DataKey::Initialized) {
#[cfg(test)]
mod get_current_implementation_test;
            return None;
        }
        env.storage()
            .instance()
            .get(&DataKey::PreviousImplementation)
    }

#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// Get the previous version number.
    ///
    /// # Returns
    ///
    /// `Option<u32>` - Previous version number, or None if no previous exists
    pub fn get_previous_version(env: Env) -> Option<u32> {
        if !env.storage().instance().has(&DataKey::Initialized) {
#[cfg(test)]
mod get_current_implementation_test;
            return None;
        }
        env.storage().instance().get(&DataKey::PreviousVersion)
    }

    /// Get the admin address.
    ///
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// # Returns
    ///
    /// `Option<Address>` - Admin address, or None if not initialized
    pub fn get_admin(env: Env) -> Option<Address> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return None;
#[cfg(test)]
mod get_current_implementation_test;
        }
        env.storage().instance().get(&DataKey::Admin)
    }

    /// Check if the registry is initialized.
    ///
    /// # Returns
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    ///
    /// `bool` - True if initialized, false otherwise
    pub fn is_initialized(env: Env) -> bool {
        env.storage().instance().has(&DataKey::Initialized)
    }

    /// Get complete version information for the current implementation.
    ///
#[cfg(test)]
mod get_current_implementation_test;
    /// # Returns
    ///
    /// `Option<VersionInfo>` - Current version info, or None if not initialized
    ///
    /// Note: `activated_at` is not stored historically, so it reflects the
    /// current ledger timestamp when queried.
    pub fn get_version_info(env: Env) -> Option<VersionInfo> {
#[cfg(test)]
mod get_current_implementation_adversarial_test;
        if !Self::is_initialized(env.clone()) {
            return None;
        }

        let implementation: Address = env
            .storage()
            .instance()
#[cfg(test)]
mod get_current_implementation_test;
            .get(&DataKey::CurrentImplementation)
            .expect("current implementation missing");
        let version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::CurrentVersion)
            .expect("current version missing");

#[cfg(test)]
mod get_current_implementation_adversarial_test;
        Some(VersionInfo {
            version,
            implementation,
            migration_data: None, // Migration data is not stored, only used during upgrade
            activated_at: env.ledger().timestamp(),
        })
    }

#[cfg(test)]
mod get_current_implementation_test;
    // ── Duplicate-key protection ────────────────────────────────────

    /// Register an attestation key for `(attester, key)`, enforcing uniqueness.
    ///
    /// This is the registry-layer duplicate-key guard. Call this before writing
    /// an attestation to the implementation contract. The registry records the
    /// `(attester, key)` pair and rejects any future attempt to register the
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// same pair, preventing replay attacks and accidental overwrites.
    ///
    /// # Arguments
    ///
    /// * `attester` - The address submitting the attestation (must authorize)
    /// * `key`      - Opaque string key identifying the attestation (e.g. period, subject ID)
    ///
#[cfg(test)]
mod get_current_implementation_test;
    /// # Panics
    ///
    /// * If registry is not initialized
    /// * If `attester` does not authorize the call
    /// * If `(attester, key)` has already been registered
    ///
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// # Security
    ///
    /// Authorization is required from `attester` so that no third party can
    /// pre-emptively occupy a key on behalf of another address.
    pub fn register_attestation_key(env: Env, attester: Address, key: String) {
        Self::require_initialized(&env);
        attester.require_auth();

#[cfg(test)]
mod get_current_implementation_test;
        let dk = DataKey::AttestationKey(attester, key);
        if env.storage().persistent().has(&dk) {
            panic!("attestation key already registered");
        }
        env.storage()
            .persistent()
            .set(&dk, &env.ledger().timestamp());
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    }

    /// Check whether an `(attester, key)` pair has already been registered.
    ///
    /// # Returns
    ///
    /// `true` if the key exists, `false` otherwise.
#[cfg(test)]
mod get_current_implementation_test;
    pub fn has_attestation_key(env: Env, attester: Address, key: String) -> bool {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return false;
        }
        env.storage()
            .persistent()
            .has(&DataKey::AttestationKey(attester, key))
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    }

    // ── Admin management ────────────────────────────────────────────

    /// Transfer admin rights to a new address.
    ///
    /// # Arguments
#[cfg(test)]
mod get_current_implementation_test;
    ///
    /// * `new_admin` - The new admin address
    ///
    /// # Panics
    ///
    /// * If registry is not initialized
    /// * If caller is not the current admin
    ///
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    /// # Safety
    ///
    /// This is a critical operation. The new admin will have full control
    /// over upgrades. Use with extreme caution.
    pub fn transfer_admin(env: Env, new_admin: Address) {
        Self::require_initialized(&env);
        Self::require_admin(&env);
#[cfg(test)]
mod get_current_implementation_test;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
    }
}

// ════════════════════════════════════════════════════════════════════
//  Internal helpers
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod get_current_implementation_adversarial_test;
impl AttestationRegistry {
    /// Require that the registry is initialized, panic otherwise.
    fn require_initialized(env: &Env) {
        if !env.storage().instance().has(&DataKey::Initialized) {
            panic!("registry not initialized");
        }
    }

    /// Require that the caller is the admin, return admin address.
#[cfg(test)]
mod get_current_implementation_test;
    fn require_admin(env: &Env) -> Address {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("admin missing");
        admin.require_auth();
        admin
#[cfg(test)]
mod get_current_implementation_adversarial_test;
    }
}

#[cfg(test)]
mod upgrade_adversarial_test;

#[cfg(test)]
mod get_current_implementation_test;

#[cfg(test)]
mod get_current_implementation_adversarial_test;