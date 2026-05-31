#![no_std]

//! # Revenue Share Distribution Contract
//!
//! Automatically distributes caller-supplied revenue amounts to configured
//! stakeholders using deterministic basis-point allocation rules.
//!
//! ## Distribution model
//!
//! The contract maintains a list of stakeholders with their respective share percentages.
//! When revenue is distributed:
//!
//! 1. Verifies an on-chain attestation exists for `(business, period)` and that the
//!    declared `revenue_amount` matches the attested Merkle root (`SHA256(revenue BE bytes)`).
//! 2. Rejects expired or revoked attestations (when exposed by the attestation contract).
//! 3. Calculates each stakeholder's share: `amount = revenue × share_bps / 10_000` using
//!    checked arithmetic.
//! 4. Transfers tokens to each stakeholder after confirming the business holds sufficient balance.
//! 5. Handles rounding residuals by allocating to the first stakeholder and asserts the final
//!    vector sums exactly to `revenue_amount`.
//!
//! ## Rounding Dust Handling - Deterministic Algorithm
//!
//! Revenue distributions with non-exact share calculations produce rounding dust.
//! The contract ensures deterministic, transparent dust handling via the following algorithm:
//!
//! **Algorithm:**
//! 1. Calculate base share for each stakeholder: `base_i = floor(revenue × share_bps_i / 10_000)`
//! 2. Sum all base shares: `total_base = Σ base_i`
//! 3. Calculate residual (dust): `residual = revenue - total_base`
//! 4. If residual > 0, add it entirely to the first stakeholder's allocation
//! 5. Verify final distribution sums exactly to `revenue_amount` (invariant check)
//!
//! **Properties:**
//! - Residual is guaranteed to be in range `[0, num_stakeholders)` (at most 1 unit per stakeholder)
//! - First stakeholder receives: `base_amount + residual`
//! - All other stakeholders receive: `base_amount` only (no dust)
//! - Total distributed always equals `revenue_amount` (no loss, no overpayment)
//! - Deterministic: identical inputs always produce identical allocations
//! - Fair: maximizes fairness by concentrating dust with primary recipient
//!
//! **Why the first stakeholder?**
//! - Deterministic selection rule (no bias based on stake size)
//! - Simplifies operationalization and auditing
//! - Aligns with convention used in many revenue-sharing systems
//! - Can be rotated in future versions if needed
//!
//! **Example:**
//! ```text
//! Stakeholders: A (3333 bps), B (3333 bps), C (3334 bps)
//! Revenue: 10_000
//!
//! Base calculations:
//!   A: 10_000 * 3333 / 10_000 = 3333
//!   B: 10_000 * 3333 / 10_000 = 3333
//!   C: 10_000 * 3334 / 10_000 = 3334
//!   Total base: 10_000
//!   Residual: 0
//!
//! Allocations:
//!   A: 3333, B: 3333, C: 3334 (sum = 10_000) ✓
//!
//! ---
//!
//! Stakeholders: A (3334 bps), B (3333 bps), C (3333 bps)
//! Revenue: 10_001
//!
//! Base calculations:
//!   A: 10_001 * 3334 / 10_000 = 3334
//!   B: 10_001 * 3333 / 10_000 = 3333
//!   C: 10_001 * 3333 / 10_000 = 3333
//!   Total base: 10_000
//!   Residual: 1
//!
//! Allocations:
//!   A: 3334 + 1 = 3335, B: 3333, C: 3333 (sum = 10_001) ✓
//! ```
//!
//! ## Share configuration
//!
//! - Shares are expressed in basis points (1 bps = 0.01%).
//! - Total shares must equal exactly 10,000 bps (100%).
//! - Minimum 1 stakeholder, maximum 50 stakeholders.
//! - Each stakeholder must have at least 1 bps (0.01%).
//!
//! ## Security / guardrails
//!
//! - Admin-only configuration changes with per-admin replay nonces.
//! - Per-business replay nonces on each successful distribution.
//! - Attestation binding, expiry, and revocation checks before any transfer.
//! - Period identifier length cap to bound storage and cross-contract work.
//! - Checked arithmetic for share aggregation and intermediate products.
//! - Explicit pre-transfer balance check and post-calculation sum invariant.
//! - One distribution per `(business, period)` (idempotent storage key).

use soroban_sdk::{
    contract, contractimpl, contracttype, token, Address, Bytes, BytesN, Env, String, Vec,
};
use veritasor_common::replay_protection;

/// Nonce channel for admin configuration calls (`initialize` uses `0` as first nonce).
pub const NONCE_CHANNEL_ADMIN: u32 = 1;

/// Nonce channel for `distribute_revenue` (per `business` address).
pub const NONCE_CHANNEL_DISTRIBUTE: u32 = 2;

/// Maximum UTF-8 byte length for `period` strings (DoS / storage guardrail).
pub const MAX_PERIOD_BYTES: u32 = 128;

// ════════════════════════════════════════════════════════════════════
//  Attestation client (WASM import vs. dev crate)
// ════════════════════════════════════════════════════════════════════

#[cfg(target_arch = "wasm32")]
mod attestation_import {
    use soroban_sdk::{Address, BytesN, String, Vec};
    #[allow(dead_code)]
    pub type AttestationData = (BytesN<32>, u64, u32, i128, Option<BytesN<32>>, Option<u64>);
    #[allow(dead_code)]
    pub type RevocationData = (Address, u64, String);
    #[allow(dead_code)]
    pub type AttestationWithRevocation = (AttestationData, Option<RevocationData>);
    #[allow(dead_code)]
    pub type AttestationStatusResult =
        Vec<(String, Option<AttestationData>, Option<RevocationData>)>;

    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/veritasor_attestation.wasm"
    );
    pub use Client as AttestationContractClient;
}

#[cfg(not(target_arch = "wasm32"))]
mod attestation_import {
    pub use veritasor_attestation::AttestationContractClient;
}

use attestation_import::AttestationContractClient;

// ════════════════════════════════════════════════════════════════════
//  Storage types
// ════════════════════════════════════════════════════════════════════

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Contract administrator
    Admin,
    /// Attestation contract address reserved for integration and off-chain coordination
    AttestationContract,
    /// Token contract for distributions
    Token,
    /// Vector of stakeholders
    Stakeholders,
    /// Distribution record: (business, period) -> DistributionRecord
    Distribution(Address, String),
    /// Distribution counter for a business
    DistributionCount(Address),
}

/// Stakeholder configuration
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Stakeholder {
    /// Recipient address
    pub address: Address,
    /// Share in basis points (0-10,000)
    pub share_bps: u32,
}

/// Distribution execution record with deterministic rounding dust allocation.
///
/// # Fields
/// - `total_amount`: Total revenue amount distributed (input to distribution)
/// - `timestamp`: Timestamp of distribution execution
/// - `amounts`: Individual amounts sent to each stakeholder (in order)
///
/// # Invariants
/// - `sum(amounts) == total_amount` (always, even with rounding dust)
/// - `amounts[0] >= base_share[0]` (first stakeholder gets residual)
/// - `amounts[i] == base_share[i]` for i > 0 (others get exact base)
/// - `amounts.len() == num_stakeholders`
///
/// # Rounding Dust
/// The `amounts` vector includes all allocated rounding dust in `amounts[0]`.
/// This ensures transparency: auditors can verify:
/// 1. Each amount matches the calculation or includes documented residual
/// 2. No loss or overpayment occurred
/// 3. Allocation is deterministic across identical inputs
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct DistributionRecord {
    /// Total revenue amount distributed
    pub total_amount: i128,
    /// Timestamp of distribution
    pub timestamp: u64,
    /// Individual amounts sent to each stakeholder
    pub amounts: Vec<i128>,
}

// ════════════════════════════════════════════════════════════════════
//  Contract
// ════════════════════════════════════════════════════════════════════

#[contract]
pub struct RevenueShareContract;

#[contractimpl]
impl RevenueShareContract {
    // ── Initialization ──────────────────────────────────────────────

    /// Initialize the contract with admin, attestation contract, and token.
    ///
    /// # Parameters
    /// - `admin`: Administrator address with configuration privileges
    /// - `nonce`: Replay protection nonce for admin channel (must be `0` on first call)
    /// - `attestation_contract`: Address of the Veritasor attestation contract
    /// - `token`: Token contract address for revenue distributions
    ///
    /// # Panics
    /// - If already initialized
    /// - If nonce is invalid for `(admin, NONCE_CHANNEL_ADMIN)`
    pub fn initialize(
        env: Env,
        admin: Address,
        nonce: u64,
        attestation_contract: Address,
        token: Address,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();

        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::AttestationContract, &attestation_contract);
        env.storage().instance().set(&DataKey::Token, &token);
    }

    // ── Admin: Configuration ────────────────────────────────────────

    /// Configure stakeholders and their revenue shares.
    ///
    /// # Validation
    /// - Total shares must equal exactly 10,000 bps (100%)
    /// - Must have 1-50 stakeholders
    /// - Each stakeholder must have at least 1 bps
    /// - No duplicate addresses
    ///
    /// # Parameters
    /// - `nonce`: Replay protection nonce for admin
    /// - `stakeholders`: Vector of stakeholder configurations
    ///
    /// # Panics
    /// - If caller is not admin
    /// - If nonce is invalid
    /// - If validation fails
    pub fn configure_stakeholders(env: Env, nonce: u64, stakeholders: Vec<Stakeholder>) {
        let _admin = Self::require_admin_with_nonce(&env, nonce);

        let count = stakeholders.len();
        assert!(count > 0, "must have at least one stakeholder");
        assert!(count <= 50, "cannot exceed 50 stakeholders");

        let mut total_bps = 0u32;
        for i in 0..count {
            let stakeholder = stakeholders.get(i).unwrap();
            assert!(
                stakeholder.share_bps > 0,
                "each stakeholder must have at least 1 bps"
            );
            total_bps = total_bps
                .checked_add(stakeholder.share_bps)
                .expect("stakeholder bps overflow");

            for j in (i + 1)..count {
                let other = stakeholders.get(j).unwrap();
                assert!(
                    stakeholder.address != other.address,
                    "duplicate stakeholder address"
                );
            }
        }

        assert_eq!(
            total_bps, 10_000,
            "total shares must equal 10,000 bps (100%)"
        );

        env.storage()
            .instance()
            .set(&DataKey::Stakeholders, &stakeholders);
    }

    /// Update the attestation contract address.
    pub fn set_attestation_contract(env: Env, nonce: u64, attestation_contract: Address) {
        Self::require_admin_with_nonce(&env, nonce);
        env.storage()
            .instance()
            .set(&DataKey::AttestationContract, &attestation_contract);
    }

    /// Update the token contract address.
    pub fn set_token(env: Env, nonce: u64, token: Address) {
        Self::require_admin_with_nonce(&env, nonce);
        env.storage().instance().set(&DataKey::Token, &token);
    }

    // ── Distribution Execution ──────────────────────────────────────

    /// Distribute revenue based on attested data and stakeholder configuration.
    ///
    /// # Parameters
    /// - `business`: Business address whose attestation and token balance are used
    /// - `period`: Revenue period identifier (length ≤ [`MAX_PERIOD_BYTES`])
    /// - `revenue_amount`: Total revenue amount to distribute (must match attestation root)
    /// - `nonce`: Replay protection nonce for `(business, NONCE_CHANNEL_DISTRIBUTE)`
    ///
    /// # Guardrails
    /// - Business must authorize; after other guardrails pass, the distribution nonce must
    ///   match the expected monotonic counter (incremented only when execution reaches transfers)
    /// - Attestation must exist, not expired, not revoked; Merkle root must bind `revenue_amount`
    /// - No prior distribution for the same `(business, period)`
    /// - Business token balance must be ≥ `revenue_amount` before transfers
    /// - Final per-recipient amounts sum exactly to `revenue_amount`
    ///
    /// # Rounding Dust Handling
    ///
    /// Rounding dust (residual amounts that cannot be evenly distributed) is deterministically
    /// allocated to the first stakeholder in the configuration. This ensures:
    ///
    /// - **No loss**: Total distributed always equals `revenue_amount` exactly
    /// - **Determinism**: Identical inputs always produce identical allocations
    /// - **Predictability**: First stakeholder receives all dust; others receive exact base shares
    /// - **Auditability**: Simple, transparent allocation rule
    ///
    /// See the crate-level documentation for the full dust handling algorithm and examples.
    ///
    /// # Panics
    /// - On any failed validation, failed invariant, insufficient balance, or transfer error
    pub fn distribute_revenue(
        env: Env,
        business: Address,
        period: String,
        revenue_amount: i128,
        nonce: u64,
    ) {
        business.require_auth();

        Self::assert_period_within_limit(&period);

        assert!(revenue_amount >= 0, "revenue amount must be non-negative");

        let dist_key = DataKey::Distribution(business.clone(), period.clone());
        assert!(
            !env.storage().instance().has(&dist_key),
            "distribution already executed for this period"
        );

        let attestation_contract: Address = env
            .storage()
            .instance()
            .get(&DataKey::AttestationContract)
            .expect("attestation contract not configured");

        Self::assert_revenue_attested(
            &env,
            &attestation_contract,
            &business,
            &period,
            revenue_amount,
        );

        let stakeholders: Vec<Stakeholder> = env
            .storage()
            .instance()
            .get(&DataKey::Stakeholders)
            .expect("stakeholders not configured");

        let mut amounts = Vec::new(&env);
        let mut total_distributed = 0i128;

        for i in 0..stakeholders.len() {
            let stakeholder = stakeholders.get(i).unwrap();
            let amount = Self::calculate_share(revenue_amount, stakeholder.share_bps);
            amounts.push_back(amount);
            total_distributed = total_distributed
                .checked_add(amount)
                .expect("total distributed overflow");
        }

        let residual = revenue_amount
            .checked_sub(total_distributed)
            .expect("residual underflow");
        if residual > 0 {
            let first_amount = amounts.get(0).unwrap();
            amounts.set(
                0,
                first_amount
                    .checked_add(residual)
                    .expect("residual allocation overflow"),
            );
        }

        Self::assert_amounts_sum(&amounts, revenue_amount);

        let token_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::Token)
            .expect("token not configured");
        let token_client = token::Client::new(&env, &token_address);

        let balance = token_client.balance(&business);
        assert!(
            balance >= revenue_amount,
            "insufficient token balance for distribution"
        );

        replay_protection::verify_and_increment_nonce(
            &env,
            &business,
            NONCE_CHANNEL_DISTRIBUTE,
            nonce,
        );

        for i in 0..stakeholders.len() {
            let stakeholder = stakeholders.get(i).unwrap();
            let amount = amounts.get(i).unwrap();
            if amount > 0 {
                token_client.transfer(&business, &stakeholder.address, &amount);
            }
        }

        let record = DistributionRecord {
            total_amount: revenue_amount,
            timestamp: env.ledger().timestamp(),
            amounts,
        };
        env.storage().instance().set(&dist_key, &record);

        let count_key = DataKey::DistributionCount(business.clone());
        let count: u64 = env.storage().instance().get(&count_key).unwrap_or(0);
        env.storage()
            .instance()
            .set(&count_key, &count.checked_add(1).expect("count overflow"));
    }

    // ── Read-only Queries ───────────────────────────────────────────

    /// Returns the maximum allowed byte length for a `period` string.
    pub fn get_max_period_bytes(_env: Env) -> u32 {
        MAX_PERIOD_BYTES
    }

    /// Get the current stakeholder configuration.
    pub fn get_stakeholders(env: Env) -> Option<Vec<Stakeholder>> {
        env.storage().instance().get(&DataKey::Stakeholders)
    }

    /// Get distribution record for a specific business and period.
    pub fn get_distribution(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<DistributionRecord> {
        let key = DataKey::Distribution(business, period);
        env.storage().instance().get(&key)
    }

    /// Get total number of distributions executed for a business.
    pub fn get_distribution_count(env: Env, business: Address) -> u64 {
        let key = DataKey::DistributionCount(business);
        env.storage().instance().get(&key).unwrap_or(0)
    }

    /// Calculate the share amount for a given revenue and basis points.
    ///
    /// Formula: `amount = revenue × share_bps / 10_000` (checked; panics on overflow).
    ///
    /// # Rounding
    /// Uses integer division (floor), which produces the base share amount.
    /// Rounding dust (remainder) is calculated by [`distribute_revenue`] and allocated
    /// deterministically to the first stakeholder. See crate-level documentation.
    ///
    /// # Example
    /// ```ignore
    /// calculate_share(10_000, 3333) = 3333  // floor(10_000 * 3333 / 10_000)
    /// calculate_share(10_001, 3333) = 3333  // floor(10_001 * 3333 / 10_000) = floor(3333.3333)
    /// // Residual: 1 unit goes to first stakeholder
    /// ```
    pub fn calculate_share(revenue: i128, share_bps: u32) -> i128 {
        revenue
            .checked_mul(share_bps as i128)
            .and_then(|p| p.checked_div(10_000i128))
            .expect("calculate_share overflow")
    }

    /// Get the contract admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized")
    }

    /// Get the attestation contract address.
    pub fn get_attestation_contract(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::AttestationContract)
            .expect("attestation contract not configured")
    }

    /// Get the token contract address.
    pub fn get_token(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Token)
            .expect("not initialized")
    }

    /// Get the current nonce for replay protection for `(actor, channel)`.
    pub fn get_replay_nonce(env: Env, actor: Address, channel: u32) -> u64 {
        replay_protection::get_nonce(&env, &actor, channel)
    }

    // ── Internal Helpers ────────────────────────────────────────────

    fn require_admin_with_nonce(env: &Env, nonce: u64) -> Address {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        admin.require_auth();

        replay_protection::verify_and_increment_nonce(env, &admin, NONCE_CHANNEL_ADMIN, nonce);

        admin
    }

    fn assert_period_within_limit(period: &String) {
        assert!(
            period.len() <= MAX_PERIOD_BYTES,
            "period exceeds maximum length"
        );
    }

    /// Binds `revenue_amount` to the attestation Merkle root (`SHA256(i128 BE)`), matching
    /// the pattern used elsewhere in Veritasor (e.g. lender revenue submission).
    fn assert_revenue_attested(
        env: &Env,
        attestation_contract: &Address,
        business: &Address,
        period: &String,
        revenue_amount: i128,
    ) {
        let client = AttestationContractClient::new(env, attestation_contract);

        let att = client.get_attestation(business, period);
        assert!(att.is_some(), "attestation not found");

        assert!(
            client.get_revocation_info(business, period).is_none(),
            "attestation is revoked"
        );
        assert!(!client.is_expired(business, period), "attestation expired");

        let (stored_root, _, _, _, _, _): (
            BytesN<32>,
            u64,
            u32,
            i128,
            Option<BytesN<32>>,
            Option<u64>,
        ) = att.expect("attestation not found");

        let mut buf = [0u8; 16];
        buf.copy_from_slice(&revenue_amount.to_be_bytes());
        let payload = Bytes::from_slice(env, &buf);
        let calculated_root: BytesN<32> = env.crypto().sha256(&payload).into();

        assert_eq!(
            calculated_root, stored_root,
            "revenue amount does not match attested merkle root"
        );
    }

    fn assert_amounts_sum(amounts: &Vec<i128>, expected: i128) {
        let mut sum = 0i128;
        for i in 0..amounts.len() {
            sum = sum
                .checked_add(amounts.get(i).unwrap())
                .expect("amount sum overflow");
        }
        assert_eq!(sum, expected, "distribution amounts must sum to revenue");
    }
}
