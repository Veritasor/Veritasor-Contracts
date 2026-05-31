//! # Revenue-Backed Bond Contract
//!
//! Issues tokenized bonds whose repayment profiles are tied to attested business revenue.
//!
//! ## Security Invariants
//!
//! 1. **No double-spend per period**: each `(bond_id, period)` pair can be redeemed at most once.
//! 2. **Per-period cap**: `actual_redemption <= max_payment_per_period` always holds, even after
//!    the face-value clamp.
//! 3. **Cumulative face-value cap**: `total_redeemed` never exceeds `face_value`.
//! 4. **Issuer authorization**: the bond issuer must authorize every `redeem` call.
//! 5. **Attestation integrity**: `attested_revenue` is read from the attestation contract —
//!    callers cannot supply an arbitrary revenue figure.
//! 6. **Revocation mid-cycle**: if an attestation is revoked after bond issuance, `redeem`
//!    panics; already-recorded redemptions are unaffected.
//! 7. **Admin auth ordering**: `require_auth()` is called before any equality check in admin
//!    operations to prevent admin-address probing.
//! 8. **Maturity enforcement**: redemptions are rejected for periods outside
//!    `[issue_period, issue_period + maturity_periods)`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, String};

// ─── Attestation client ───────────────────────────────────────────────────────

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
    use soroban_sdk::{Address, BytesN, Env, String};

    pub struct AttestationContractClient {
        env: Env,
        pub address: Address,
    }

    impl AttestationContractClient {
        pub fn new(env: &Env, address: &Address) -> Self {
            Self {
                env: env.clone(),
                address: address.clone(),
            }
        }

        /// Returns `(merkle_root, timestamp, version, revenue)`.
        ///
        /// Revenue is read from env temporary storage under key
        /// `(symbol_short!("rev"), business, period)`.  Tests set this before
        /// calling `redeem`; the default is `0`.
        pub fn get_attestation(
            &self,
            business: &Address,
            period: &String,
        ) -> Option<(BytesN<32>, u64, u32, i128)> {
            let revenue_opt: Option<i128> = self.env.storage().temporary().get(&(
                soroban_sdk::symbol_short!("rev"),
                business.clone(),
                period.clone(),
            ));
            revenue_opt.map(|revenue| (BytesN::from_array(&self.env, &[0u8; 32]), 1000, 1, revenue))
        }

        pub fn get_revocation_info(
            &self,
            business: &Address,
            period: &String,
        ) -> Option<(Address, u64, String)> {
            let revoked: bool = self
                .env
                .storage()
                .temporary()
                .get(&(
                    soroban_sdk::symbol_short!("rvkd"),
                    business.clone(),
                    period.clone(),
                ))
                .unwrap_or(false);
            if revoked {
                Some((
                    business.clone(),
                    0u64,
                    String::from_str(&self.env, "revoked"),
                ))
            } else {
                None
            }
        }
    }
}

// ─── Test modules ─────────────────────────────────────────────────────────────

// ─── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    Admin,
    NextBondId,
    Bond(u64),
    BondOwner(u64),
    /// Per-period redemption record; written before token transfer.
    Redemption(u64, String),
    /// Running total of all amounts transferred for a bond.
    TotalRedeemed(u64),
}

/// Bond payment structure.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum BondStructure {
    /// Fixed: pays exactly `min_payment_per_period` each period.
    Fixed = 0,
    /// Revenue-linked: `revenue * bps / 10000`, clamped to `[min, max]`.
    RevenueLinked = 1,
    /// Hybrid: `min + revenue * bps / 10000`, capped at `max`.
    Hybrid = 2,
}

/// Bond lifecycle status.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum BondStatus {
    Active = 0,
    FullyRedeemed = 1,
    Defaulted = 2,
    Matured = 3,
}

/// Bond issuance terms.
///
/// # Risk Factors
/// - Revenue volatility affects `RevenueLinked` and `Hybrid` repayment timing.
/// - Issuer default risk if revenue falls below minimum thresholds.
/// - Attestation dependency: repayments require valid, non-revoked attestations.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Bond {
    pub id: u64,
    pub issuer: Address,
    pub face_value: i128,
    pub structure: BondStructure,
    /// Revenue share in basis points (0–10 000).
    pub revenue_share_bps: u32,
    /// Floor payment per period (≥ 0).
    pub min_payment_per_period: i128,
    /// Ceiling payment per period; also the per-period redemption cap.
    pub max_payment_per_period: i128,
    /// Number of calendar months the bond is active.
    pub maturity_periods: u32,
    pub attestation_contract: Address,
    pub token: Address,
    pub status: BondStatus,
    pub issued_at: u64,
    pub grace_period_seconds: u64,
    pub issue_period: String,
}

/// Parameters for issuing a new bond.
///
/// Grouped into a struct to comply with Soroban's 10-parameter limit.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct BondTerms {
    pub face_value: i128,
    pub structure: BondStructure,
    pub revenue_share_bps: u32,
    pub min_payment_per_period: i128,
    pub max_payment_per_period: i128,
    pub maturity_periods: u32,
    pub grace_period_seconds: u64,
    pub issue_period: String,
}

/// Immutable record of a single period's redemption.
///
/// Written atomically before the token transfer; Soroban reverts the entire
/// transaction on panic, so the record and transfer are effectively atomic.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RedemptionRecord {
    pub bond_id: u64,
    pub period: String,
    /// Revenue read from the attestation contract at redemption time.
    pub attested_revenue: i128,
    /// Tokens actually transferred; may be less than the calculated amount
    /// when the remaining face value is smaller than the per-period payment.
    pub redemption_amount: i128,
    pub redeemed_at: u64,
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Parse `"YYYY-MM"` into a monotonic month index.
///
/// # Panics
/// Panics with a descriptive message on any malformed input.
pub fn parse_period(env: &Env, period: String) -> u64 {
    assert!(period.len() == 7, "invalid period length");
    let mut bytes = [0u8; 7];
    period.copy_into_slice(&mut bytes);
    assert!(bytes[4] == b'-', "invalid period separator");
    let mut year = 0u64;
    for i in 0..4 {
        let d = bytes[i] as u64 - b'0' as u64;
        assert!(d <= 9, "invalid year digit");
        year = year * 10 + d;
    }
    let mut month = 0u64;
    for i in 0..2 {
        let d = bytes[5 + i] as u64 - b'0' as u64;
        assert!(d <= 9, "invalid month digit");
        month = month * 10 + d;
    }
    assert!(month >= 1 && month <= 12, "invalid month");
    year * 12 + month - 1
}

/// Helper to determine if a year is a leap year.
fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Helper to get the number of days in a given month.
fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => panic!("invalid month"),
    }
}

/// Returns the unix timestamp (seconds) for the start of the month following `period`.
///
/// Example: "2024-05" -> Start of 2024-06-01 00:00:00.
pub fn get_period_end_timestamp(period: String) -> u64 {
    assert!(period.len() == 7, "invalid period length");
    let mut bytes = [0u8; 7];
    period.copy_into_slice(&mut bytes);
    let mut year = 0u64;
    for i in 0..4 {
        year = year * 10 + (bytes[i] as u64 - b'0' as u64);
    }
    let mut month = 0u64;
    for i in 0..2 {
        month = month * 10 + (bytes[5 + i] as u64 - b'0' as u64);
    }

    // Move to next month
    let mut end_month = month + 1;
    let mut end_year = year;
    if end_month > 12 {
        end_month = 1;
        end_year += 1;
    }

    let mut total_days = 0;
    for y in 1970..end_year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }
    for m in 1..end_month {
        total_days += days_in_month(end_year, m);
    }
    total_days * 86400
}

/// Returns `true` iff `period` falls within `[issue_period, issue_period + maturity_periods)`.
pub fn is_period_within_maturity(env: &Env, bond: &Bond, period: String) -> bool {
    let issue_months = parse_period(env, bond.issue_period.clone());
    let period_months = parse_period(env, period);
    period_months >= issue_months && period_months < issue_months + (bond.maturity_periods as u64)
}

/// Calculate the uncapped redemption amount for a period.
///
/// Returns a value in `[min_payment_per_period, max_payment_per_period]` for
/// `RevenueLinked`/`Hybrid`, or exactly `min_payment_per_period` for `Fixed`.
/// The caller must still apply the face-value clamp and re-assert the per-period
/// ceiling afterwards.
fn calculate_redemption(bond: &Bond, attested_revenue: i128) -> i128 {
    match bond.structure {
        BondStructure::Fixed => bond.min_payment_per_period,
        BondStructure::RevenueLinked => {
            let share = (attested_revenue as u128)
                .saturating_mul(bond.revenue_share_bps as u128)
                .saturating_div(10000) as i128;
            share
                .max(bond.min_payment_per_period)
                .min(bond.max_payment_per_period)
        }
        BondStructure::Hybrid => {
            let revenue_component = (attested_revenue as u128)
                .saturating_mul(bond.revenue_share_bps as u128)
                .saturating_div(10000) as i128;
            (bond.min_payment_per_period + revenue_component).min(bond.max_payment_per_period)
        }
    }
}

// ─── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct RevenueBondContract;

#[contractimpl]
impl RevenueBondContract {
    /// Initialize the contract with an admin address.
    ///
    /// # Panics
    /// Panics if already initialized.
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        assert!(
            !env.storage().instance().has(&DataKey::Admin),
            "already initialized"
        );
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::NextBondId, &0u64);
    }

    /// Issue a new revenue-backed bond.
    ///
    /// # Arguments
    /// * `issuer` – Business issuing the bond; must authorize.
    /// * `initial_owner` – Initial bond holder (must differ from issuer).
    /// * `face_value` – Total token amount to be repaid (> 0).
    /// * `structure` – Payment structure (`Fixed`, `RevenueLinked`, or `Hybrid`).
    /// * `revenue_share_bps` – Revenue share in basis points (0–10 000).
    /// * `min_payment_per_period` – Floor payment per period (≥ 0).
    /// * `max_payment_per_period` – Ceiling / per-period cap (> 0, ≥ min).
    /// * `maturity_periods` – Calendar months the bond is active (> 0).
    /// * `issue_period` – First eligible redemption period (`"YYYY-MM"`).
    /// * `terms` – Bond parameters.
    /// * `attestation_contract` – Revenue attestation contract address.
    /// * `token` – Soroban token used for repayments.
    ///
    /// # Returns
    /// The new bond's numeric identifier.
    pub fn issue_bond(
        env: Env,
        issuer: Address,
        initial_owner: Address,
        terms: BondTerms,
        attestation_contract: Address,
        token: Address,
    ) -> u64 {
        issuer.require_auth();

        assert!(terms.face_value > 0, "face_value must be positive");
        assert!(
            terms.revenue_share_bps <= 10000,
            "revenue_share_bps must be <= 10000"
        );
        assert!(
            terms.min_payment_per_period >= 0,
            "min_payment_per_period must be non-negative"
        );
        assert!(
            terms.max_payment_per_period > 0,
            "max_payment_per_period must be positive"
        );
        assert!(
            terms.max_payment_per_period >= terms.min_payment_per_period,
            "max must be >= min"
        );
        assert!(
            terms.maturity_periods > 0,
            "maturity_periods must be positive"
        );
        assert!(!issuer.eq(&initial_owner), "issuer and owner must differ");

        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextBondId)
            .unwrap_or(0);

        let bond = Bond {
            id,
            issuer,
            face_value: terms.face_value,
            structure: terms.structure,
            revenue_share_bps: terms.revenue_share_bps,
            min_payment_per_period: terms.min_payment_per_period,
            max_payment_per_period: terms.max_payment_per_period,
            maturity_periods: terms.maturity_periods,
            issue_period: terms.issue_period,
            attestation_contract,
            token,
            status: BondStatus::Active,
            issued_at: env.ledger().timestamp(),
            grace_period_seconds: terms.grace_period_seconds,
        };

        env.storage().instance().set(&DataKey::Bond(id), &bond);
        env.storage()
            .instance()
            .set(&DataKey::BondOwner(id), &initial_owner);
        env.storage()
            .instance()
            .set(&DataKey::TotalRedeemed(id), &0i128);
        env.storage()
            .instance()
            .set(&DataKey::NextBondId, &(id + 1));

        id
    }

    /// Redeem a bond for a single period.
    ///
    /// The issuer must authorize this call.  Revenue is read directly from the
    /// attestation contract — callers cannot supply an arbitrary revenue figure.
    ///
    /// # Security invariants enforced
    ///
    /// 1. Bond must be `Active`.
    /// 2. Period must be within the bond's maturity window.
    /// 3. No prior redemption for `(bond_id, period)` — double-spend guard.
    /// 4. Attestation must exist and must not be revoked — revocation mid-cycle guard.
    /// 5. `actual_redemption <= max_payment_per_period` — per-period cap.
    /// 6. `total_redeemed + actual_redemption <= face_value` — cumulative cap.
    /// 7. Issuer must authorize — prevents unauthorized token drain.
    ///
    /// # Arguments
    /// * `bond_id` – Bond identifier.
    /// * `period` – Period to redeem (`"YYYY-MM"`).
    ///
    /// # Panics
    /// Panics on any violated invariant; the entire transaction is reverted.
    pub fn redeem(env: Env, bond_id: u64, period: String) {
        let bond: Bond = env
            .storage()
            .instance()
            .get(&DataKey::Bond(bond_id))
            .expect("bond not found");

        // Invariant 7: issuer must authorize every redemption.
        bond.issuer.require_auth();

        // Invariant 1: bond must be active.
        assert_eq!(bond.status, BondStatus::Active, "bond not active");

        // Invariant 2: period within maturity window.
        assert!(
            is_period_within_maturity(&env, &bond, period.clone()),
            "period exceeds maturity"
        );

        // Invariant 3: double-spend guard.
        assert!(
            env.storage()
                .instance()
                .get::<_, RedemptionRecord>(&DataKey::Redemption(bond_id, period.clone()))
                .is_none(),
            "already redeemed for period"
        );

        let client =
            attestation_import::AttestationContractClient::new(&env, &bond.attestation_contract);

        // Invariant 4a: revocation mid-cycle guard (checked before reading revenue).
        assert!(
            client.get_revocation_info(&bond.issuer, &period).is_none(),
            "attestation is revoked"
        );

        // Invariant 4b: attestation must exist; revenue is read from it.
        let attestation = client
            .get_attestation(&bond.issuer, &period)
            .expect("attestation not found");
        let attested_revenue: i128 = attestation.3;
        assert!(
            attested_revenue >= 0,
            "attested_revenue must be non-negative"
        );

        // Calculate uncapped per-period amount.
        let redemption_amount = calculate_redemption(&bond, attested_revenue);

        // Invariant 6: cumulative face-value cap.
        let total_redeemed: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalRedeemed(bond_id))
            .unwrap_or(0);
        let remaining = bond.face_value - total_redeemed;
        assert!(remaining > 0, "bond already fully redeemed");

        let actual_redemption = redemption_amount.min(remaining);

        // Invariant 5: per-period cap — re-assert after face-value clamp.
        assert!(
            actual_redemption <= bond.max_payment_per_period,
            "redemption exceeds per-period cap"
        );

        // Transfer tokens from issuer to bond owner.
        if actual_redemption > 0 {
            let owner: Address = env
                .storage()
                .instance()
                .get(&DataKey::BondOwner(bond_id))
                .expect("owner not found");
            token::Client::new(&env, &bond.token).transfer(
                &bond.issuer,
                &owner,
                &actual_redemption,
            );
        }

        // Write redemption record (Soroban reverts the whole tx on panic,
        // so this write and the transfer above are effectively atomic).
        env.storage().instance().set(
            &DataKey::Redemption(bond_id, period.clone()),
            &RedemptionRecord {
                bond_id,
                period,
                attested_revenue,
                redemption_amount: actual_redemption,
                redeemed_at: env.ledger().timestamp(),
            },
        );

        let new_total = total_redeemed + actual_redemption;
        env.storage()
            .instance()
            .set(&DataKey::TotalRedeemed(bond_id), &new_total);

        if new_total >= bond.face_value {
            let mut updated_bond = bond;
            updated_bond.status = BondStatus::FullyRedeemed;
            env.storage()
                .instance()
                .set(&DataKey::Bond(bond_id), &updated_bond);
        }
    }

    /// Transfer bond ownership to a new address.
    ///
    /// # Security Invariants
    /// 1. The `current_owner` must authorize the transfer.
    /// 2. The `current_owner` must match the stored owner of the bond.
    /// 3. Cannot transfer to self (`current_owner == new_owner`).
    /// 4. Cannot transfer to the bond issuer (prevents bypassing issuer restrictions).
    /// 5. Cannot transfer to the contract itself (zero-address/placeholder guard).
    /// 6. The bond must be in `Active` status.
    ///
    /// # Panics
    /// Panics if any invariant is violated or if the bond is not found.
    pub fn transfer_ownership(env: Env, bond_id: u64, current_owner: Address, new_owner: Address) {
        current_owner.require_auth();

        let stored_owner: Address = env
            .storage()
            .instance()
            .get(&DataKey::BondOwner(bond_id))
            .expect("bond not found");

        assert_eq!(current_owner, stored_owner, "not bond owner");
        assert!(!current_owner.eq(&new_owner), "cannot transfer to self");

        let bond: Bond = env
            .storage()
            .instance()
            .get(&DataKey::Bond(bond_id))
            .expect("bond not found");

        assert_eq!(bond.status, BondStatus::Active, "bond not active");
        assert!(!bond.issuer.eq(&new_owner), "cannot transfer to issuer");
        assert!(
            !env.current_contract_address().eq(&new_owner),
            "cannot transfer to contract itself"
        );

        env.storage()
            .instance()
            .set(&DataKey::BondOwner(bond_id), &new_owner);
    }

    /// Mark a bond as defaulted (admin only).
    ///
    /// Irreversible.  No further redemptions are possible after default.
    ///
    /// # Security
    /// `require_auth()` is called before the equality check to prevent
    /// callers from probing whether an address is admin without signing.
    pub fn mark_defaulted(env: Env, admin: Address, bond_id: u64) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert_eq!(admin, stored_admin, "unauthorized");

        let mut bond: Bond = env
            .storage()
            .instance()
            .get(&DataKey::Bond(bond_id))
            .expect("bond not found");
        assert!(matches!(bond.status, BondStatus::Active), "bond not active");
        bond.status = BondStatus::Defaulted;
        env.storage().instance().set(&DataKey::Bond(bond_id), &bond);
    }

    /// Mark a bond as matured (admin only).
    ///
    /// Irreversible.  No further redemptions are possible after maturity.
    ///
    /// # Security
    /// `require_auth()` is called before the equality check.
    pub fn mark_matured(env: Env, admin: Address, bond_id: u64) {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert_eq!(admin, stored_admin, "unauthorized");

        let mut bond: Bond = env
            .storage()
            .instance()
            .get(&DataKey::Bond(bond_id))
            .expect("bond not found");
        assert!(matches!(bond.status, BondStatus::Active), "bond not active");
        bond.status = BondStatus::Matured;
        env.storage().instance().set(&DataKey::Bond(bond_id), &bond);
    }

    /// Get bond details.
    pub fn get_bond(env: Env, bond_id: u64) -> Option<Bond> {
        env.storage().instance().get(&DataKey::Bond(bond_id))
    }

    /// Get the current bond owner.
    pub fn get_owner(env: Env, bond_id: u64) -> Option<Address> {
        env.storage().instance().get(&DataKey::BondOwner(bond_id))
    }

    /// Get the redemption record for a specific period, if any.
    pub fn get_redemption(env: Env, bond_id: u64, period: String) -> Option<RedemptionRecord> {
        env.storage()
            .instance()
            .get(&DataKey::Redemption(bond_id, period))
    }

    /// Get the total amount redeemed across all periods for a bond.
    pub fn get_total_redeemed(env: Env, bond_id: u64) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::TotalRedeemed(bond_id))
            .unwrap_or(0)
    }

    /// Get the remaining face value yet to be redeemed.
    ///
    /// Returns `0` for bonds that are not `Active`.
    pub fn get_remaining_value(env: Env, bond_id: u64) -> i128 {
        let bond: Bond = env
            .storage()
            .instance()
            .get(&DataKey::Bond(bond_id))
            .expect("bond not found");
        if !matches!(bond.status, BondStatus::Active) {
            return 0;
        }
        let total_redeemed: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalRedeemed(bond_id))
            .unwrap_or(0);
        bond.face_value - total_redeemed
    }

    /// Get the contract admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}
