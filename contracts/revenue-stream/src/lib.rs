//! # Time-Locked Revenue Stream Contract
//!
//! Releases payments to beneficiaries when referenced attestation data exists
//! and is not revoked. Streams are funded at creation; release is gated by
//! an attestation check via cross-contract call. Supports **lump** (single
//! payout) and **linear** accrual schedules, plus an admin **pause** that
//! stops claims and **freezes** the effective schedule time; **resume** remaps
//! ledger so pauses are not counted toward accrual (O(1), stream rows unchanged).

#![allow(clippy::too_many_arguments)]
#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, token, Address, BytesN, Env, IntoVal, String,
};
use veritasor_common::replay_protection;

/// Nonce channel for admin replay protection.
pub const NONCE_CHANNEL_ADMIN: u32 = 1;

/// Attestation client: WASM import for wasm32 (avoids duplicate symbols), crate for tests.
#[cfg(target_arch = "wasm32")]
mod attestation_import {
    // Define type aliases locally to match attestation contract
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

    // Path from crate dir (contracts/revenue-stream): ../../ = workspace root.
    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/veritasor_attestation.wasm"
    );
    pub use Client as AttestationContractClient;
}

#[cfg(not(target_arch = "wasm32"))]
use veritasor_attestation::AttestationContractClient;

#[cfg(target_arch = "wasm32")]
use attestation_import::AttestationContractClient;

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum VestingSchedule {
    /// One payment: vested when the optional `cliff` (ledger time) is reached.
    /// Vested amount is always the full `Stream::amount` after the cliff, or
    /// immediately if `cliff` is `None`.
    Lump(Option<u64>),
    /// Linear accrual on `[accrual_start, accrual_end)`. Invariants enforced at
    /// create: `accrual_start < accrual_end`.
    Linear(u64, u64),
}

#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    Admin,
    /// Next stream id.
    NextStreamId,
    /// Stream by id.
    Stream(u64),
    /// When true, [`release`](RevenueStreamContract::release) reverts; schedule time is frozen.
    Paused,
    /// While paused: frozen `effective_vest_ledger` value (not raw ledger) so vesting is constant until resume.
    PauseSnapshotT,
    /// Active after at least one `resume` until overwritten; see [`VestTimeRemap`].
    VestTimeRemap,
}

/// Maps real ledger to schedule time: `t_eff(ledger) = t_eff0 + (ledger - at_ledger)`; see
/// [`get_effective_vest_ledger`](RevenueStreamContract::get_effective_vest_ledger).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VestTimeRemap {
    /// Effective time at the anchor ledger (frozen value after pause, before new accrual).
    pub t_eff0: u64,
    /// Ledger time when that `t_eff0` was fixed (end of a pause / resume call).
    pub at_ledger: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Stream {
    pub id: u64,
    /// Attestation contract to check for (business, period).
    pub attestation_contract: Address,
    pub business: Address,
    pub period: String,
    pub beneficiary: Address,
    pub token: Address,
    /// Total funded amount for this stream.
    pub amount: i128,
    /// Schedule for how much of `amount` is time-vested at a given ledger time.
    pub vesting: VestingSchedule,
    /// Cumulative amount already transferred to the beneficiary (0 ..= amount).
    pub released_amount: i128,
}

#[contract]
pub struct RevenueStreamContract;

/// Returns the schedule time for vesting, shared by all streams (pause freezes it; after resume,
/// it advances 1:1 with ledger with an anchor that skips paused intervals).
fn effective_vest_ledger_time(env: &Env) -> u64 {
    let ledger = env.ledger().timestamp();
    if env
        .storage()
        .instance()
        .get(&DataKey::Paused)
        .unwrap_or(false)
    {
        return env
            .storage()
            .instance()
            .get(&DataKey::PauseSnapshotT)
            .expect("paused without snapshot");
    }
    if let Some(m) = env
        .storage()
        .instance()
        .get::<_, VestTimeRemap>(&DataKey::VestTimeRemap)
    {
        return m.t_eff0.saturating_add(ledger.saturating_sub(m.at_ledger));
    }
    ledger
}

/// Time-based portion of the stream that is vested at `t_upper` (not accounting for attestation).
fn vested_by_schedule(amount: i128, vesting: &VestingSchedule, t_upper: u64) -> i128 {
    assert!(amount > 0, "internal: amount");
    match vesting {
        VestingSchedule::Lump(cliff) => {
            if let Some(c) = cliff {
                if t_upper < *c {
                    return 0;
                }
            }
            amount
        }
        VestingSchedule::Linear(accrual_start, accrual_end) => {
            if t_upper <= *accrual_start {
                return 0;
            }
            let end = *accrual_end;
            if t_upper >= end {
                return amount;
            }
            let duration = (end - accrual_start) as i128;
            let elapsed = (t_upper - accrual_start) as i128;
            amount
                .checked_mul(elapsed)
                .and_then(|v| v.checked_div(duration))
                .expect("vesting math overflow or zero duration")
        }
    }
}

fn is_fully_paid(s: &Stream) -> bool {
    s.released_amount >= s.amount
}

#[contractimpl]
#[allow(clippy::too_many_arguments)]
impl RevenueStreamContract {
    /// Initialize the contract with an admin address.
    ///
    /// # Replay protection
    /// Uses the admin address and [`NONCE_CHANNEL_ADMIN`]. The first call must use nonce 0
    /// per channel semantics in `veritasor_common::replay_protection`.
    pub fn initialize(env: Env, admin: Address, nonce: u64) {
        admin.require_auth();

        // Verify and increment nonce for replay protection
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);

        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::NextStreamId, &0u64);
        env.storage().instance().set(&DataKey::Paused, &false);
    }

    /// Create a stream: fund it with `amount` of `token` (transferred from admin).
    ///
    /// # Invariants
    /// - `amount > 0`.
    /// - `Linear`: `accrual_start < accrual_end` and positive duration; each stream is O(1) storage.
    /// - Tokens are moved from the admin into this contract before the stream is stored.
    ///
    /// # Replay protection
    /// Same channel as other admin entrypoints ([`NONCE_CHANNEL_ADMIN`]).
    #[allow(clippy::too_many_arguments)]
    pub fn create_stream(
        env: Env,
        admin: Address,
        nonce: u64,
        attestation_contract: Address,
        business: Address,
        period: String,
        beneficiary: Address,
        token: Address,
        amount: i128,
        vesting: VestingSchedule,
    ) -> u64 {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert_eq!(admin, stored_admin);
        admin.require_auth();

        // Verify and increment nonce for replay protection
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        assert!(amount > 0, "amount must be positive");
        if let VestingSchedule::Linear(accrual_start, accrual_end) = &vesting {
            assert!(
                accrual_start < accrual_end,
                "accrual_start must be before accrual_end"
            );
            let _ = accrual_end - accrual_start;
        }
        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextStreamId)
            .unwrap_or(0);
        let stream = Stream {
            id,
            attestation_contract: attestation_contract.clone(),
            business: business.clone(),
            period: period.clone(),
            beneficiary: beneficiary.clone(),
            token: token.clone(),
            amount,
            vesting,
            released_amount: 0,
        };
        env.storage().instance().set(&DataKey::Stream(id), &stream);
        env.storage()
            .instance()
            .set(&DataKey::NextStreamId, &(id + 1));
        let self_addr = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&admin, &self_addr, &amount);
        id
    }

    /// Transfers the **claimable** balance (schedule-vested minus already released) to the beneficiary
    /// if the attestation exists, is not revoked, and the contract is not paused. Reverts with
    /// `nothing to claim` when the schedule has not yet vested funds or the remainder is zero; with
    /// `cliff not reached` for lump+cliff when the effective time is before the cliff.
    ///
    /// # Security
    /// - Re-checks the attestation contract on every call (no trust in cached attestation state).
    /// - Reverts when paused (accrual time is frozen; see module docs and [`VestTimeRemap`]).
    /// - Partial payouts for `Linear` schedules; re-entrant safe by updating storage before token transfer.
    pub fn release(env: Env, stream_id: u64) {
        let mut stream: Stream = env
            .storage()
            .instance()
            .get(&DataKey::Stream(stream_id))
            .expect("stream not found");
        if is_fully_paid(&stream) {
            panic!("stream already released");
        }
        let paused: bool = env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        assert!(!paused, "contract is paused");

        let t_upper = effective_vest_ledger_time(&env);
        if let VestingSchedule::Lump(Some(c)) = &stream.vesting {
            if t_upper < *c {
                panic!("cliff not reached");
            }
        }
        let time_vested = vested_by_schedule(stream.amount, &stream.vesting, t_upper);
        let pay_cap =
            (time_vested - stream.released_amount).min(stream.amount - stream.released_amount);
        assert!(pay_cap > 0, "nothing to claim");

        let client = AttestationContractClient::new(&env, &stream.attestation_contract);
        let exists = client
            .get_attestation(&stream.business, &stream.period)
            .is_some();
        let revoked = client
            .get_revocation_info(&stream.business, &stream.period)
            .is_some();
        assert!(exists, "attestation not found");
        assert!(!revoked, "attestation is revoked");
        stream.released_amount = stream
            .released_amount
            .checked_add(pay_cap)
            .expect("released_amount overflow");
        env.storage()
            .instance()
            .set(&DataKey::Stream(stream_id), &stream);
        let token_client = token::Client::new(&env, &stream.token);
        let self_addr = env.current_contract_address();
        token_client.transfer(&self_addr, &stream.beneficiary, &pay_cap);
    }

    /// Pause: admin + replay nonce. Freezes the effective schedule time used for all streams (see
    /// [`VestTimeRemap`]) so vesting no longer increases while paused. [`release`](Self::release) reverts.
    /// A second `pause` while already paused reverts. Stores snapshot before setting the paused flag.
    pub fn pause(env: Env, admin: Address, nonce: u64) {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert_eq!(admin, stored_admin);
        admin.require_auth();
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        let paused: bool = env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        assert!(!paused, "already paused");
        let snapshot = effective_vest_ledger_time(&env);
        env.storage()
            .instance()
            .set(&DataKey::PauseSnapshotT, &snapshot);
        env.storage().instance().set(&DataKey::Paused, &true);
    }

    /// Resume: anchors [`VestTimeRemap`] so that after this ledger, `t_eff(ledger) = t_snap + (ledger - now)`,
    /// where `t_snap` is the frozen effective time at pause. No per-stream storage writes.
    /// Reverts if not paused.
    pub fn resume(env: Env, admin: Address, nonce: u64) {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert_eq!(admin, stored_admin);
        admin.require_auth();
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        let paused: bool = env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        assert!(paused, "not paused");
        let t_snap: u64 = env
            .storage()
            .instance()
            .get(&DataKey::PauseSnapshotT)
            .expect("pause state inconsistent");
        let now = env.ledger().timestamp();
        env.storage().instance().set(
            &DataKey::VestTimeRemap,
            &VestTimeRemap {
                t_eff0: t_snap,
                at_ledger: now,
            },
        );
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().remove(&DataKey::PauseSnapshotT);
    }

    /// Whether the contract is in the paused state (claims blocked; schedule time frozen for vesting).
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Read-only: schedule-vested amount at the current effective time, ignoring attestation.
    /// UIs can compare with `Stream::released_amount` for time-based claimable.
    pub fn get_vested_by_schedule(env: Env, stream_id: u64) -> i128 {
        let stream: Stream = env
            .storage()
            .instance()
            .get(&DataKey::Stream(stream_id))
            .expect("stream not found");
        let t = effective_vest_ledger_time(&env);
        vested_by_schedule(stream.amount, &stream.vesting, t)
    }

    /// Global effective time used for all streams' `VestingSchedule` (same units as
    /// `env.ledger().timestamp()` and `Stream` accrual bounds). See module docs and [`VestTimeRemap`].
    pub fn get_effective_vest_ledger(env: Env) -> u64 {
        effective_vest_ledger_time(&env)
    }

    /// Get stream by id.
    pub fn get_stream(env: Env, stream_id: u64) -> Option<Stream> {
        env.storage().instance().get(&DataKey::Stream(stream_id))
    }

    /// Get admin.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    /// Get the current nonce for replay protection.
    /// Returns the nonce value that must be supplied on the next call.
    pub fn get_replay_nonce(env: Env, actor: Address, channel: u32) -> u64 {
        replay_protection::get_nonce(&env, &actor, channel)
    }
}
