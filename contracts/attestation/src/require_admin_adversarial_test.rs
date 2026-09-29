//! # Adversarial coverage for `access_control::require_admin` (issue #895)
//!
//! `require_admin` (contracts/attestation/src/access_control.rs:491) is the
//! guard in front of `grant_role`, `revoke_role`, `pause`, `unpause`,
//! `schedule_pause`, `swap_admin` and the `*_by_admin` wrappers, yet it had no
//! directly associated fixture: the `full-tests`-gated `access_control_test.rs`
//! exercises the role *mutators*, and `access_control_property_test.rs` sweeps
//! role bitmaps — neither calls `require_admin` itself.
//!
//! The guard is two lines long, which is exactly why it needs adversarial
//! coverage: everything about its correctness is *ordering* and *authority
//! source*.
//!
//! * Authority is the `ROLE_ADMIN` **bit in the caller's bitmap** — not the
//!   `DataKey::Admin` address that `dynamic_fees::require_admin` (a second,
//!   same-named helper at dynamic_fees.rs:315) consults. The two diverge.
//! * Non-admin bitmaps are rejected individually and in combination; the
//!   all-zero ed25519 account can never become an authority at all.
//! * A rejection must be pure: no nonce consumed, no bitmap written, no
//!   `RoleHolders` entry appended, no pause flag flipped.
//! * Roles are per deployed instance — an admin of one contract is a stranger
//!   to another.
//!
//! Two Soroban host constraints shape this file: `env.as_contract(..)` is a
//! non-top-level context, so `require_auth()` inside it needs
//! `mock_all_auths_allowing_non_root_auth()`; and a panic caught inside
//! `as_contract` leaves the host poisoned for the rest of the test, so every
//! direct-call rejection is the *last* statement of its test while
//! state-after-rejection assertions go through contract invocations, which the
//! host rolls back cleanly.

use super::*;
use crate::access_control::{
    self, AccessControlKey, ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, Vec};

/// StrKey of the all-zero ed25519 public key — the account `grant_role`
/// refuses to hand ADMIN to.
const ZERO_ACCOUNT_STRKEY: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// Register and initialize the attestation contract.
///
/// `initialize` stores `admin` as the fee admin *and* grants it `ROLE_ADMIN`.
/// `(env, client, contract_id, admin)`.
fn setup() -> (Env, AttestationContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, contract_id, admin)
}

/// Invoke the guard directly, inside the contract's own storage context.
/// Panics when the caller is not an admin.
fn call_require_admin(env: &Env, contract_id: &Address, caller: &Address) {
    env.as_contract(contract_id, || {
        access_control::require_admin(env, caller);
    });
}

/// `true` when `require_admin` rejected `caller`. Must be the last host
/// interaction of a test.
fn require_admin_rejects(env: &Env, contract_id: &Address, caller: &Address) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        call_require_admin(env, contract_id, caller);
    }))
    .is_err()
}

/// `get_roles` in contract context (0 when unset).
fn stored_roles(env: &Env, contract_id: &Address, account: &Address) -> u32 {
    env.as_contract(contract_id, || access_control::get_roles(env, account))
}

/// The `RoleHolders` enumeration vector.
fn role_holders(env: &Env, contract_id: &Address) -> Vec<Address> {
    env.as_contract(contract_id, || {
        env.storage()
            .instance()
            .get(&AccessControlKey::RoleHolders)
            .unwrap_or_else(|| Vec::new(env))
    })
}

/// The next nonce `account` must present on the admin channel.
///
/// Nonce state lives in `veritasor_common::replay_protection` (keyed by
/// `ReplayKey::Nonce`), *not* in `AccessControlKey::LastNonce` — the latter is
/// only touched by `require_valid_nonce`, which no admin guard calls.
/// `initialize` consumes channel 0's nonce `0`, so a freshly bootstrapped admin
/// reads `1` here.
fn next_admin_nonce(env: &Env, contract_id: &Address, account: &Address) -> u64 {
    env.as_contract(contract_id, || {
        veritasor_common::replay_protection::get_nonce(env, account, crate::NONCE_CHANNEL_ADMIN)
    })
}

// ════════════════════════════════════════════════════════════════════
//  The accepting path
// ════════════════════════════════════════════════════════════════════

/// The address bootstrapped by `initialize` satisfies the guard, and repeated
/// checks stay satisfied (the guard is a pure read).
#[test]
fn require_admin_accepts_the_bootstrapped_admin_repeatedly() {
    let (env, _client, contract_id, admin) = setup();

    for _ in 0..3 {
        call_require_admin(&env, &contract_id, &admin);
    }

    assert_eq!(stored_roles(&env, &contract_id, &admin), ROLE_ADMIN);
    assert_eq!(role_holders(&env, &contract_id).len(), 1);
    // `initialize` used nonce 0; three repetitions of the pure guard advanced nothing.
    assert_eq!(next_admin_nonce(&env, &contract_id, &admin), 1);
}

/// A combined bitmap that merely *contains* `ROLE_ADMIN` is enough — the check
/// is a bit test, not an equality on the whole bitmap.
#[test]
fn require_admin_accepts_admin_combined_with_other_roles() {
    let (env, client, contract_id, admin) = setup();
    let multi = Address::generate(&env);

    client.grant_role(&admin, &multi, &(ROLE_ADMIN | ROLE_ATTESTOR));
    client.grant_role(&admin, &multi, &(ROLE_BUSINESS | ROLE_OPERATOR));

    assert_eq!(
        stored_roles(&env, &contract_id, &multi),
        ROLE_ADMIN | ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR
    );
    call_require_admin(&env, &contract_id, &multi);
}

// ════════════════════════════════════════════════════════════════════
//  The rejecting paths, role by role
// ════════════════════════════════════════════════════════════════════

/// An address with no roles at all is rejected with the guard's own message.
#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn require_admin_rejects_an_address_with_no_roles() {
    let (env, _client, contract_id, _admin) = setup();
    let stranger = Address::generate(&env);

    assert_eq!(stored_roles(&env, &contract_id, &stranger), 0);
    call_require_admin(&env, &contract_id, &stranger);
}

/// Holding ATTESTOR is not governance authority.
#[test]
fn require_admin_rejects_an_attestor() {
    let (env, client, contract_id, admin) = setup();
    let attestor = Address::generate(&env);
    client.grant_role(&admin, &attestor, &ROLE_ATTESTOR);

    assert_eq!(stored_roles(&env, &contract_id, &attestor), ROLE_ATTESTOR);
    assert!(require_admin_rejects(&env, &contract_id, &attestor));
}

/// Holding BUSINESS is not governance authority.
#[test]
fn require_admin_rejects_a_business() {
    let (env, client, contract_id, admin) = setup();
    let business = Address::generate(&env);
    client.grant_role(&admin, &business, &ROLE_BUSINESS);

    assert_eq!(stored_roles(&env, &contract_id, &business), ROLE_BUSINESS);
    assert!(require_admin_rejects(&env, &contract_id, &business));
}

/// Holding OPERATOR is not governance authority.
#[test]
fn require_admin_rejects_an_operator() {
    let (env, client, contract_id, admin) = setup();
    let operator = Address::generate(&env);
    client.grant_role(&admin, &operator, &ROLE_OPERATOR);

    assert_eq!(stored_roles(&env, &contract_id, &operator), ROLE_OPERATOR);
    assert!(require_admin_rejects(&env, &contract_id, &operator));
}

/// The complement bitmap (`0b1110`, every defined role except ADMIN) is
/// rejected — the guard is not "does the caller have any role".
#[test]
fn require_admin_rejects_the_full_bitmap_without_the_admin_bit() {
    let (env, client, contract_id, admin) = setup();
    let nearly_admin = Address::generate(&env);

    client.grant_role(
        &admin,
        &nearly_admin,
        &(ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR),
    );

    assert_eq!(
        stored_roles(&env, &contract_id, &nearly_admin),
        ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR
    );
    assert!(require_admin_rejects(&env, &contract_id, &nearly_admin));
}

/// Revoking the ADMIN bit takes effect on the very next check — there is no
/// cached authority and no grace window.
#[test]
fn require_admin_rejects_immediately_after_the_admin_bit_is_revoked() {
    let (env, client, contract_id, admin) = setup();
    let second = Address::generate(&env);

    // A second admin keeps MIN_ADMIN_COUNT satisfied for the removal below.
    client.grant_role(&admin, &second, &ROLE_ADMIN);
    client.revoke_role(&admin, &second, &ROLE_ADMIN);

    assert_eq!(stored_roles(&env, &contract_id, &second), 0);
    assert_eq!(stored_roles(&env, &contract_id, &admin), ROLE_ADMIN);
    // The surviving admin is checked first: a rejection below must not have
    // happened before it.
    call_require_admin(&env, &contract_id, &admin);
    assert!(require_admin_rejects(&env, &contract_id, &second));
}

/// The zero account cannot be granted ADMIN at all, so it can never become an
/// authority the guard would accept (`caller: &Address` boundary value).
#[test]
fn require_admin_can_never_be_satisfied_by_the_zero_account() {
    let (env, client, contract_id, admin) = setup();
    let zero = Address::from_str(&env, ZERO_ACCOUNT_STRKEY);

    let grant = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&admin, &zero, &ROLE_ADMIN);
    }));
    assert!(
        grant.is_err(),
        "ADMIN must not be grantable to the all-zero account"
    );
    assert_eq!(stored_roles(&env, &contract_id, &zero), 0);
    assert!(require_admin_rejects(&env, &contract_id, &zero));
}

// ════════════════════════════════════════════════════════════════════
//  Authority source: the role bitmap, not the stored admin address
// ════════════════════════════════════════════════════════════════════

/// `access_control::require_admin` and `dynamic_fees::require_admin` disagree on
/// the source of truth: the former reads the `ROLE_ADMIN` bit, the latter reads
/// `DataKey::Admin` (which is what `get_admin` returns). A granted admin is an
/// authority without being the stored admin, and the stored admin is not an
/// authority once its bit is gone.
#[test]
fn require_admin_follows_the_role_bitmap_not_the_stored_admin_address() {
    let (env, client, contract_id, admin) = setup();
    let delegate = Address::generate(&env);

    client.grant_role(&admin, &delegate, &ROLE_ADMIN);

    // `delegate` can exercise an admin-only entry point…
    let outsider = Address::generate(&env);
    client.grant_role(&delegate, &outsider, &ROLE_OPERATOR);
    assert!(client.has_role(&outsider, &ROLE_OPERATOR));
    // …while the contract's stored admin address is unchanged.
    assert_eq!(client.get_admin(), admin);
    assert_eq!(stored_roles(&env, &contract_id, &delegate), ROLE_ADMIN);

    // Reverse direction: the delegate strips ADMIN from the stored admin.
    // Two admins exist, so MIN_ADMIN_COUNT allows the removal.
    client.revoke_role(&delegate, &admin, &ROLE_ADMIN);
    assert_eq!(
        client.get_admin(),
        admin,
        "the stored admin address is not an authority by itself"
    );
    assert!(require_admin_rejects(&env, &contract_id, &admin));
}

// ════════════════════════════════════════════════════════════════════
//  Purity of a rejection
// ════════════════════════════════════════════════════════════════════

/// Through a public entry point: `grant_role` runs `require_admin` before any
/// mutation, so a rejected caller writes no bitmap, registers no role holder,
/// and consumes nothing.
#[test]
fn rejected_require_admin_via_grant_role_writes_no_access_control_state() {
    let (env, client, contract_id, admin) = setup();
    let outsider = Address::generate(&env);
    let target = Address::generate(&env);

    let holders_before = role_holders(&env, &contract_id).len();

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.grant_role(&outsider, &target, &ROLE_ADMIN);
    }));
    assert!(rejected.is_err(), "a non-admin must not grant roles");

    assert_eq!(stored_roles(&env, &contract_id, &outsider), 0);
    assert_eq!(stored_roles(&env, &contract_id, &target), 0);
    assert_eq!(
        role_holders(&env, &contract_id).len(),
        holders_before,
        "a rejected guard must not register a role holder"
    );
    assert_eq!(
        next_admin_nonce(&env, &contract_id, &outsider),
        0,
        "a rejected guard must not open a nonce stream for the caller"
    );
    assert!(!client.is_paused());
    // And the real admin keeps its authority afterwards.
    call_require_admin(&env, &contract_id, &admin);
}

/// `pause` runs `require_admin` *before* `verify_and_increment_nonce`, so a
/// non-admin's attempted pause neither pauses the contract nor burns a nonce —
/// the same nonce stays available to the real admin.
///
/// The outsider presents nonce `0`, which *is* the next valid value for its own
/// admin-channel stream; only the role guard can stop it.
#[test]
fn rejected_guard_via_pause_does_not_burn_the_nonce_or_pause_the_contract() {
    let (env, client, contract_id, admin) = setup();
    let outsider = Address::generate(&env);

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.pause(&outsider, &0u64);
    }));
    assert!(
        rejected.is_err(),
        "a nonce-valid call from a non-admin must still be rejected"
    );
    assert!(!client.is_paused());
    assert_eq!(next_admin_nonce(&env, &contract_id, &outsider), 0);
    assert_eq!(next_admin_nonce(&env, &contract_id, &admin), 1);

    // The rejected attempt consumed nothing: the admin's own pause with its
    // expected nonce still goes through, and advances the stream by one.
    client.pause(&admin, &1u64);
    assert!(client.is_paused());
    assert_eq!(next_admin_nonce(&env, &contract_id, &admin), 2);
    assert_eq!(next_admin_nonce(&env, &contract_id, &outsider), 0);
}

/// The guard is orthogonal to the pause flag: pausing does not demote admins and
/// does not authorize strangers — `require_admin` is not where pausing is
/// enforced.
#[test]
fn require_admin_is_unaffected_by_the_pause_flag() {
    let (env, client, contract_id, admin) = setup();
    let outsider = Address::generate(&env);

    client.pause(&admin, &1u64);
    assert!(client.is_paused());

    call_require_admin(&env, &contract_id, &admin);
    assert!(require_admin_rejects(&env, &contract_id, &outsider));
}

// ════════════════════════════════════════════════════════════════════
//  Instance scoping
// ════════════════════════════════════════════════════════════════════

/// Roles live in each deployed instance's storage: bootstrapping the same
/// address in two contracts makes it an admin of both, while a second admin
/// created in one instance remains a stranger in the other.
#[test]
fn require_admin_authority_does_not_cross_contract_instances() {
    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();

    let id_a = env.register(AttestationContract, ());
    let client_a = AttestationContractClient::new(&env, &id_a);
    let id_b = env.register(AttestationContract, ());
    let client_b = AttestationContractClient::new(&env, &id_b);

    let admin = Address::generate(&env);
    client_a.initialize(&admin, &0u64);
    client_b.initialize(&admin, &0u64);

    let second_admin = Address::generate(&env);
    client_a.grant_role(&admin, &second_admin, &ROLE_ADMIN);

    assert_eq!(stored_roles(&env, &id_a, &second_admin), ROLE_ADMIN);
    assert_eq!(
        stored_roles(&env, &id_b, &second_admin),
        0,
        "B must not inherit A's role bitmap"
    );

    // `second_admin` is an authority in A: the guard lets it through grant_role.
    let target = Address::generate(&env);
    client_a.grant_role(&second_admin, &target, &ROLE_ATTESTOR);
    assert_eq!(stored_roles(&env, &id_a, &target), ROLE_ATTESTOR);

    // The same address is a stranger in B, and B rejects it without writing.
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client_b.grant_role(&second_admin, &target, &ROLE_ATTESTOR);
    }));
    assert!(
        rejected.is_err(),
        "ADMIN in one instance must not be ADMIN in another"
    );
    assert_eq!(stored_roles(&env, &id_b, &target), 0);

    // The bootstrap admin is still an authority in both instances, last so the
    // direct call runs on an unpoisoned host.
    call_require_admin(&env, &id_b, &admin);
}
