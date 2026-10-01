//! Adversarial coverage for `access_control::role_names` (issue #909).
//!
//! `role_names` is a pure, storage-free decoder that turns a role bitmap into
//! the human-readable names used by off-chain tooling and by the ABI. The
//! existing suites only exercise it implicitly through `has_role`/`get_roles`;
//! this module pins its own contract:
//!
//! * the empty bitmap and bitmaps made only of undefined bits decode to an
//!   empty vector (no panic, no placeholder name);
//! * every defined single-bit role decodes to exactly one name, and combined
//!   bitmaps decode to the canonical ADMIN → ATTESTOR → BUSINESS → OPERATOR
//!   order regardless of bit order in the input;
//! * undefined high bits are silently ignored rather than mapped or rejected;
//! * the decoder is deterministic and round-trips with `role_from_name`.

use crate::access_control::{
    role_from_name, role_names, ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR,
    ROLE_VALID_MASK,
};
use soroban_sdk::{Env, String, Vec};

fn names(env: &Env, roles: u32) -> Vec<String> {
    role_names(env, roles)
}

#[test]
fn empty_bitmap_decodes_to_no_names() {
    let env = Env::default();
    assert_eq!(names(&env, 0).len(), 0);
}

#[test]
fn each_defined_role_decodes_to_exactly_one_name() {
    let env = Env::default();

    let admin = names(&env, ROLE_ADMIN);
    assert_eq!(admin.len(), 1);
    assert_eq!(admin.get(0).unwrap(), String::from_str(&env, "ADMIN"));

    let attestor = names(&env, ROLE_ATTESTOR);
    assert_eq!(attestor.len(), 1);
    assert_eq!(attestor.get(0).unwrap(), String::from_str(&env, "ATTESTOR"));

    let business = names(&env, ROLE_BUSINESS);
    assert_eq!(business.len(), 1);
    assert_eq!(business.get(0).unwrap(), String::from_str(&env, "BUSINESS"));

    let operator = names(&env, ROLE_OPERATOR);
    assert_eq!(operator.len(), 1);
    assert_eq!(operator.get(0).unwrap(), String::from_str(&env, "OPERATOR"));
}

#[test]
fn all_defined_roles_decode_in_canonical_order() {
    let env = Env::default();
    let all = names(&env, ROLE_VALID_MASK);

    assert_eq!(all.len(), 4);
    assert_eq!(all.get(0).unwrap(), String::from_str(&env, "ADMIN"));
    assert_eq!(all.get(1).unwrap(), String::from_str(&env, "ATTESTOR"));
    assert_eq!(all.get(2).unwrap(), String::from_str(&env, "BUSINESS"));
    assert_eq!(all.get(3).unwrap(), String::from_str(&env, "OPERATOR"));
}

#[test]
fn partial_bitmaps_decode_to_the_matching_subset_in_order() {
    let env = Env::default();

    let admin_and_business = names(&env, ROLE_ADMIN | ROLE_BUSINESS);
    assert_eq!(admin_and_business.len(), 2);
    assert_eq!(
        admin_and_business.get(0).unwrap(),
        String::from_str(&env, "ADMIN")
    );
    assert_eq!(
        admin_and_business.get(1).unwrap(),
        String::from_str(&env, "BUSINESS")
    );

    // Input bit order must not influence output order.
    let attestor_and_operator = names(&env, ROLE_OPERATOR | ROLE_ATTESTOR);
    assert_eq!(attestor_and_operator.len(), 2);
    assert_eq!(
        attestor_and_operator.get(0).unwrap(),
        String::from_str(&env, "ATTESTOR")
    );
    assert_eq!(
        attestor_and_operator.get(1).unwrap(),
        String::from_str(&env, "OPERATOR")
    );
}

#[test]
fn bitmaps_of_only_undefined_bits_decode_to_no_names() {
    let env = Env::default();
    let undefined_only = 0xFFFF_FFFFu32 & !ROLE_VALID_MASK;

    // No panic, no placeholder: undefined bits carry no role name.
    assert_eq!(names(&env, undefined_only).len(), 0);
}

#[test]
fn defined_bits_mixed_with_undefined_bits_ignore_the_undefined_part() {
    let env = Env::default();
    let mixed = ROLE_ADMIN | (1 << 7) | (1 << 31);

    let out = names(&env, mixed);
    assert_eq!(out.len(), 1);
    assert_eq!(out.get(0).unwrap(), String::from_str(&env, "ADMIN"));
}

#[test]
fn u32_max_decodes_to_all_defined_roles_without_panicking() {
    let env = Env::default();
    let out = names(&env, u32::MAX);

    assert_eq!(out.len(), 4);
    assert_eq!(out.get(0).unwrap(), String::from_str(&env, "ADMIN"));
    assert_eq!(out.get(1).unwrap(), String::from_str(&env, "ATTESTOR"));
    assert_eq!(out.get(2).unwrap(), String::from_str(&env, "BUSINESS"));
    assert_eq!(out.get(3).unwrap(), String::from_str(&env, "OPERATOR"));
}

#[test]
fn decoding_is_deterministic_across_calls() {
    let env = Env::default();
    let first = names(&env, ROLE_ADMIN | ROLE_ATTESTOR);
    let second = names(&env, ROLE_ADMIN | ROLE_ATTESTOR);
    assert_eq!(first, second);
}

#[test]
fn role_names_round_trips_with_role_from_name_for_every_defined_role() {
    let env = Env::default();

    for (name, bit) in [
        ("ADMIN", ROLE_ADMIN),
        ("ATTESTOR", ROLE_ATTESTOR),
        ("BUSINESS", ROLE_BUSINESS),
        ("OPERATOR", ROLE_OPERATOR),
    ] {
        assert_eq!(role_from_name(name), bit);
        let out = names(&env, bit);
        assert_eq!(out.len(), 1);
        assert_eq!(out.get(0).unwrap(), String::from_str(&env, name));
    }
}
