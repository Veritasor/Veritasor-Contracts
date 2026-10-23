//! # Adversarial & Boundary Tests for `role_from_name` (Issue #910)
//!
//! Covers `access_control::role_from_name` in isolation and in contract-level
//! role workflows:
//! - Exact mappings for `"ADMIN"`, `"ATTESTOR"`, `"BUSINESS"`, and `"OPERATOR"`,
//!   single-bit invariants, pairwise disjointness, and union equal to `ROLE_VALID_MASK`.
//! - Empty, unknown, single-char, and long boundary strings returning `0`.
//! - Case-sensitive variants, leading/trailing/internal whitespace, and control characters.
//! - Near-miss prefixes/suffixes, plurals, identifier strings, spelling mutations, and
//!   compound/delimited inputs.
//! - Unicode and homoglyph spoofing inputs.
//! - Round-trip consistency with `access_control::role_names`.
//! - Authorized admin role grants and revocations using `role_from_name`.
//! - Rejected operations (unrecognized role names resolving to `0`, and unauthorized
//!   callers) leaving contract storage (`get_roles`, `get_role_holders`, `admin_count`)
//!   unchanged.

use crate::access_control::{
    self, role_from_name, ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR, ROLE_VALID_MASK,
};
use crate::{AttestationContract, AttestationContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

const VALID_ROLE_CASES: [(&str, u32); 4] = [
    ("ADMIN", ROLE_ADMIN),
    ("ATTESTOR", ROLE_ATTESTOR),
    ("BUSINESS", ROLE_BUSINESS),
    ("OPERATOR", ROLE_OPERATOR),
];

fn setup() -> (Env, AttestationContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &0u64);
    (env, client, admin)
}

fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

fn roles_of(env: &Env, contract: &Address, account: &Address) -> u32 {
    in_contract(env, contract, |e| access_control::get_roles(e, account))
}

fn holder_count_of(env: &Env, contract: &Address) -> u32 {
    in_contract(env, contract, |e| access_control::get_role_holders(e).len())
}

fn admin_count_of(env: &Env, contract: &Address) -> u32 {
    in_contract(env, contract, access_control::admin_count)
}

#[test]
fn test_role_from_name_valid_exact_mappings() {
    let mut union_mask = 0u32;

    for (i, (name, expected_bit)) in VALID_ROLE_CASES.iter().copied().enumerate() {
        let role = role_from_name(name);
        assert_eq!(
            role, expected_bit,
            "Valid name '{name}' must map to its constant"
        );
        assert_eq!(role.count_ones(), 1, "Role '{name}' must be a single bit");
        assert!(
            access_control::is_valid_role_bitmap(role),
            "Role '{name}' must be a valid role bitmap"
        );
        assert_eq!(
            role & ROLE_VALID_MASK,
            role,
            "Role '{name}' must be covered by ROLE_VALID_MASK"
        );

        for (other_name, _) in VALID_ROLE_CASES.iter().copied().skip(i + 1) {
            let other_role = role_from_name(other_name);
            assert_eq!(
                role & other_role,
                0,
                "Distinct roles '{name}' and '{other_name}' must be disjoint"
            );
        }

        union_mask |= role;
    }

    assert_eq!(
        union_mask, ROLE_VALID_MASK,
        "Union of all valid named roles must equal ROLE_VALID_MASK"
    );
}

#[test]
fn test_role_from_name_empty_and_unknown_names() {
    let moderate_long_name = "A".repeat(256);
    let large_long_name = "ADMIN".repeat(512);
    let unknown_cases = [
        "",
        "UNKNOWN",
        "ROOT",
        "USER",
        "GUEST",
        "NONE",
        "ALL",
        "A",
        "O",
        "0",
        "1",
        moderate_long_name.as_str(),
        large_long_name.as_str(),
    ];

    for name in unknown_cases {
        assert_eq!(
            role_from_name(name),
            0,
            "Unknown input '{name}' must return 0"
        );
    }
}

#[test]
fn test_role_from_name_case_sensitivity() {
    let case_variants = [
        "admin", "Admin", "aDMIN", "AdMiN", "attestor", "Attestor", "aTTESTOR", "business",
        "Business", "bUSINESS", "operator", "Operator", "oPERATOR",
    ];

    for variant in case_variants {
        assert_eq!(
            role_from_name(variant),
            0,
            "Non-uppercase variant '{variant}' must return 0"
        );
    }
}

#[test]
fn test_role_from_name_whitespace_and_control_chars() {
    let whitespace_cases = [
        // Leading and trailing spaces
        " ADMIN",
        "ADMIN ",
        " ATTESTOR ",
        "  BUSINESS",
        // Tabs, newlines, carriage returns
        "\tADMIN",
        "ADMIN\t",
        "\nATTESTOR",
        "OPERATOR\n",
        "\r\nBUSINESS\r\n",
        // Embedded null and internal whitespace
        "ADMIN\0",
        "\0ATTESTOR",
        "AD MIN",
        "OPERA TOR",
        // Whitespace-only strings
        " ",
        "\t",
        "\n",
        "\0",
    ];

    for input in whitespace_cases {
        assert_eq!(
            role_from_name(input),
            0,
            "Whitespace/control-padded input '{input:?}' must return 0"
        );
    }
}

#[test]
fn test_role_from_name_near_misses_and_affixes() {
    let near_misses = [
        // Truncated prefixes
        "ADM",
        "ATT",
        "BUS",
        "OPER",
        // Superstrings, plurals, and extensions
        "ADMINS",
        "ADMINISTRATOR",
        "SUPERADMIN",
        "ATTESTORS",
        "BUSINESSES",
        "OPERATORS",
        "ROLE_ADMIN",
        "ROLE_OPERATOR",
        // Spelling mutations
        "ADMN",
        "ATTESTER",
        "BUISNESS",
        "OPERATER",
        // Compound or delimited strings
        "ADMIN|OPERATOR",
        "ADMIN,ATTESTOR",
        "ADMIN ATTESTOR",
    ];

    for candidate in near_misses {
        assert_eq!(
            role_from_name(candidate),
            0,
            "Near-miss candidate '{candidate}' must return 0"
        );
    }
}

#[test]
fn test_role_from_name_unicode_and_homoglyphs() {
    let unicode_cases = [
        "\u{0410}DMIN",                             // Cyrillic Capital 'А' spoofing Latin 'A'
        "\u{0391}DMIN",                             // Greek Capital 'Α' (Alpha)
        "ÁDMIN",                                    // Accented Latin character
        "ADMIN\u{200B}",                            // Trailing zero-width space
        "\u{FEFF}ADMIN",                            // Leading byte-order mark
        "\u{FF21}\u{FF24}\u{FF2D}\u{FF29}\u{FF2E}", // Fullwidth 'ＡＤＭＩＮ'
        "管理员",                                   // Non-Latin translation
    ];

    for input in unicode_cases {
        assert_eq!(
            role_from_name(input),
            0,
            "Unicode/homoglyph input '{input}' must return 0"
        );
    }
}

#[test]
fn test_role_from_name_invalid_never_overlaps_valid_mask() {
    let sample_invalids = [
        "",
        "admin",
        "ADMIN ",
        " ADMIN",
        "ADMIN\0",
        "ADMINS",
        "UNKNOWN",
        "ATTESTOR\n",
        "\u{0410}DMIN",
    ];

    for input in sample_invalids {
        let result = role_from_name(input);
        assert_eq!(result, 0, "Invalid input '{input}' must return 0");
        assert_eq!(
            result & ROLE_VALID_MASK,
            0,
            "Invalid input '{input}' must not set bits in ROLE_VALID_MASK"
        );
    }
}

#[test]
fn test_role_from_name_determinism() {
    let cases = [
        ("ADMIN", ROLE_ADMIN),
        ("ATTESTOR", ROLE_ATTESTOR),
        ("BUSINESS", ROLE_BUSINESS),
        ("OPERATOR", ROLE_OPERATOR),
        ("admin", 0),
        ("ADMIN ", 0),
        ("", 0),
    ];

    for (input, expected) in cases {
        for _ in 0..5 {
            assert_eq!(role_from_name(input), expected);
        }
    }
}

#[test]
fn test_role_from_name_roundtrip_with_role_names() {
    let env = Env::default();

    for (name, _) in VALID_ROLE_CASES {
        let bit = role_from_name(name);
        let names = access_control::role_names(&env, bit);
        assert_eq!(names.len(), 1);
        assert_eq!(names.get(0), Some(String::from_str(&env, name)));
    }

    let combined = role_from_name("ADMIN")
        | role_from_name("ATTESTOR")
        | role_from_name("BUSINESS")
        | role_from_name("OPERATOR");
    let all_names = access_control::role_names(&env, combined);
    assert_eq!(all_names.len(), 4);
    for (idx, (name, _)) in VALID_ROLE_CASES.iter().copied().enumerate() {
        assert_eq!(
            all_names.get(idx as u32),
            Some(String::from_str(&env, name))
        );
    }

    let invalids = ["", "admin", "UNKNOWN", "ADMIN ", "ADMINS"];
    for invalid in invalids {
        let parsed = role_from_name(invalid);
        let names = access_control::role_names(&env, parsed);
        assert_eq!(names.len(), 0);
    }
}

#[test]
fn test_role_from_name_unknown_never_matches_has_role() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    client.grant_role(&admin, &user, &ROLE_VALID_MASK);

    for (name, _) in VALID_ROLE_CASES {
        let role = role_from_name(name);
        assert!(client.has_role(&user, &role));
    }

    let invalids = ["", "admin", "UNKNOWN", "ADMIN ", "\0", "ADMINS"];
    for invalid in invalids {
        let role = role_from_name(invalid);
        assert!(!client.has_role(&user, &role));
    }
}

#[test]
fn test_role_from_name_authorized_grant_and_revoke_flow() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    for name in ["ATTESTOR", "BUSINESS", "OPERATOR"] {
        let role = role_from_name(name);
        client.grant_role(&admin, &user, &role);
        assert!(client.has_role(&user, &role));
    }

    let expected_combined = ROLE_ATTESTOR | ROLE_BUSINESS | ROLE_OPERATOR;
    assert_eq!(roles_of(&env, &client.address, &user), expected_combined);

    let business_role = role_from_name("BUSINESS");
    client.revoke_role(&admin, &user, &business_role);
    assert!(!client.has_role(&user, &business_role));
    assert!(client.has_role(&user, &role_from_name("ATTESTOR")));
    assert!(client.has_role(&user, &role_from_name("OPERATOR")));
}

#[test]
fn test_role_from_name_rejected_unknown_grant_leaves_state_unchanged() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    let initial_role = role_from_name("ATTESTOR");
    client.grant_role(&admin, &user, &initial_role);

    let roles_before = roles_of(&env, &client.address, &user);
    let holders_before = holder_count_of(&env, &client.address);
    let admins_before = admin_count_of(&env, &client.address);

    let invalids = ["", "admin", "UNKNOWN", "ADMIN ", "ADMINS"];
    for invalid in invalids {
        let parsed = role_from_name(invalid);
        let result = client.try_grant_role(&admin, &user, &parsed);
        assert!(
            result.is_err(),
            "grant_role must reject zero bitmask from invalid role name '{invalid}'"
        );
    }

    assert_eq!(roles_of(&env, &client.address, &user), roles_before);
    assert_eq!(holder_count_of(&env, &client.address), holders_before);
    assert_eq!(admin_count_of(&env, &client.address), admins_before);
}

#[test]
fn test_role_from_name_rejected_unknown_revoke_leaves_state_unchanged() {
    let (env, client, admin) = setup();
    let user = Address::generate(&env);

    let business_role = role_from_name("BUSINESS");
    client.grant_role(&admin, &user, &business_role);

    let roles_before = roles_of(&env, &client.address, &user);
    let holders_before = holder_count_of(&env, &client.address);

    let invalids = ["", "business", "UNKNOWN", "BUSINESS "];
    for invalid in invalids {
        let parsed = role_from_name(invalid);
        let result = client.try_revoke_role(&admin, &user, &parsed);
        assert!(
            result.is_err(),
            "revoke_role must reject zero bitmask from invalid role name '{invalid}'"
        );
    }

    assert_eq!(roles_of(&env, &client.address, &user), roles_before);
    assert_eq!(holder_count_of(&env, &client.address), holders_before);
}

#[test]
fn test_role_from_name_unauthorized_caller_rejected_and_state_unchanged() {
    let (env, client, admin) = setup();
    let stranger = Address::generate(&env);
    let operator = Address::generate(&env);
    let target = Address::generate(&env);

    let operator_role = role_from_name("OPERATOR");
    let business_role = role_from_name("BUSINESS");
    let admin_role = role_from_name("ADMIN");

    client.grant_role(&admin, &operator, &operator_role);
    client.grant_role(&admin, &target, &business_role);

    let target_roles_before = roles_of(&env, &client.address, &target);
    let holders_before = holder_count_of(&env, &client.address);
    let admins_before = admin_count_of(&env, &client.address);

    for caller in [&stranger, &operator, &target] {
        let grant_res = client.try_grant_role(caller, &target, &admin_role);
        assert!(grant_res.is_err(), "non-admin grant must be rejected");

        let revoke_res = client.try_revoke_role(caller, &target, &business_role);
        assert!(revoke_res.is_err(), "non-admin revoke must be rejected");
    }

    assert_eq!(
        roles_of(&env, &client.address, &target),
        target_roles_before
    );
    assert_eq!(holder_count_of(&env, &client.address), holders_before);
    assert_eq!(admin_count_of(&env, &client.address), admins_before);
}

#[test]
#[should_panic(expected = "invalid role: must be non-zero and within valid range")]
fn test_role_from_name_unknown_grant_panics_with_expected_message() {
    let (env, client, admin) = setup();
    let target = Address::generate(&env);
    let unknown_role = role_from_name("UNKNOWN");

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &admin, &target, unknown_role);
    });
}

#[test]
#[should_panic(expected = "caller does not have ADMIN role")]
fn test_role_from_name_unauthorized_grant_panics_with_expected_message() {
    let (env, client, _admin) = setup();
    let stranger = Address::generate(&env);
    let target = Address::generate(&env);
    let attestor_role = role_from_name("ATTESTOR");

    in_contract(&env, &client.address, |e| {
        access_control::grant_role_by_admin(e, &stranger, &target, attestor_role);
    });
}
