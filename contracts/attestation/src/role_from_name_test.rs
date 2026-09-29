//! # Adversarial & Boundary Tests for `role_from_name` (Issue #910)
//!
//! `role_from_name` is a pure helper mapping `&str` to role bitflags (`u32`):
//! - It takes no `Env` parameter and performs no storage access, authentication, or state mutation.
//! - Authorization and state-rollback checks are therefore not applicable to this helper.
//! - Exact matching is required for "ADMIN", "ATTESTOR", "BUSINESS", and "OPERATOR"; all other
//!   inputs must safely return 0.

use crate::access_control::{
    role_from_name, ROLE_ADMIN, ROLE_ATTESTOR, ROLE_BUSINESS, ROLE_OPERATOR, ROLE_VALID_MASK,
};

const VALID_ROLE_CASES: [(&str, u32); 4] = [
    ("ADMIN", ROLE_ADMIN),
    ("ATTESTOR", ROLE_ATTESTOR),
    ("BUSINESS", ROLE_BUSINESS),
    ("OPERATOR", ROLE_OPERATOR),
];

#[test]
fn test_role_from_name_valid_exact_mappings() {
    for (name, expected_bit) in VALID_ROLE_CASES {
        let role = role_from_name(name);
        assert_eq!(
            role, expected_bit,
            "Valid name '{name}' must map to its constant"
        );
        assert_eq!(role.count_ones(), 1, "Role '{name}' must be a single bit");
        assert_eq!(
            role & ROLE_VALID_MASK,
            role,
            "Role '{name}' must be covered by ROLE_VALID_MASK"
        );
    }
}

#[test]
fn test_role_from_name_empty_and_unknown_names() {
    let moderate_long_name = "A".repeat(256);
    let unknown_cases = [
        "",
        "UNKNOWN",
        "ROOT",
        "USER",
        "GUEST",
        "A",
        moderate_long_name.as_str(),
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
