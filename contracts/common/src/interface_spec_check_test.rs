//! # Interface Specification Consistency Check Tests
//!
//! These tests verify that the documented interface specification remains
//! consistent with the actual contract implementations.

use soroban_sdk::{Env, String};

// Import the module under test
use crate::interface_spec_check::{
    get_event_count, get_expected_events, get_expected_methods, get_expected_structs,
    get_method_count, get_struct_count, is_event_documented, is_method_documented,
    is_struct_documented, verify_interface_consistency, VerificationResult,
};

#[test]
fn test_verification_result_new() {
    let env = Env::default();
    let result = VerificationResult::new(&env);

    assert!(result.passed);
    assert_eq!(result.missing_methods.len(), 0);
    assert_eq!(result.undocumented_methods.len(), 0);
    assert_eq!(result.missing_events.len(), 0);
    assert_eq!(result.missing_structs.len(), 0);
    assert_eq!(result.errors.len(), 0);
}

#[test]
fn test_verification_result_add_missing_method() {
    let env = Env::default();
    let mut result = VerificationResult::new(&env);

    result.add_missing_method(&env, String::from_str(&env, "test_method"));

    assert!(!result.passed);
    assert_eq!(result.missing_methods.len(), 1);
}

#[test]
fn test_verification_result_add_undocumented_method() {
    let env = Env::default();
    let mut result = VerificationResult::new(&env);

    result.add_undocumented_method(&env, String::from_str(&env, "undoc_method"));

    assert!(!result.passed);
    assert_eq!(result.undocumented_methods.len(), 1);
}

#[test]
fn test_verification_result_add_missing_event() {
    let env = Env::default();
    let mut result = VerificationResult::new(&env);

    result.add_missing_event(&env, String::from_str(&env, "test_event"));

    assert!(!result.passed);
    assert_eq!(result.missing_events.len(), 1);
}

#[test]
fn test_verification_result_add_missing_struct() {
    let env = Env::default();
    let mut result = VerificationResult::new(&env);

    result.add_missing_struct(&env, String::from_str(&env, "TestStruct"));

    assert!(!result.passed);
    assert_eq!(result.missing_structs.len(), 1);
}

#[test]
fn test_verification_result_add_error() {
    let env = Env::default();
    let mut result = VerificationResult::new(&env);

    result.add_error(&env, String::from_str(&env, "test error"));

    assert!(!result.passed);
    assert_eq!(result.errors.len(), 1);
}

#[test]
fn test_get_expected_methods_non_empty() {
    let env = Env::default();
    let methods = get_expected_methods(&env);

    assert!(!methods.is_empty(), "Expected methods should not be empty");
}

#[test]
fn test_get_expected_events_non_empty() {
    let env = Env::default();
    let events = get_expected_events(&env);

    assert!(!events.is_empty(), "Expected events should not be empty");
}

#[test]
fn test_get_expected_structs_non_empty() {
    let env = Env::default();
    let structs = get_expected_structs(&env);

    assert!(!structs.is_empty(), "Expected structs should not be empty");
}

#[test]
fn test_method_count() {
    let env = Env::default();
    let count = get_method_count(&env);

    // Total: 83 methods across all contracts
    assert_eq!(count, 83, "Total method count should be 83");
}

#[test]
fn test_event_count() {
    let env = Env::default();
    let count = get_event_count(&env);

    // Total: 13 events
    assert_eq!(count, 13, "Total event count should be 13");
}

#[test]
fn test_struct_count() {
    let env = Env::default();
    let count = get_struct_count(&env);

    // Total: 17 structs
    assert_eq!(count, 17, "Total struct count should be 17");
}

#[test]
fn test_is_method_documented() {
    let env = Env::default();

    assert!(
        is_method_documented(&env, "AttestationContract", "initialize"),
        "initialize should be documented for AttestationContract"
    );
    assert!(
        is_method_documented(&env, "AttestationContract", "submit_attestation"),
        "submit_attestation should be documented"
    );
    assert!(
        is_method_documented(&env, "IntegrationRegistryContract", "register_provider"),
        "register_provider should be documented"
    );
    assert!(
        !is_method_documented(&env, "AttestationContract", "nonexistent_method"),
        "nonexistent_method should not be documented"
    );
}

#[test]
fn test_is_event_documented() {
    let env = Env::default();

    assert!(
        is_event_documented(&env, "AttestationContract", "AttestationSubmitted"),
        "AttestationSubmitted should be documented"
    );
    assert!(
        is_event_documented(&env, "AttestationContract", "RoleGranted"),
        "RoleGranted should be documented"
    );
    assert!(
        is_event_documented(&env, "IntegrationRegistryContract", "ProviderRegistered"),
        "ProviderRegistered should be documented"
    );
    assert!(
        !is_event_documented(&env, "AttestationContract", "NonexistentEvent"),
        "NonexistentEvent should not be documented"
    );
}

#[test]
fn test_is_struct_documented() {
    let env = Env::default();

    assert!(
        is_struct_documented(&env, "AttestationContract", "FeeConfig"),
        "FeeConfig should be documented"
    );
    assert!(
        is_struct_documented(&env, "AttestationContract", "Proposal"),
        "Proposal should be documented"
    );
    assert!(
        is_struct_documented(&env, "IntegrationRegistryContract", "Provider"),
        "Provider should be documented"
    );
    assert!(
        !is_struct_documented(&env, "AttestationContract", "NonexistentStruct"),
        "NonexistentStruct should not be documented"
    );
}

#[test]
fn test_verify_interface_consistency() {
    let env = Env::default();
    let result = verify_interface_consistency(&env);

    assert!(
        result.passed,
        "Interface consistency verification should pass"
    );
}

#[test]
fn test_all_contracts_have_initialize() {
    let env = Env::default();
    let methods = get_expected_methods(&env);

    let contracts = [
        "AttestationContract",
        "AggregatedAttestationsContract",
        "AttestationSnapshotContract",
        "AuditLogContract",
        "IntegrationRegistryContract",
        "RevenueStreamContract",
    ];

    for contract in contracts.iter() {
        let has_initialize = methods.iter().any(|m| {
            m.contract == String::from_str(&env, contract)
                && m.name == String::from_str(&env, "initialize")
        });
        assert!(has_initialize, "{} should have initialize", contract);
    }
}

#[test]
fn test_all_contracts_have_get_admin() {
    let env = Env::default();
    let methods = get_expected_methods(&env);

    let contracts = [
        "AttestationContract",
        "AggregatedAttestationsContract",
        "AttestationSnapshotContract",
        "AuditLogContract",
        "IntegrationRegistryContract",
        "RevenueStreamContract",
    ];

    for contract in contracts.iter() {
        let has_get_admin = methods.iter().any(|m| {
            m.contract == String::from_str(&env, contract)
                && m.name == String::from_str(&env, "get_admin")
        });
        assert!(has_get_admin, "{} should have get_admin", contract);
    }
}

#[test]
fn test_attestation_events_have_correct_topics() {
    let env = Env::default();
    let events = get_expected_events(&env);

    let expected_topics = [
        ("AttestationSubmitted", "att_sub"),
        ("AttestationRevoked", "att_rev"),
        ("AttestationMigrated", "att_mig"),
        ("RoleGranted", "role_gr"),
        ("RoleRevoked", "role_rv"),
        ("ContractPaused", "paused"),
        ("ContractUnpaused", "unpaus"),
        ("FeeConfigChanged", "fee_cfg"),
    ];

    for (name, expected_topic) in expected_topics.iter() {
        let event = events.iter().find(|e| {
            e.name == String::from_str(&env, name)
                && e.contract == String::from_str(&env, "AttestationContract")
        });
        assert!(event.is_some(), "Event {} should exist", name);
        assert_eq!(
            event.unwrap().topic,
            String::from_str(&env, expected_topic),
            "Event {} should have topic {}",
            name,
            expected_topic
        );
    }
}

#[test]
fn test_provider_events_have_correct_topics() {
    let env = Env::default();
    let events = get_expected_events(&env);

    let expected_topics = [
        ("ProviderRegistered", "prv_reg"),
        ("ProviderEnabled", "prv_ena"),
        ("ProviderDeprecated", "prv_dep"),
        ("ProviderDisabled", "prv_dis"),
        ("ProviderUpdated", "prv_upd"),
    ];

    for (name, expected_topic) in expected_topics.iter() {
        let event = events.iter().find(|e| {
            e.name == String::from_str(&env, name)
                && e.contract == String::from_str(&env, "IntegrationRegistryContract")
        });
        assert!(event.is_some(), "Event {} should exist", name);
        assert_eq!(
            event.unwrap().topic,
            String::from_str(&env, expected_topic),
            "Event {} should have topic {}",
            name,
            expected_topic
        );
    }
}

#[test]
fn test_method_documentation_completeness() {
    let env = Env::default();

    let required_methods = [
        ("AttestationContract", "initialize"),
        ("AttestationContract", "initialize_multisig"),
        ("AttestationContract", "configure_fees"),
        ("AttestationContract", "set_tier_discount"),
        ("AttestationContract", "set_business_tier"),
        ("AttestationContract", "set_volume_brackets"),
        ("AttestationContract", "set_fee_enabled"),
        ("AttestationContract", "grant_role"),
        ("AttestationContract", "revoke_role"),
        ("AttestationContract", "has_role"),
        ("AttestationContract", "get_roles"),
        ("AttestationContract", "get_role_holders"),
        ("AttestationContract", "pause"),
        ("AttestationContract", "unpause"),
        ("AttestationContract", "is_paused"),
        ("AttestationContract", "submit_attestation"),
        ("AttestationContract", "submit_attestation_with_metadata"),
        ("AttestationContract", "revoke_attestation"),
        ("AttestationContract", "migrate_attestation"),
        ("AttestationContract", "is_revoked"),
        ("AttestationContract", "get_attestation"),
        ("AttestationContract", "get_attestation_metadata"),
        ("AttestationContract", "verify_attestation"),
        ("AttestationContract", "create_proposal"),
        ("AttestationContract", "approve_proposal"),
        ("AttestationContract", "reject_proposal"),
        ("AttestationContract", "execute_proposal"),
        ("AttestationContract", "get_proposal"),
        ("AttestationContract", "get_approval_count"),
        ("AttestationContract", "is_proposal_approved"),
        ("AttestationContract", "get_multisig_owners"),
        ("AttestationContract", "get_multisig_threshold"),
        ("AttestationContract", "is_multisig_owner"),
        ("AttestationContract", "get_fee_config"),
        ("AttestationContract", "get_fee_quote"),
        ("AttestationContract", "get_business_tier"),
        ("AttestationContract", "get_business_count"),
        ("AttestationContract", "get_admin"),
    ];

    for (contract, method) in required_methods.iter() {
        assert!(
            is_method_documented(&env, contract, method),
            "Method {}::{} should be documented",
            contract,
            method
        );
    }
}

#[test]
fn test_spec_document_exists() {
    let env = Env::default();
    let method_count = get_method_count(&env);
    assert!(method_count > 0, "Spec should define methods");
}
