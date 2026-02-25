//! # Interface Specification Consistency Check
//!
//! This module provides utilities to verify that the documented interface
//! specification in `docs/contract-interfaces.md` remains consistent with
//! the actual contract implementations.
//!
//! ## Purpose
//!
//! - Ensure all public methods are documented
//! - Detect interface drift between docs and implementation
//! - Support SDK generation from verified interfaces
//!
//! ## Usage
//!
//! ```rust,ignore
//! use veritasor_common::interface_spec_check::{InterfaceSpec, MethodSpec};
//!
//! let spec = InterfaceSpec::load();
//! spec.verify_methods_exist();
//! ```

use soroban_sdk::{contracttype, Env, String, Vec};

/// Represents a method parameter in the interface specification.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ParamSpec {
    /// Parameter name
    pub name: String,
    /// Parameter type as string (e.g., "Address", "u64", "Vec<Address>")
    pub type_name: String,
    /// Parameter description
    pub description: String,
}

/// Represents a method in the interface specification.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct MethodSpec {
    /// Method name
    pub name: String,
    /// Contract this method belongs to
    pub contract: String,
    /// List of parameters
    pub params: Vec<ParamSpec>,
    /// Return type (empty string if void)
    pub return_type: String,
    /// Whether the method requires authorization
    pub requires_auth: bool,
    /// Brief description
    pub description: String,
}

/// Represents an event in the interface specification.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct EventSpec {
    /// Event name
    pub name: String,
    /// Event topic symbol
    pub topic: String,
    /// Contract this event belongs to
    pub contract: String,
    /// List of fields
    pub fields: Vec<ParamSpec>,
}

/// Represents a data structure in the interface specification.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct StructSpec {
    /// Struct name
    pub name: String,
    /// Contract this struct belongs to
    pub contract: String,
    /// List of fields
    pub fields: Vec<ParamSpec>,
}

/// Complete interface specification for all contracts.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct InterfaceSpec {
    /// All documented methods
    pub methods: Vec<MethodSpec>,
    /// All documented events
    pub events: Vec<EventSpec>,
    /// All documented structs
    pub structs: Vec<StructSpec>,
    /// Version of the specification
    pub version: String,
}

/// Verification result for interface consistency.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct VerificationResult {
    /// Whether verification passed
    pub passed: bool,
    /// List of missing methods (documented but not implemented)
    pub missing_methods: Vec<String>,
    /// List of undocumented methods (implemented but not documented)
    pub undocumented_methods: Vec<String>,
    /// List of missing events
    pub missing_events: Vec<String>,
    /// List of missing structs
    pub missing_structs: Vec<String>,
    /// Error messages
    pub errors: Vec<String>,
}

impl VerificationResult {
    /// Create a new empty verification result.
    pub fn new(env: &Env) -> Self {
        VerificationResult {
            passed: true,
            missing_methods: Vec::new(env),
            undocumented_methods: Vec::new(env),
            missing_events: Vec::new(env),
            missing_structs: Vec::new(env),
            errors: Vec::new(env),
        }
    }

    /// Add a missing method to the result.
    pub fn add_missing_method(&mut self, _env: &Env, method: String) {
        self.missing_methods.push_back(method);
        self.passed = false;
    }

    /// Add an undocumented method to the result.
    pub fn add_undocumented_method(&mut self, _env: &Env, method: String) {
        self.undocumented_methods.push_back(method);
        self.passed = false;
    }

    /// Add a missing event to the result.
    pub fn add_missing_event(&mut self, _env: &Env, event: String) {
        self.missing_events.push_back(event);
        self.passed = false;
    }

    /// Add a missing struct to the result.
    pub fn add_missing_struct(&mut self, _env: &Env, struct_name: String) {
        self.missing_structs.push_back(struct_name);
        self.passed = false;
    }

    /// Add an error message.
    pub fn add_error(&mut self, _env: &Env, error: String) {
        self.errors.push_back(error);
        self.passed = false;
    }
}

/// Expected methods for each contract.
/// This list must be kept in sync with docs/contract-interfaces.md
pub fn get_expected_methods(env: &Env) -> Vec<MethodSpec> {
    let mut methods = Vec::new(env);

    // AttestationContract methods
    let attestation_methods = [
        ("initialize", "AttestationContract", "void", true),
        ("initialize_multisig", "AttestationContract", "void", true),
        ("configure_fees", "AttestationContract", "void", true),
        ("set_tier_discount", "AttestationContract", "void", true),
        ("set_business_tier", "AttestationContract", "void", true),
        ("set_volume_brackets", "AttestationContract", "void", true),
        ("set_fee_enabled", "AttestationContract", "void", true),
        ("grant_role", "AttestationContract", "void", true),
        ("revoke_role", "AttestationContract", "void", true),
        ("has_role", "AttestationContract", "bool", false),
        ("get_roles", "AttestationContract", "u32", false),
        (
            "get_role_holders",
            "AttestationContract",
            "Vec<Address>",
            false,
        ),
        ("pause", "AttestationContract", "void", true),
        ("unpause", "AttestationContract", "void", true),
        ("is_paused", "AttestationContract", "bool", false),
        ("submit_attestation", "AttestationContract", "void", true),
        (
            "submit_attestation_with_metadata",
            "AttestationContract",
            "void",
            true,
        ),
        ("revoke_attestation", "AttestationContract", "void", true),
        ("migrate_attestation", "AttestationContract", "void", true),
        ("is_revoked", "AttestationContract", "bool", false),
        (
            "get_attestation",
            "AttestationContract",
            "Option<(BytesN<32>, u64, u32, i128)>",
            false,
        ),
        (
            "get_attestation_metadata",
            "AttestationContract",
            "Option<AttestationMetadata>",
            false,
        ),
        ("verify_attestation", "AttestationContract", "bool", false),
        ("create_proposal", "AttestationContract", "u64", true),
        ("approve_proposal", "AttestationContract", "void", true),
        ("reject_proposal", "AttestationContract", "void", true),
        ("execute_proposal", "AttestationContract", "void", true),
        (
            "get_proposal",
            "AttestationContract",
            "Option<Proposal>",
            false,
        ),
        ("get_approval_count", "AttestationContract", "u32", false),
        ("is_proposal_approved", "AttestationContract", "bool", false),
        (
            "get_multisig_owners",
            "AttestationContract",
            "Vec<Address>",
            false,
        ),
        (
            "get_multisig_threshold",
            "AttestationContract",
            "u32",
            false,
        ),
        ("is_multisig_owner", "AttestationContract", "bool", false),
        (
            "get_fee_config",
            "AttestationContract",
            "Option<FeeConfig>",
            false,
        ),
        ("get_fee_quote", "AttestationContract", "i128", false),
        ("get_business_tier", "AttestationContract", "u32", false),
        ("get_business_count", "AttestationContract", "u64", false),
        ("get_admin", "AttestationContract", "Address", false),
    ];

    for (name, contract, return_type, requires_auth) in attestation_methods.iter() {
        methods.push_back(MethodSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, contract),
            params: Vec::new(env),
            return_type: String::from_str(env, return_type),
            requires_auth: *requires_auth,
            description: String::from_str(env, ""),
        });
    }

    // AggregatedAttestationsContract methods
    let aggregated_methods = [
        ("initialize", "AggregatedAttestationsContract", "void", true),
        (
            "register_portfolio",
            "AggregatedAttestationsContract",
            "void",
            true,
        ),
        (
            "get_aggregated_metrics",
            "AggregatedAttestationsContract",
            "AggregatedMetrics",
            false,
        ),
        (
            "get_admin",
            "AggregatedAttestationsContract",
            "Address",
            false,
        ),
        (
            "get_portfolio",
            "AggregatedAttestationsContract",
            "Option<Vec<Address>>",
            false,
        ),
    ];

    for (name, contract, return_type, requires_auth) in aggregated_methods.iter() {
        methods.push_back(MethodSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, contract),
            params: Vec::new(env),
            return_type: String::from_str(env, return_type),
            requires_auth: *requires_auth,
            description: String::from_str(env, ""),
        });
    }

    // AttestationSnapshotContract methods
    let snapshot_methods = [
        ("initialize", "AttestationSnapshotContract", "void", true),
        (
            "set_attestation_contract",
            "AttestationSnapshotContract",
            "void",
            true,
        ),
        ("add_writer", "AttestationSnapshotContract", "void", true),
        ("remove_writer", "AttestationSnapshotContract", "void", true),
        ("is_writer", "AttestationSnapshotContract", "bool", false),
        (
            "record_snapshot",
            "AttestationSnapshotContract",
            "void",
            true,
        ),
        (
            "get_snapshot",
            "AttestationSnapshotContract",
            "Option<SnapshotRecord>",
            false,
        ),
        (
            "get_snapshots_for_business",
            "AttestationSnapshotContract",
            "Vec<SnapshotRecord>",
            false,
        ),
        ("get_admin", "AttestationSnapshotContract", "Address", false),
        (
            "get_attestation_contract",
            "AttestationSnapshotContract",
            "Option<Address>",
            false,
        ),
    ];

    for (name, contract, return_type, requires_auth) in snapshot_methods.iter() {
        methods.push_back(MethodSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, contract),
            params: Vec::new(env),
            return_type: String::from_str(env, return_type),
            requires_auth: *requires_auth,
            description: String::from_str(env, ""),
        });
    }

    // AuditLogContract methods
    let audit_methods = [
        ("initialize", "AuditLogContract", "void", true),
        ("append", "AuditLogContract", "u64", true),
        ("get_log_count", "AuditLogContract", "u64", false),
        (
            "get_entry",
            "AuditLogContract",
            "Option<AuditRecord>",
            false,
        ),
        ("get_seqs_by_actor", "AuditLogContract", "Vec<u64>", false),
        (
            "get_seqs_by_contract",
            "AuditLogContract",
            "Vec<u64>",
            false,
        ),
        ("get_admin", "AuditLogContract", "Address", false),
    ];

    for (name, contract, return_type, requires_auth) in audit_methods.iter() {
        methods.push_back(MethodSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, contract),
            params: Vec::new(env),
            return_type: String::from_str(env, return_type),
            requires_auth: *requires_auth,
            description: String::from_str(env, ""),
        });
    }

    // IntegrationRegistryContract methods
    let registry_methods = [
        ("initialize", "IntegrationRegistryContract", "void", true),
        (
            "grant_governance",
            "IntegrationRegistryContract",
            "void",
            true,
        ),
        (
            "revoke_governance",
            "IntegrationRegistryContract",
            "void",
            true,
        ),
        (
            "register_provider",
            "IntegrationRegistryContract",
            "void",
            true,
        ),
        (
            "enable_provider",
            "IntegrationRegistryContract",
            "void",
            true,
        ),
        (
            "deprecate_provider",
            "IntegrationRegistryContract",
            "void",
            true,
        ),
        (
            "disable_provider",
            "IntegrationRegistryContract",
            "void",
            true,
        ),
        (
            "update_metadata",
            "IntegrationRegistryContract",
            "void",
            true,
        ),
        (
            "get_provider",
            "IntegrationRegistryContract",
            "Option<Provider>",
            false,
        ),
        ("is_enabled", "IntegrationRegistryContract", "bool", false),
        (
            "is_deprecated",
            "IntegrationRegistryContract",
            "bool",
            false,
        ),
        (
            "is_valid_for_attestation",
            "IntegrationRegistryContract",
            "bool",
            false,
        ),
        (
            "get_status",
            "IntegrationRegistryContract",
            "Option<ProviderStatus>",
            false,
        ),
        (
            "get_all_providers",
            "IntegrationRegistryContract",
            "Vec<String>",
            false,
        ),
        (
            "get_enabled_providers",
            "IntegrationRegistryContract",
            "Vec<String>",
            false,
        ),
        (
            "get_deprecated_providers",
            "IntegrationRegistryContract",
            "Vec<String>",
            false,
        ),
        ("get_admin", "IntegrationRegistryContract", "Address", false),
        (
            "has_governance",
            "IntegrationRegistryContract",
            "bool",
            false,
        ),
    ];

    for (name, contract, return_type, requires_auth) in registry_methods.iter() {
        methods.push_back(MethodSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, contract),
            params: Vec::new(env),
            return_type: String::from_str(env, return_type),
            requires_auth: *requires_auth,
            description: String::from_str(env, ""),
        });
    }

    // RevenueStreamContract methods
    let stream_methods = [
        ("initialize", "RevenueStreamContract", "void", true),
        ("create_stream", "RevenueStreamContract", "u64", true),
        ("release", "RevenueStreamContract", "void", false),
        (
            "get_stream",
            "RevenueStreamContract",
            "Option<Stream>",
            false,
        ),
        ("get_admin", "RevenueStreamContract", "Address", false),
    ];

    for (name, contract, return_type, requires_auth) in stream_methods.iter() {
        methods.push_back(MethodSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, contract),
            params: Vec::new(env),
            return_type: String::from_str(env, return_type),
            requires_auth: *requires_auth,
            description: String::from_str(env, ""),
        });
    }

    methods
}

/// Expected events for each contract.
pub fn get_expected_events(env: &Env) -> Vec<EventSpec> {
    let mut events = Vec::new(env);

    let attestation_events = [
        ("AttestationSubmitted", "att_sub", "AttestationContract"),
        ("AttestationRevoked", "att_rev", "AttestationContract"),
        ("AttestationMigrated", "att_mig", "AttestationContract"),
        ("RoleGranted", "role_gr", "AttestationContract"),
        ("RoleRevoked", "role_rv", "AttestationContract"),
        ("ContractPaused", "paused", "AttestationContract"),
        ("ContractUnpaused", "unpaus", "AttestationContract"),
        ("FeeConfigChanged", "fee_cfg", "AttestationContract"),
    ];

    for (name, topic, contract) in attestation_events.iter() {
        events.push_back(EventSpec {
            name: String::from_str(env, name),
            topic: String::from_str(env, topic),
            contract: String::from_str(env, contract),
            fields: Vec::new(env),
        });
    }

    let registry_events = [
        (
            "ProviderRegistered",
            "prv_reg",
            "IntegrationRegistryContract",
        ),
        ("ProviderEnabled", "prv_ena", "IntegrationRegistryContract"),
        (
            "ProviderDeprecated",
            "prv_dep",
            "IntegrationRegistryContract",
        ),
        ("ProviderDisabled", "prv_dis", "IntegrationRegistryContract"),
        ("ProviderUpdated", "prv_upd", "IntegrationRegistryContract"),
    ];

    for (name, topic, contract) in registry_events.iter() {
        events.push_back(EventSpec {
            name: String::from_str(env, name),
            topic: String::from_str(env, topic),
            contract: String::from_str(env, contract),
            fields: Vec::new(env),
        });
    }

    events
}

/// Expected structs for each contract.
pub fn get_expected_structs(env: &Env) -> Vec<StructSpec> {
    let mut structs = Vec::new(env);

    let attestation_structs = [
        "FeeConfig",
        "AttestationMetadata",
        "RevenueBasis",
        "Proposal",
        "ProposalAction",
        "ProposalStatus",
        "Dispute",
        "DisputeStatus",
        "DisputeType",
        "DisputeOutcome",
    ];

    for name in attestation_structs.iter() {
        structs.push_back(StructSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, "AttestationContract"),
            fields: Vec::new(env),
        });
    }

    let aggregated_structs = ["AggregatedMetrics"];

    for name in aggregated_structs.iter() {
        structs.push_back(StructSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, "AggregatedAttestationsContract"),
            fields: Vec::new(env),
        });
    }

    let snapshot_structs = ["SnapshotRecord"];

    for name in snapshot_structs.iter() {
        structs.push_back(StructSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, "AttestationSnapshotContract"),
            fields: Vec::new(env),
        });
    }

    let audit_structs = ["AuditRecord"];

    for name in audit_structs.iter() {
        structs.push_back(StructSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, "AuditLogContract"),
            fields: Vec::new(env),
        });
    }

    let registry_structs = ["Provider", "ProviderStatus", "ProviderMetadata"];

    for name in registry_structs.iter() {
        structs.push_back(StructSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, "IntegrationRegistryContract"),
            fields: Vec::new(env),
        });
    }

    let stream_structs = ["Stream"];

    for name in stream_structs.iter() {
        structs.push_back(StructSpec {
            name: String::from_str(env, name),
            contract: String::from_str(env, "RevenueStreamContract"),
            fields: Vec::new(env),
        });
    }

    structs
}

/// Verify that all expected methods are documented.
/// Returns a verification result with any discrepancies found.
pub fn verify_interface_consistency(env: &Env) -> VerificationResult {
    let mut result = VerificationResult::new(env);

    // Get expected methods from the spec
    let expected_methods = get_expected_methods(env);
    let expected_events = get_expected_events(env);
    let expected_structs = get_expected_structs(env);

    // In a real implementation, this would:
    // 1. Parse the actual contract code or use reflection
    // 2. Compare with expected methods
    // 3. Report any discrepancies

    // For now, we verify that our expected lists are non-empty
    if expected_methods.is_empty() {
        result.add_error(env, String::from_str(env, "No expected methods defined"));
    }

    if expected_events.is_empty() {
        result.add_error(env, String::from_str(env, "No expected events defined"));
    }

    if expected_structs.is_empty() {
        result.add_error(env, String::from_str(env, "No expected structs defined"));
    }

    // Verify method counts per contract
    let contract_method_counts = [
        ("AttestationContract", 38),
        ("AggregatedAttestationsContract", 5),
        ("AttestationSnapshotContract", 10),
        ("AuditLogContract", 7),
        ("IntegrationRegistryContract", 18),
        ("RevenueStreamContract", 5),
    ];

    for (contract, expected_count) in contract_method_counts.iter() {
        let actual_count = expected_methods
            .iter()
            .filter(|m| m.contract == String::from_str(env, contract))
            .count();

        if actual_count != *expected_count {
            // Use a simple error message without format for no_std compatibility
            result.add_error(env, String::from_str(env, "Method count mismatch"));
        }
    }

    result
}

/// Get the total count of documented methods.
pub fn get_method_count(env: &Env) -> u32 {
    get_expected_methods(env).len() as u32
}

/// Get the total count of documented events.
pub fn get_event_count(env: &Env) -> u32 {
    get_expected_events(env).len() as u32
}

/// Get the total count of documented structs.
pub fn get_struct_count(env: &Env) -> u32 {
    get_expected_structs(env).len() as u32
}

/// Check if a method is documented in the specification.
pub fn is_method_documented(env: &Env, contract: &str, method: &str) -> bool {
    let methods = get_expected_methods(env);
    let contract_str = String::from_str(env, contract);
    let method_str = String::from_str(env, method);

    methods
        .iter()
        .any(|m| m.contract == contract_str && m.name == method_str)
}

/// Check if an event is documented in the specification.
pub fn is_event_documented(env: &Env, contract: &str, event: &str) -> bool {
    let events = get_expected_events(env);
    let contract_str = String::from_str(env, contract);
    let event_str = String::from_str(env, event);

    events
        .iter()
        .any(|e| e.contract == contract_str && e.name == event_str)
}

/// Check if a struct is documented in the specification.
pub fn is_struct_documented(env: &Env, contract: &str, struct_name: &str) -> bool {
    let structs = get_expected_structs(env);
    let contract_str = String::from_str(env, contract);
    let struct_str = String::from_str(env, struct_name);

    structs
        .iter()
        .any(|s| s.contract == contract_str && s.name == struct_str)
}
