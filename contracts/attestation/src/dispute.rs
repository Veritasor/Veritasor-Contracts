//! Dispute management module for attestation challenges
use soroban_sdk::{contracttype, Address, Env, String, Vec};

/// Status of a dispute
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum DisputeStatus {
    /// Dispute is open and awaiting resolution
    Open,
    /// Dispute has been resolved but not yet closed
    Resolved,
    /// Dispute is closed and final
    Closed,
}

/// Type of dispute being raised
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum DisputeType {
    /// Disputed revenue amount differs from claimed amount
    RevenueMismatch,
    /// Disputed data integrity or authenticity
    DataIntegrity,
    /// Other type of dispute
    Other,
}

/// Resolution outcome of a dispute
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum DisputeOutcome {
    /// Dispute upheld - challenger wins
    Upheld,
    /// Dispute rejected - original attestation stands
    Rejected,
    /// Dispute settled - partial resolution
    Settled,
}

/// Resolution details when a dispute is resolved
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct DisputeResolution {
    /// Address of the party resolving the dispute
    pub resolver: Address,
    /// Outcome of the dispute resolution
    pub outcome: DisputeOutcome,
    /// Timestamp when resolution occurred
    pub timestamp: u64,
    /// Optional notes about the resolution
    pub notes: String,
}

/// Optional resolution (contracttype-compatible alternative to Option<DisputeResolution>).
#[derive(Clone, Debug, PartialEq)]
#[contracttype]
pub enum MaybeResolution {
    None,
    Some(DisputeResolution),
}

impl MaybeResolution {
    pub fn is_none(&self) -> bool {
        matches!(self, MaybeResolution::None)
    }
    pub fn is_some(&self) -> bool {
        matches!(self, MaybeResolution::Some(_))
    }
    pub fn unwrap(self) -> DisputeResolution {
        match self {
            MaybeResolution::Some(r) => r,
            MaybeResolution::None => panic!("called unwrap on None"),
        }
    }
    pub fn as_ref(&self) -> core::option::Option<&DisputeResolution> {
        match self {
            MaybeResolution::Some(r) => core::option::Option::Some(r),
            MaybeResolution::None => core::option::Option::None,
        }
    }
}

/// Dispute record for a challenged attestation
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Dispute {
    /// Unique identifier for this dispute
    pub id: u64,
    /// Address of the party challenging the attestation
    pub challenger: Address,
    /// Business address associated with the attestation
    pub business: Address,
    /// Period of the attestation being disputed
    pub period: String,
    /// Status of the dispute
    pub status: DisputeStatus,
    /// Type of dispute being raised
    pub dispute_type: DisputeType,
    /// Evidence or description of the dispute
    pub evidence: String,
    /// Timestamp when dispute was opened
    pub timestamp: u64,
    /// Resolution details (None if not yet resolved)
    pub resolution: MaybeResolution,
}

/// Storage keys for dispute management
#[contracttype]
#[derive(Clone)]
enum DisputeKey {
    /// Counter for generating unique dispute IDs
    DisputeIdCounter,
    /// Individual dispute record: (dispute_id) -> Dispute
    Dispute(u64),
    /// Resolution for a dispute: (dispute_id) -> DisputeResolution
    DisputeResolution(u64),
    /// Disputes by attestation: (business, period) -> Vec<dispute_id>
    DisputesByAttestation(Address, String),
    /// Disputes by challenger: (challenger) -> Vec<dispute_id>
    DisputesByChallenger(Address),
}

/// Generate next unique dispute ID
pub fn generate_dispute_id(env: &Env) -> u64 {
    let key = DisputeKey::DisputeIdCounter;
    let current = env.storage().instance().get(&key).unwrap_or(0u64);
    let next = current + 1;
    env.storage().instance().set(&key, &next);
    next
}

/// Store a dispute record
pub fn store_dispute(env: &Env, dispute: &Dispute) {
    let key = DisputeKey::Dispute(dispute.id);
    env.storage().instance().set(&key, dispute);
}

/// Retrieve a dispute by ID
pub fn get_dispute(env: &Env, dispute_id: u64) -> Option<Dispute> {
    let key = DisputeKey::Dispute(dispute_id);
    env.storage().instance().get(&key)
}

/// Store a dispute resolution
pub fn store_dispute_resolution(env: &Env, dispute_id: u64, resolution: &DisputeResolution) {
    let key = DisputeKey::DisputeResolution(dispute_id);
    env.storage().instance().set(&key, resolution);
}

/// Retrieve a dispute resolution by dispute ID
pub fn get_dispute_resolution(env: &Env, dispute_id: u64) -> Option<DisputeResolution> {
    let key = DisputeKey::DisputeResolution(dispute_id);
    env.storage().instance().get(&key)
}

/// Get all dispute IDs for a specific attestation
pub fn get_dispute_ids_by_attestation(env: &Env, business: &Address, period: &String) -> Vec<u64> {
    let key = DisputeKey::DisputesByAttestation(business.clone(), period.clone());
    env.storage()
        .instance()
        .get(&key)
        .unwrap_or_else(|| Vec::new(env))
}

/// Add dispute ID to attestation index
pub fn add_dispute_to_attestation_index(
    env: &Env,
    business: &Address,
    period: &String,
    dispute_id: u64,
) {
    let key = DisputeKey::DisputesByAttestation(business.clone(), period.clone());
    let mut disputes = get_dispute_ids_by_attestation(env, business, period);
    disputes.push_back(dispute_id);
    env.storage().instance().set(&key, &disputes);
}

/// Get all dispute IDs opened by a challenger
pub fn get_dispute_ids_by_challenger(env: &Env, challenger: &Address) -> Vec<u64> {
    let key = DisputeKey::DisputesByChallenger(challenger.clone());
    env.storage()
        .instance()
        .get(&key)
        .unwrap_or_else(|| Vec::new(env))
}

/// Add dispute ID to challenger index
pub fn add_dispute_to_challenger_index(env: &Env, challenger: &Address, dispute_id: u64) {
    let key = DisputeKey::DisputesByChallenger(challenger.clone());
    let mut disputes = get_dispute_ids_by_challenger(env, challenger);
    disputes.push_back(dispute_id);
    env.storage().instance().set(&key, &disputes);
}

/// Check if a challenger has already opened a dispute for this attestation
pub fn has_existing_dispute(
    env: &Env,
    challenger: &Address,
    business: &Address,
    period: &String,
) -> bool {
    let dispute_ids = get_dispute_ids_by_attestation(env, business, period);
    for i in 0..dispute_ids.len() {
        if let Some(dispute_id) = dispute_ids.get(i) {
            if let Some(dispute) = get_dispute(env, dispute_id) {
                if dispute.challenger == *challenger {
                    return true;
                }
            }
        }
    }
    false
}

/// Validate that a dispute can be opened (authorized challenger, valid attestation exists)
pub fn validate_dispute_eligibility(
    env: &Env,
    challenger: &Address,
    business: &Address,
    period: &String,
) -> Result<(), &'static str> {
    // Check if attestation exists
    let attestation_key = (business.clone(), period.clone());
    if !env.storage().instance().has(&attestation_key) {
        return Err("no attestation exists for this business and period");
    }

    // Check if challenger already has an open dispute for this attestation
    if has_existing_dispute(env, challenger, business, period) {
        return Err("challenger already has an open dispute for this attestation");
    }

    // In a real implementation, we would check if challenger is authorized
    // (e.g., is a lender in a registry, or has permission from business)
    // For now, we'll allow any address to challenge
    Ok(())
}

/// Validate that a dispute can be resolved
pub fn validate_dispute_resolution(
    env: &Env,
    dispute_id: u64,
    _resolver: &Address,
) -> Result<Dispute, &'static str> {
    let dispute = get_dispute(env, dispute_id).ok_or("dispute not found")?;

    if dispute.status != DisputeStatus::Open {
        return Err("dispute is not open");
    }

    // In a real implementation, we would check if resolver is authorized
    // (e.g., is an arbitrator, governance contract, or predefined resolver)
    // For now, we'll allow any address to resolve
    Ok(dispute)
}

/// Validate that a dispute can be closed
pub fn validate_dispute_closure(env: &Env, dispute_id: u64) -> Result<Dispute, &'static str> {
    let dispute = get_dispute(env, dispute_id).ok_or("dispute not found")?;

    if dispute.status != DisputeStatus::Resolved {
        return Err("dispute is not resolved");
    }

    Ok(dispute)
}
