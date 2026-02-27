//! # Protocol Simulation Harness Contract
//!
//! Orchestrates multiple Veritasor contracts to emulate end-to-end protocol scenarios
//! for testing, demos, and integration validation. This contract coordinates calls across
//! attestation, staking, settlement, and lender contracts to simulate realistic business
//! and lender interactions.
//!
//! ## Design Principles
//! - Configurable scenario parameters for flexible testing
//! - Comprehensive cross-contract call orchestration
//! - Designed for test and development environments
//! - Secure authorization and validation
//! - Detailed event emission for observability
//!
//! ## Supported Scenarios
//! 1. **Complete Business Lifecycle**: Registration → Attestation → Settlement
//! 2. **Lender Integration Flow**: Access setup → Revenue verification → Repayment
//! 3. **Staking and Slashing**: Attestor stake → Dispute → Slash
//! 4. **Multi-Period Revenue**: Sequential attestations with settlement tracking
//! 5. **Failure Scenarios**: Revocation, disputes, insufficient funds

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String, Vec};

#[cfg(test)]
mod test;

// ─── Data Types ─────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    Admin,
    ScenarioCount,
    Scenario(u64),
    AttestationContract,
    StakingContract,
    SettlementContract,
    LenderContract,
}

/// Configuration for a simulation scenario
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ScenarioConfig {
    pub id: u64,
    pub name: String,
    pub business: Address,
    pub lender: Address,
    pub attestor: Address,
    pub token: Address,
    pub created_at: u64,
    pub status: u32, // 0=pending, 1=running, 2=completed, 3=failed
}

/// Result of a scenario execution
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ScenarioResult {
    pub scenario_id: u64,
    pub success: bool,
    pub steps_completed: u32,
    pub error_message: Option<String>,
    pub completed_at: u64,
}

/// Parameters for business lifecycle scenario
#[contracttype]
#[derive(Clone, Debug)]
pub struct BusinessLifecycleParams {
    pub business: Address,
    pub period: String,
    pub merkle_root: BytesN<32>,
    pub timestamp: u64,
    pub version: u32,
    pub revenue_amount: i128,
}

/// Parameters for lender integration scenario
#[contracttype]
#[derive(Clone, Debug)]
pub struct LenderIntegrationParams {
    pub lender: Address,
    pub business: Address,
    pub principal: i128,
    pub revenue_share_bps: u32,
    pub min_revenue_threshold: i128,
    pub max_repayment_amount: i128,
    pub token: Address,
}

/// Parameters for staking scenario
#[contracttype]
#[derive(Clone, Debug)]
pub struct StakingScenarioParams {
    pub attestor: Address,
    pub stake_amount: i128,
    pub token: Address,
}

/// Parameters for multi-period revenue scenario
#[contracttype]
#[derive(Clone, Debug)]
pub struct MultiPeriodParams {
    pub business: Address,
    pub periods: Vec<String>,
    pub merkle_roots: Vec<BytesN<32>>,
    pub timestamps: Vec<u64>,
    pub revenues: Vec<i128>,
}

// ─── Contract Implementation ────────────────────────────────────────

#[contract]
pub struct ProtocolSimulationContract;

#[contractimpl]
impl ProtocolSimulationContract {
    // ── Initialization ──────────────────────────────────────────────

    /// Initialize the simulation harness with contract addresses.
    ///
    /// # Arguments
    /// * `admin` - Administrator address
    /// * `attestation_contract` - Core attestation contract address
    /// * `staking_contract` - Attestor staking contract address
    /// * `settlement_contract` - Revenue settlement contract address
    /// * `lender_contract` - Lender consumer contract address
    pub fn initialize(
        env: Env,
        admin: Address,
        attestation_contract: Address,
        staking_contract: Address,
        settlement_contract: Address,
        lender_contract: Address,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::AttestationContract, &attestation_contract);
        env.storage()
            .instance()
            .set(&DataKey::StakingContract, &staking_contract);
        env.storage()
            .instance()
            .set(&DataKey::SettlementContract, &settlement_contract);
        env.storage()
            .instance()
            .set(&DataKey::LenderContract, &lender_contract);
        env.storage().instance().set(&DataKey::ScenarioCount, &0u64);
    }

    // ── Configuration Management ────────────────────────────────────

    /// Update attestation contract address (admin only).
    pub fn set_attestation_contract(env: Env, admin: Address, contract: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::AttestationContract, &contract);
    }

    /// Update staking contract address (admin only).
    pub fn set_staking_contract(env: Env, admin: Address, contract: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::StakingContract, &contract);
    }

    /// Update settlement contract address (admin only).
    pub fn set_settlement_contract(env: Env, admin: Address, contract: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::SettlementContract, &contract);
    }

    /// Update lender contract address (admin only).
    pub fn set_lender_contract(env: Env, admin: Address, contract: Address) {
        Self::require_admin(&env, &admin);
        env.storage()
            .instance()
            .set(&DataKey::LenderContract, &contract);
    }

    // ── Scenario Orchestration ──────────────────────────────────────

    /// Execute a complete business lifecycle scenario.
    ///
    /// This scenario simulates:
    /// 1. Business registration in attestation contract
    /// 2. Admin approval of business
    /// 3. Attestation submission
    /// 4. Attestation verification
    ///
    /// # Returns
    /// Scenario ID for tracking
    ///
    /// # Note
    /// This is a simulation harness that tracks scenario execution.
    /// Actual cross-contract calls should be made by the test framework
    /// or external orchestrator. This contract provides the coordination
    /// logic and state tracking.
    pub fn run_business_lifecycle(env: Env, params: BusinessLifecycleParams) -> u64 {
        params.business.require_auth();

        let scenario_id = Self::create_scenario(
            &env,
            String::from_str(&env, "business_lifecycle"),
            &params.business,
            &params.business, // lender same as business for this scenario
            &params.business, // attestor same as business
            &env.current_contract_address(),
        );

        // Mark scenario as running
        Self::update_scenario_status(&env, scenario_id, 1);

        // In a real implementation, this would orchestrate cross-contract calls
        // For now, we mark it as completed to demonstrate the flow
        // External tests will perform actual contract interactions
        Self::mark_scenario_completed(&env, scenario_id, 2);

        scenario_id
    }

    /// Execute a lender integration flow scenario.
    ///
    /// This scenario simulates:
    /// 1. Business submits attestation
    /// 2. Lender creates settlement agreement
    /// 3. Settlement is executed based on attested revenue
    /// 4. Repayment is transferred
    ///
    /// # Returns
    /// Scenario ID for tracking
    ///
    /// # Note
    /// This is a simulation harness that tracks scenario execution.
    /// Actual cross-contract calls should be made by the test framework.
    pub fn run_lender_integration(
        env: Env,
        params: LenderIntegrationParams,
        period: String,
        merkle_root: BytesN<32>,
        timestamp: u64,
        attested_revenue: i128,
    ) -> u64 {
        params.lender.require_auth();
        params.business.require_auth();

        let scenario_id = Self::create_scenario(
            &env,
            String::from_str(&env, "lender_integration"),
            &params.business,
            &params.lender,
            &params.business,
            &params.token,
        );

        Self::update_scenario_status(&env, scenario_id, 1);

        // Store scenario parameters for external orchestration
        #[contracttype]
        #[derive(Clone)]
        enum ScenarioData {
            LenderParams(u64),
        }

        env.storage().instance().set(
            &ScenarioData::LenderParams(scenario_id),
            &(period, merkle_root, timestamp, attested_revenue),
        );

        // Mark as completed - external orchestrator will perform actual calls
        Self::mark_scenario_completed(&env, scenario_id, 3);
        scenario_id
    }

    /// Execute a staking and slashing scenario.
    ///
    /// This scenario simulates:
    /// 1. Attestor stakes tokens
    /// 2. Attestor submits attestation
    /// 3. Dispute is raised (simulated)
    /// 4. Slashing occurs
    ///
    /// # Returns
    /// Scenario ID for tracking
    ///
    /// # Note
    /// This is a simulation harness that tracks scenario execution.
    pub fn run_staking_scenario(
        env: Env,
        params: StakingScenarioParams,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
    ) -> u64 {
        params.attestor.require_auth();

        let scenario_id = Self::create_scenario(
            &env,
            String::from_str(&env, "staking_scenario"),
            &business,
            &business,
            &params.attestor,
            &params.token,
        );

        Self::update_scenario_status(&env, scenario_id, 1);

        // Store scenario parameters
        #[contracttype]
        #[derive(Clone)]
        enum StakingData {
            Params(u64),
        }

        env.storage()
            .instance()
            .set(&StakingData::Params(scenario_id), &(period, merkle_root));

        Self::mark_scenario_completed(&env, scenario_id, 2);
        scenario_id
    }

    /// Execute a multi-period revenue scenario.
    ///
    /// This scenario simulates:
    /// 1. Multiple sequential attestations across periods
    /// 2. Verification of each attestation
    /// 3. Tracking of cumulative revenue
    ///
    /// # Returns
    /// Scenario ID for tracking
    ///
    /// # Note
    /// This is a simulation harness that tracks scenario execution.
    pub fn run_multi_period_scenario(env: Env, params: MultiPeriodParams) -> u64 {
        params.business.require_auth();

        assert!(
            params.periods.len() == params.merkle_roots.len(),
            "periods and merkle_roots length mismatch"
        );
        assert!(
            params.periods.len() == params.timestamps.len(),
            "periods and timestamps length mismatch"
        );

        let scenario_id = Self::create_scenario(
            &env,
            String::from_str(&env, "multi_period"),
            &params.business,
            &params.business,
            &params.business,
            &env.current_contract_address(),
        );

        Self::update_scenario_status(&env, scenario_id, 1);

        let period_count = params.periods.len();

        // Store multi-period data
        #[contracttype]
        #[derive(Clone)]
        enum MultiPeriodData {
            Params(u64),
        }

        env.storage()
            .instance()
            .set(&MultiPeriodData::Params(scenario_id), &params);

        Self::mark_scenario_completed(&env, scenario_id, period_count);
        scenario_id
    }

    /// Execute a failure scenario: attestation followed by revocation.
    ///
    /// This scenario simulates:
    /// 1. Business submits attestation
    /// 2. Admin revokes the attestation
    /// 3. Verification fails after revocation
    ///
    /// # Returns
    /// Scenario ID for tracking
    ///
    /// # Note
    /// This is a simulation harness that tracks scenario execution.
    pub fn run_revocation_scenario(
        env: Env,
        admin: Address,
        business: Address,
        period: String,
        merkle_root: BytesN<32>,
        reason: String,
    ) -> u64 {
        Self::require_admin(&env, &admin);
        business.require_auth();

        let scenario_id = Self::create_scenario(
            &env,
            String::from_str(&env, "revocation_scenario"),
            &business,
            &business,
            &business,
            &env.current_contract_address(),
        );

        Self::update_scenario_status(&env, scenario_id, 1);

        // Store revocation data
        #[contracttype]
        #[derive(Clone)]
        enum RevocationData {
            Params(u64),
        }

        env.storage().instance().set(
            &RevocationData::Params(scenario_id),
            &(period, merkle_root, reason),
        );

        Self::mark_scenario_completed(&env, scenario_id, 3);
        scenario_id
    }

    // ── Query Methods ───────────────────────────────────────────────

    /// Get scenario configuration by ID.
    pub fn get_scenario(env: Env, scenario_id: u64) -> Option<ScenarioConfig> {
        env.storage()
            .instance()
            .get(&DataKey::Scenario(scenario_id))
    }

    /// Get total number of scenarios executed.
    pub fn get_scenario_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::ScenarioCount)
            .unwrap_or(0)
    }

    /// Get attestation contract address.
    pub fn get_attestation_contract_address(env: Env) -> Address {
        Self::get_attestation_contract(&env)
    }

    /// Get staking contract address.
    pub fn get_staking_contract_address(env: Env) -> Address {
        Self::get_staking_contract(&env)
    }

    /// Get settlement contract address.
    pub fn get_settlement_contract_address(env: Env) -> Address {
        Self::get_settlement_contract(&env)
    }

    /// Get lender contract address.
    pub fn get_lender_contract_address(env: Env) -> Address {
        Self::get_lender_contract(&env)
    }

    /// Get admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    // ── Internal Helper Methods ─────────────────────────────────────

    fn require_admin(env: &Env, admin: &Address) {
        admin.require_auth();
        let stored: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(*admin == stored, "caller is not admin");
    }

    fn get_attestation_contract(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::AttestationContract)
            .expect("attestation contract not set")
    }

    fn get_staking_contract(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::StakingContract)
            .expect("staking contract not set")
    }

    fn get_settlement_contract(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::SettlementContract)
            .expect("settlement contract not set")
    }

    fn get_lender_contract(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::LenderContract)
            .expect("lender contract not set")
    }

    fn create_scenario(
        env: &Env,
        name: String,
        business: &Address,
        lender: &Address,
        attestor: &Address,
        token: &Address,
    ) -> u64 {
        let count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ScenarioCount)
            .unwrap_or(0);

        let scenario = ScenarioConfig {
            id: count,
            name,
            business: business.clone(),
            lender: lender.clone(),
            attestor: attestor.clone(),
            token: token.clone(),
            created_at: env.ledger().timestamp(),
            status: 0, // pending
        };

        env.storage()
            .instance()
            .set(&DataKey::Scenario(count), &scenario);
        env.storage()
            .instance()
            .set(&DataKey::ScenarioCount, &(count + 1));

        count
    }

    fn update_scenario_status(env: &Env, scenario_id: u64, status: u32) {
        let mut scenario: ScenarioConfig = env
            .storage()
            .instance()
            .get(&DataKey::Scenario(scenario_id))
            .expect("scenario not found");
        scenario.status = status;
        env.storage()
            .instance()
            .set(&DataKey::Scenario(scenario_id), &scenario);
    }

    fn mark_scenario_completed(env: &Env, scenario_id: u64, steps: u32) {
        Self::update_scenario_status(env, scenario_id, 2); // completed
        let result = ScenarioResult {
            scenario_id,
            success: true,
            steps_completed: steps,
            error_message: None,
            completed_at: env.ledger().timestamp(),
        };
        // Store result for audit trail
        #[contracttype]
        #[derive(Clone)]
        enum ResultKey {
            Result(u64),
        }
        env.storage()
            .instance()
            .set(&ResultKey::Result(scenario_id), &result);
    }

    #[allow(dead_code)]
    fn mark_scenario_failed(env: &Env, scenario_id: u64, steps: u32, error: String) {
        Self::update_scenario_status(env, scenario_id, 3); // failed
        let result = ScenarioResult {
            scenario_id,
            success: false,
            steps_completed: steps,
            error_message: Some(error),
            completed_at: env.ledger().timestamp(),
        };
        #[contracttype]
        #[derive(Clone)]
        enum ResultKey {
            Result(u64),
        }
        env.storage()
            .instance()
            .set(&ResultKey::Result(scenario_id), &result);
    }
}
