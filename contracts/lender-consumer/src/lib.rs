#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String};
use veritasor_attestation::AttestationContractClient;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    CoreAttestation,
    RevenueMetrics(Address, String),
    Dispute(Address, String),
    LatestIndexedPeriod(Address),
}

#[contracttype]
#[derive(Clone)]
pub struct RevenueMetrics {
    pub has_value: bool,
    pub period_revenue: i128,
    pub trailing_3m_revenue: i128,
    pub trailing_12m_revenue: i128,
}

#[contracttype]
#[derive(Clone)]
pub struct DisputeStatus {
    pub is_known: bool,
    pub is_disputed: bool,
    pub reason: Option<String>,
}

#[contracttype]
#[derive(Clone)]
pub struct LenderAttestationView {
    pub business: Address,
    pub period: String,
    pub merkle_root: BytesN<32>,
    pub timestamp: u64,
    pub version: u32,
    pub fee_paid: i128,
    pub revenue: RevenueMetrics,
    pub dispute: DisputeStatus,
}

#[contracttype]
#[derive(Clone)]
pub struct BusinessSummary {
    pub business: Address,
    pub attestation_count: u64,
    pub latest_period: Option<String>,
    pub latest_timestamp: Option<u64>,
    pub latest_version: Option<u32>,
    pub latest_fee_paid: Option<i128>,
    pub latest_dispute: DisputeStatus,
}

#[contract]
pub struct LenderConsumerContract;

fn read_admin(env: &Env) -> Address {
    let key = DataKey::Admin;
    env.storage()
        .instance()
        .get(&key)
        .expect("not initialized")
}

fn require_admin(env: &Env) {
    let admin = read_admin(env);
    admin.require_auth();
}

fn read_core_attestation(env: &Env) -> Address {
    let key = DataKey::CoreAttestation;
    env.storage()
        .instance()
        .get(&key)
        .expect("core attestation not set")
}

fn attestation_client(env: &Env) -> AttestationContractClient {
    let core = read_core_attestation(env);
    AttestationContractClient::new(env, &core)
}

fn get_latest_indexed_period(env: &Env, business: &Address) -> Option<String> {
    let key = DataKey::LatestIndexedPeriod(business.clone());
    env.storage().instance().get(&key)
}

fn set_latest_indexed_period(env: &Env, business: &Address, period: &String) {
    let key = DataKey::LatestIndexedPeriod(business.clone());
    env.storage().instance().set(&key, period);
}

fn read_revenue_metrics(env: &Env, business: &Address, period: &String) -> Option<RevenueMetrics> {
    let key = DataKey::RevenueMetrics(business.clone(), period.clone());
    env.storage().instance().get(&key)
}

fn write_revenue_metrics(
    env: &Env,
    business: &Address,
    period: &String,
    metrics: &RevenueMetrics,
) {
    let key = DataKey::RevenueMetrics(business.clone(), period.clone());
    env.storage().instance().set(&key, metrics);
}

fn read_dispute_status(env: &Env, business: &Address, period: &String) -> Option<DisputeStatus> {
    let key = DataKey::Dispute(business.clone(), period.clone());
    env.storage().instance().get(&key)
}

fn write_dispute_status(
    env: &Env,
    business: &Address,
    period: &String,
    status: &DisputeStatus,
) {
    let key = DataKey::Dispute(business.clone(), period.clone());
    env.storage().instance().set(&key, status);
}

#[contractimpl]
impl LenderConsumerContract {
    /// Initialize the lender-facing consumer.
    ///
    /// Sets the admin and the address of the core attestation contract.
    /// The provided `admin` must authorize the call.
    pub fn initialize(env: Env, admin: Address, core_attestation: Address) {
        let key = DataKey::Admin;
        if env.storage().instance().has(&key) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::CoreAttestation, &core_attestation);
    }

    /// Update the core attestation contract address.
    ///
    /// Only the admin may update the core contract reference.
    pub fn set_core_attestation(env: Env, core_attestation: Address) {
        require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::CoreAttestation, &core_attestation);
    }

    /// Record revenue metrics for a specific attested period.
    ///
    /// This method anchors lender-facing revenue aggregates (period and
    /// trailing sums) to an existing attestation in the core contract.
    /// The admin must authorize the call.
    ///
    /// Panics if the underlying attestation does not exist.
    pub fn record_revenue_metrics(
        env: Env,
        business: Address,
        period: String,
        period_revenue: i128,
        trailing_3m_revenue: i128,
        trailing_12m_revenue: i128,
    ) {
        require_admin(&env);

        let client = attestation_client(&env);
        let att = client.get_attestation(&business, &period);
        if att.is_none() {
            panic!("attestation not found for business and period");
        }

        let metrics = RevenueMetrics {
            has_value: true,
            period_revenue,
            trailing_3m_revenue,
            trailing_12m_revenue,
        };
        write_revenue_metrics(&env, &business, &period, &metrics);

        let latest = get_latest_indexed_period(&env, &business);
        match latest {
            None => set_latest_indexed_period(&env, &business, &period),
            Some(prev_period) => {
                let prev_att = client.get_attestation(&business, &prev_period);
                let (_, prev_ts, _, _) = prev_att.expect("missing latest indexed attestation");
                let (_, ts, _, _) = att.expect("attestation disappeared");
                if ts >= prev_ts {
                    set_latest_indexed_period(&env, &business, &period);
                }
            }
        }
    }

    /// Mark or clear a dispute or revocation for an attestation.
    ///
    /// Dispute statuses are surfaced to lenders without mutating the
    /// underlying attestation in the core contract. The admin must
    /// authorize the call.
    pub fn set_dispute_status(
        env: Env,
        business: Address,
        period: String,
        is_disputed: bool,
        reason: Option<String>,
    ) {
        require_admin(&env);

        let client = attestation_client(&env);
        let att = client.get_attestation(&business, &period);
        if att.is_none() {
            panic!("attestation not found for business and period");
        }

        let status = DisputeStatus {
            is_known: true,
            is_disputed,
            reason,
        };
        write_dispute_status(&env, &business, &period, &status);
    }

    /// Return a lender-oriented view of a single attestation.
    ///
    /// Combines raw attestation data from the core contract with
    /// lender-specific overlays such as revenue metrics and dispute
    /// status. Returns `None` if the attestation does not exist.
    pub fn get_lender_view(
        env: Env,
        business: Address,
        period: String,
    ) -> Option<LenderAttestationView> {
        let client = attestation_client(&env);
        let att = client.get_attestation(&business, &period);
        match att {
            None => None,
            Some((root, ts, ver, fee)) => {
                let revenue = read_revenue_metrics(&env, &business, &period)
                    .unwrap_or(RevenueMetrics {
                        has_value: false,
                        period_revenue: 0,
                        trailing_3m_revenue: 0,
                        trailing_12m_revenue: 0,
                    });
                let dispute = read_dispute_status(&env, &business, &period).unwrap_or(
                    DisputeStatus {
                        is_known: false,
                        is_disputed: false,
                        reason: None,
                    },
                );
                Some(LenderAttestationView {
                    business,
                    period,
                    merkle_root: root,
                    timestamp: ts,
                    version: ver,
                    fee_paid: fee,
                    revenue,
                    dispute,
                })
            }
        }
    }

    /// Return stored revenue metrics for a given attestation.
    pub fn get_trailing_revenue(
        env: Env,
        business: Address,
        period: String,
    ) -> RevenueMetrics {
        read_revenue_metrics(&env, &business, &period).unwrap_or(RevenueMetrics {
            has_value: false,
            period_revenue: 0,
            trailing_3m_revenue: 0,
            trailing_12m_revenue: 0,
        })
    }

    /// Return dispute status for a given attestation.
    pub fn get_dispute_status(
        env: Env,
        business: Address,
        period: String,
    ) -> DisputeStatus {
        read_dispute_status(&env, &business, &period).unwrap_or(DisputeStatus {
            is_known: false,
            is_disputed: false,
            reason: None,
        })
    }

    /// Return a summary view for a business.
    ///
    /// Exposes total attestation count from the core contract together
    /// with details for the latest indexed attestation and its dispute
    /// status.
    pub fn get_business_summary(env: Env, business: Address) -> BusinessSummary {
        let client = attestation_client(&env);
        let count = client.get_business_count(&business);

        let latest_period = get_latest_indexed_period(&env, &business);
        match latest_period {
            None => BusinessSummary {
                business,
                attestation_count: count,
                latest_period: None,
                latest_timestamp: None,
                latest_version: None,
                latest_fee_paid: None,
                latest_dispute: DisputeStatus {
                    is_known: false,
                    is_disputed: false,
                    reason: None,
                },
            },
            Some(period) => {
                let att = client
                    .get_attestation(&business, &period)
                    .expect("indexed period missing attestation");
                let (_, ts, ver, fee) = att;
                let dispute = read_dispute_status(&env, &business, &period).unwrap_or(
                    DisputeStatus {
                        is_known: false,
                        is_disputed: false,
                        reason: None,
                    },
                );
                BusinessSummary {
                    business,
                    attestation_count: count,
                    latest_period: Some(period),
                    latest_timestamp: Some(ts),
                    latest_version: Some(ver),
                    latest_fee_paid: Some(fee),
                    latest_dispute: dispute,
                }
            }
        }
    }
}

#[cfg(test)]
mod test;
