//! # On-Chain Audit Log Contract
//!
//! Append-only audit log for key protocol actions. Records reference
//! originating contracts and actors. Strong integrity: append-only.
//!
//! ## Record schema
//!
//! Each entry stores: actor, source contract, action type, optional payload hash, ledger timestamp.
//! Ordered by sequence number. Queries by actor or by contract supported via indexes.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec};
use veritasor_common::replay_protection;

#[cfg(test)]
mod test;

/// Nonce channels for replay protection
pub const NONCE_CHANNEL_ADMIN: u32 = 1;

#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    Admin,
    /// Next sequence number (monotonic).
    NextSeq,
    /// Log entry by sequence number.
    Entry(u64),
    /// Index: actor -> list of seq numbers (append-only).
    ActorIndex(Address),
    /// Index: contract -> list of seq numbers (append-only).
    ContractIndex(Address),
}

/// Compact audit record for protocol events.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AuditRecord {
    /// Sequence number (monotonic).
    pub seq: u64,
    /// Address that performed the action (actor).
    pub actor: Address,
    /// Contract where the action originated.
    pub source_contract: Address,
    /// Action type (e.g. "submit_attestation", "revoke", "migrate").
    pub action: String,
    /// Optional payload or reference (e.g. hash). Empty string if none.
    pub payload: String,
    /// Ledger sequence at append time.
    pub ledger_seq: u32,
}

#[contract]
pub struct AuditLogContract;

#[contractimpl]
impl AuditLogContract {
    /// Initialize with admin. Only admin can authorize emitters.
    /// Initialize the audit log with an admin address.
    ///
    /// # Replay Protection
    /// Uses admin address and `NONCE_CHANNEL_ADMIN` channel.
    /// First call must use nonce 0.
    pub fn initialize(env: Env, admin: Address, nonce: u64) {
        admin.require_auth();

        // Verify and increment nonce for replay protection
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);

        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::NextSeq, &0u64);
    }

    /// Add an audit record. Callable by admin with replay protection.
    ///
    /// # Replay Protection
    /// Uses admin address and `NONCE_CHANNEL_ADMIN` channel.
    ///
    /// # Arguments
    /// * `nonce` - Current nonce for admin, must match stored value
    /// * `actor` - Address that performed the action being logged
    /// * `source_contract` - Contract where the action originated
    /// * `action` - Action type identifier
    /// * `payload` - Optional payload or reference hash
    pub fn append(
        env: Env,
        nonce: u64,
        actor: Address,
        source_contract: Address,
        action: String,
        payload: String,
    ) -> u64 {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        // Verify and increment nonce for replay protection
        replay_protection::verify_and_increment_nonce(&env, &admin, NONCE_CHANNEL_ADMIN, nonce);
        let seq: u64 = env.storage().instance().get(&DataKey::NextSeq).unwrap_or(0);
        let ledger_seq = env.ledger().sequence();
        let record = AuditRecord {
            seq,
            actor: actor.clone(),
            source_contract: source_contract.clone(),
            action,
            payload,
            ledger_seq,
        };
        env.storage().instance().set(&DataKey::Entry(seq), &record);
        env.storage().instance().set(&DataKey::NextSeq, &(seq + 1));

        let mut actor_seqs: Vec<u64> = env
            .storage()
            .instance()
            .get(&DataKey::ActorIndex(actor.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        actor_seqs.push_back(seq);
        env.storage()
            .instance()
            .set(&DataKey::ActorIndex(actor), &actor_seqs);

        let mut contract_seqs: Vec<u64> = env
            .storage()
            .instance()
            .get(&DataKey::ContractIndex(source_contract.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        contract_seqs.push_back(seq);
        env.storage()
            .instance()
            .set(&DataKey::ContractIndex(source_contract), &contract_seqs);

        seq
    }

    /// Get total number of log entries.
    pub fn get_log_count(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::NextSeq).unwrap_or(0)
    }

    /// Get a single record by sequence number.
    pub fn get_entry(env: Env, seq: u64) -> Option<AuditRecord> {
        env.storage().instance().get(&DataKey::Entry(seq))
    }

    /// Get sequence numbers for an actor (ordered).
    pub fn get_seqs_by_actor(env: Env, actor: Address) -> Vec<u64> {
        env.storage()
            .instance()
            .get(&DataKey::ActorIndex(actor))
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Get sequence numbers for a source contract (ordered).
    pub fn get_seqs_by_contract(env: Env, source_contract: Address) -> Vec<u64> {
        env.storage()
            .instance()
            .get(&DataKey::ContractIndex(source_contract))
            .unwrap_or_else(|| Vec::new(&env))
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
