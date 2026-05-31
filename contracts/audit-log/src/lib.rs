//! # On-Chain Audit Log Contract
//!
//! Append-only audit log for key protocol actions. Records reference
//! originating contracts and actors. Strong integrity: append-only
//! and tamper-evident via hash chaining.
//!
//! ## Record schema
//!
//! Each entry stores: actor, source contract, action type, optional payload hash,
//! ledger timestamp, previous entry hash, and current entry hash.
//! Ordered by sequence number. Queries by actor or by contract supported via indexes.

#![no_std]

#[cfg(test)]
extern crate std;

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String, Vec};
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
    /// Hash of the latest appended entry (chain head).
    LastHash,
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
    /// Hash of the previous entry in the chain.
    pub prev_hash: BytesN<32>,
    /// Hash of this entry.
    pub entry_hash: BytesN<32>,
}

/// Deterministic material used to derive the tamper-evident entry hash.
#[contracttype]
#[derive(Clone, Debug)]
struct AuditRecordHashInput {
    pub seq: u64,
    pub actor: Address,
    pub source_contract: Address,
    pub action: String,
    pub payload: String,
    pub ledger_seq: u32,
    pub prev_hash: BytesN<32>,
}

fn zero_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

fn compute_entry_hash(
    env: &Env,
    seq: u64,
    actor: &Address,
    source_contract: &Address,
    action: &String,
    payload: &String,
    ledger_seq: u32,
    prev_hash: &BytesN<32>,
) -> BytesN<32> {
    let hash_input = AuditRecordHashInput {
        seq,
        actor: actor.clone(),
        source_contract: source_contract.clone(),
        action: action.clone(),
        payload: payload.clone(),
        ledger_seq,
        prev_hash: prev_hash.clone(),
    };

    let encoded = hash_input.to_xdr(env);
    env.crypto().sha256(&encoded).into()
}

#[contract]
pub struct AuditLogContract;

#[contractimpl]
impl AuditLogContract {
    /// Initialize with admin. Only admin can authorize emitters.
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
        env.storage()
            .instance()
            .set(&DataKey::LastHash, &zero_hash(&env));
    }

    /// Add an audit record. Callable by admin with replay protection.
    ///
    /// Each appended entry is chained to the previous one via `prev_hash`.
    /// This makes any modification of historical entries detectable because
    /// the chain head would no longer be reproducible.
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

        let prev_hash: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::LastHash)
            .unwrap_or_else(|| zero_hash(&env));

        let entry_hash = compute_entry_hash(
            &env,
            seq,
            &actor,
            &source_contract,
            &action,
            &payload,
            ledger_seq,
            &prev_hash,
        );

        let record = AuditRecord {
            seq,
            actor: actor.clone(),
            source_contract: source_contract.clone(),
            action,
            payload,
            ledger_seq,
            prev_hash: prev_hash.clone(),
            entry_hash: entry_hash.clone(),
        };

        env.storage().instance().set(&DataKey::Entry(seq), &record);
        env.storage().instance().set(&DataKey::NextSeq, &(seq + 1));
        env.storage()
            .instance()
            .set(&DataKey::LastHash, &entry_hash);

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

    /// Get the current chain head hash.
    pub fn get_last_hash(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::LastHash)
            .unwrap_or_else(|| zero_hash(&env))
    }

    /// Get the current nonce for replay protection.
    /// Returns the nonce value that must be supplied on the next call.
    pub fn get_replay_nonce(env: Env, actor: Address, channel: u32) -> u64 {
        replay_protection::get_nonce(&env, &actor, channel)
    }
}
