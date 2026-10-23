/// Emergency pause bypass requiring two independent hardware keys.
/// Bypasses multisig time-locks for zero-day incident response.
///
/// This function allows immediate emergency pausing of the contract
/// by requiring two distinct hardware key signatures from the owner
/// set (or appropriate privileges), providing strong security while
/// eliminating review window delays.
///
/// # Arguments
/// * `sig1` - First hardware key signature
/// * `sig2` - Second hardware key signature (must be from different key)
///
/// # Events
/// Emits EmergencyPauseTriggered event on success
///
/// # Panics
/// - If either signature is invalid
/// - If signatures come from the same key
/// - If either key is not in owner set
/// - If contract is already paused
pub fn emergency_pause(env: &Env, signer1: &Address, signer2: &Address) {
    // Ensure distinct signers (different hardware keys) before any auth/state change.
    assert!(
        signer1 != signer2,
        "both signatures must come from distinct keys"
    );

    // Validate both addresses are in owner set.
    let owners = get_owners(env);
    assert!(owners.contains(signer1), "first signature not from owner");
    assert!(owners.contains(signer2), "second signature not from owner");

    // Verify contract is not already paused before proceeding.
    if is_paused(env) {
        panic!("contract already paused");
    }

    // Execute pause using access control module.
    access_control::emergency_pause_execute(env, signer1, signer2);
}
