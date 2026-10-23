    /// Emergency pause bypass (admin role, dual-key requirement).
    ///
    /// This function allows immediate emergency pausing of the contract,
    /// bypassing all multisig time‑lock mechanisms. It requires two
    /// independent hardware key signatures from the admin (or equivalent
    /// privileges) to mitigate single‑key compromise attacks.
    ///
    /// Used for zero‑day incident response without review windows.
    ///
    /// # Panics
    /// - Caller does not have ADMIN role
    /// - One or more signatures are invalid
    /// - Signatures come from the same key
    /// - Contract is already paused
    ///
    /// # Events
    /// Emits `EmergencyPauseTriggered` event
    pub fn emergency_pause(
        env: Env,
        caller: Address,
        signer1: Address,
        signer2: Address,
        nonce: u64,
    ) {
        access_control::require_admin(&env, &caller);
        replay_protection::verify_and_increment_nonce(&env, &caller, NONCE_CHANNEL_ADMIN, nonce);

        // Avoid re-authorizing the same frame twice when the caller is also one of
        // the dual-key signers. The public entrypoint already authorized `caller`;
        // we only need to authorize the additional signer(s) beyond that.
        if signer1 != caller {
            signer1.require_auth();
        }
        if signer2 != caller && signer2 != signer1 {
            signer2.require_auth();
        }

        multisig::emergency_pause(&env, &signer1, &signer2);
    }
