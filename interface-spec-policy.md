# Interface Specification Policy (Veritasor Contracts)

This document outlines the strict guidelines for cross-crate compatibility, interface regression testing, and security invariants for all Soroban contracts within the Veritasor ecosystem.

## 1. Invariants & ABI-Like Assumptions
To maintain cross-contract assumptions (attestation registry, staking, revenue modules), the following invariants are strictly enforced:
* **Function Signatures:** Any change to arguments, types, or return values of a public exported function requires a `PROTOCOL_VERSION` bump.
* **Struct/Event Layouts:** Adding, removing, or reordering fields in structs or changing event topics is considered a breaking change.
* **Bounded Storage:** Interface spec checks must run within bounded limits. Do not load unlimited vectors of strings during spec verification.

## 2. Failure Modes
If the `verify_interface_consistency` or `verify_cross_crate_version` checks fail:
* **CI/CD:** The build will immediately hard-fail.
* **On-Chain:** If run defensively on-chain, cross-contract calls will trap and revert the transaction to prevent data corruption between incompatible crate versions.

## 3. Operator & Admin Responsibilities
When deploying an upgrade:
1. Ensure all dependent crates have matching `PROTOCOL_VERSION` identifiers.
2. Run `cargo llvm-cov --workspace` to ensure new interfaces hit the **95% minimum coverage** requirement. Any gap must be explicitly documented in the PR under a "Risk Acceptance" header.
3. Node operators must verify that the new WASM hash corresponds to a spec-passing commit.

## 4. Security & Authentication Checks
* Interface spec tests run `![no_std]` and do not modify contract state.
* The tests explicitly DO NOT bypass `require_auth()` checks in the target contracts.
* Reentrancy is inherently prevented during spec checks as no cross-contract calls invoke external untrusted logic during verification.