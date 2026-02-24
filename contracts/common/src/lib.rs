//! Shared test utilities and security invariant tests for Veritasor contracts.

#![cfg_attr(not(test), no_std)]

#[cfg(test)]
pub mod interface_spec_check;

#[cfg(test)]
pub mod interface_spec_check_test;

#[cfg(test)]
pub mod merkle;

#[cfg(test)]
pub mod merkle_fuzz_test;

#[cfg(test)]
pub mod security_invariant_test;
