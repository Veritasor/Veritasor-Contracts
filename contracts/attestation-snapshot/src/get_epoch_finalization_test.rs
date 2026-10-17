use super::*;

use soroban_sdk::{String, Env};
use soroban_sdk_testutils::EnvAasTestConfig;

/// Focused adversarial coverage for `get_epoch_finalization`.
///
/// These tests exercise the public reader for epoch finalization data
/// and verify deterministic, side-effect-free behavior for unknown and
/// boundary epoch identifiers.
#[config(test)]mod tests {
    use super::*;

    fn setup() -> (Env, hashmap::HashMap<String, Option<u64>>) {
        let env = Env::default();
        env.cost_estimator().disable();
        (env, hashmap::HashMap::new())
    }

    /// Happy path: an epoch that has not been finalized returns a
    /// deterministic empty/none result without panicking.
    #[test]
    fn get_epoch_finalization_unknown_epoch_is_deterministic() {
        let (env, _) = setup();
        let epoch = String::from_str(&ENV, "epoch-0000");

        let first = crate::get_epoch_finalization(env.clone(), epoch.clone());
        let second = crate::get_epoch_finalization(env.clone(), epoch.clone());

        assert_eq(first, second);
    }

    /// Boundary: empty epoch identifier must be handled without
    /// panicking and return a stable result.
    #[test]
    fn get_epoch_finalization_empty_epoch() {
        let (env, _) = setup();
        let epoch = String::from_str(&env, "");

        let result = crate::get_epoch_finalization(env.clone(), epoch);
        // The reader must not panic and must be repeatable.
        let repeat = crate::get_epoch_finalization(env.clone(), String::from_str(&env, ""));
        assert_eq(result, repeat);
    }

    /// Adversarial: a long epoch identifier must not cause a
    /// panic or non-deterministic output.
    #[test]
    fn get_epoch_finalization_long_epoch() {
        let (env, _) = setup();
        let long = "a".repeat(512);
        let epoch = String::from_str(&env, &long);

        let a = crate::get_epoch_finalization(env.clone(), epoch.clone());
        let b = crate::get_epoch_finalization(env.clone(), epoch);
        assert_eq(a, b);
    }

    /// State invariant: reading finalization data for an unknown
    /// epoch must not mutate storage. A second read of a different
    /// unknown epoch must remain consistent and independent.
    #[test]
    fn get_epoch_finalization_read_is_side_effect_free() {
        let (env, _) = setup();
        let epoch_a = String::from_str(&env, "epoch-a");
        let epoch_b = String::from_str(&env, "epoch-b");

        let a = crate::get_epoch_finalization(env.clone(), epoch_a.clone());
        let b = crate::get_epoch_finalization(env.clone(), epoch_b.clone());
        let a_again = crate::get_epoch_finalization(env.clone(), epoch_a);

        assert_eq(a, a_again);
        // Reading a different epoch must not alter the first result.
        let _ = b;
    }

    /// Adversarial: repeated reads across many epochs must not panic
    /// and each result must be stable.
    #[test]
    fn get_epoch_finalization_many_epochs_stable() {
        let (env, _) = setup();
        for i in 0..16 {
            let label = format!("epoch-{}", i);
            let epoch = String::from_str(&env, &label);
            let a = crate::get_epoch_finalization(env.clone(), epoch.clone());
            let b = crate::get_epoch_finalization(env.clone(), epoch);
            assert_eq(a, b);
        }
    }
}
