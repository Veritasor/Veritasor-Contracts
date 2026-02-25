#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String, Vec};

fn period_str(env: &Env, i: u32) -> String {
    let s = match i {
        1 => "2026-01",
        2 => "2026-02",
        3 => "2026-03",
        4 => "2026-04",
        5 => "2026-05",
        6 => "2026-06",
        7 => "2026-07",
        8 => "2026-08",
        9 => "2026-09",
        10 => "2026-10",
        11 => "2026-11",
        12 => "2026-12",
        _ => "2026-01",
    };
    String::from_str(env, s)
}

fn setup_with_attestations(env: &Env, n: u32) -> (Address, AttestationContractClient<'_>, Vec<String>) {
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(env, &contract_id);
    let business = Address::generate(env);
    let mut periods = Vec::new(env);
    for i in 1..=n {
        let period = period_str(env, i);
        periods.push_back(period.clone());
        let root = BytesN::from_array(env, &[(i as u8) & 0xff; 32]);
        client.submit_attestation(&business, &period, &root, &1700000000u64, &i);
    }
    (business, client, periods)
}

#[test]
fn get_attestations_page_empty_periods() {
    let env = Env::default();
    let (business, client, periods) = setup_with_attestations(&env, 3);
    let (out, next) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_FILTER_ALL,
        &None,
        &10,
        &0,
    );
    assert_eq!(out.len(), 3);
    assert_eq!(next, 3);
}

#[test]
fn get_attestations_page_cursor_past_end() {
    let env = Env::default();
    let (business, client, periods) = setup_with_attestations(&env, 2);
    let (out, next) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_FILTER_ALL,
        &None,
        &10,
        &10,
    );
    assert_eq!(out.len(), 0);
    assert_eq!(next, 10);
}

#[test]
fn get_attestations_page_limit_caps_results() {
    let env = Env::default();
    let (business, client, periods) = setup_with_attestations(&env, 10);
    let (out, next) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_FILTER_ALL,
        &None,
        &3,
        &0,
    );
    assert_eq!(out.len(), 3);
    assert_eq!(next, 3);
}

#[test]
fn get_attestations_page_second_page() {
    let env = Env::default();
    let (business, client, periods) = setup_with_attestations(&env, 5);
    let (page1, next1) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_FILTER_ALL,
        &None,
        &2,
        &0,
    );
    assert_eq!(page1.len(), 2);
    assert_eq!(next1, 2);
    let (page2, next2) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_FILTER_ALL,
        &None,
        &2,
        &next1,
    );
    assert_eq!(page2.len(), 2);
    assert_eq!(next2, 4);
    let (page3, next3) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_FILTER_ALL,
        &None,
        &2,
        &next2,
    );
    assert_eq!(page3.len(), 1);
    assert_eq!(next3, 5);
}

#[test]
fn get_attestations_page_round_trip_all_pages() {
    let env = Env::default();
    let (business, client, periods) = setup_with_attestations(&env, 12);
    let mut all: Vec<(String, BytesN<32>, u64, u32, u32)> = Vec::new(&env);
    let mut cursor = 0u32;
    loop {
        let (page, next) = client.get_attestations_page(
            &business,
            &periods,
            &None,
            &None,
            &STATUS_FILTER_ALL,
            &None,
            &5,
            &cursor,
        );
        for i in 0..page.len() {
            all.push_back(page.get(i).unwrap());
        }
        if next >= periods.len() {
            break;
        }
        cursor = next;
    }
    assert_eq!(all.len(), 12);
    for i in 0..12u32 {
        let (period, _root, _ts, ver, status) = all.get(i).unwrap();
        assert_eq!(period, period_str(&env, i + 1));
        assert_eq!(ver, i + 1);
        assert_eq!(status, STATUS_ACTIVE);
    }
}

#[test]
fn get_attestations_page_filter_period_range() {
    let env = Env::default();
    let (business, client, periods) = setup_with_attestations(&env, 5);
    let start = Some(String::from_str(&env, "2026-02"));
    let end = Some(String::from_str(&env, "2026-04"));
    let (out, next) = client.get_attestations_page(
        &business,
        &periods,
        &start,
        &end,
        &STATUS_FILTER_ALL,
        &None,
        &10,
        &0,
    );
    assert_eq!(out.len(), 3);
    assert_eq!(out.get(0).unwrap().0, String::from_str(&env, "2026-02"));
    assert_eq!(out.get(1).unwrap().0, String::from_str(&env, "2026-03"));
    assert_eq!(out.get(2).unwrap().0, String::from_str(&env, "2026-04"));
    assert_eq!(next, 5);
}

#[test]
fn get_attestations_page_filter_version() {
    let env = Env::default();
    let (business, client, periods) = setup_with_attestations(&env, 5);
    let (out, _) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_FILTER_ALL,
        &Some(3),
        &10,
        &0,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out.get(0).unwrap().3, 3);
}

#[test]
fn get_attestations_page_filter_active_after_revoke() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);
    let business = Address::generate(&env);
    let mut periods = Vec::new(&env);
    for i in 1..=3 {
        let period = period_str(&env, i);
        periods.push_back(period.clone());
        let root = BytesN::from_array(&env, &[(i as u8) & 0xff; 32]);
        client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    }
    let revoke_period = String::from_str(&env, "2026-02");
    client.revoke_attestation(&admin, &business, &revoke_period);
    let (active_only, _) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_ACTIVE,
        &None,
        &10,
        &0,
    );
    assert_eq!(active_only.len(), 2);
    let (revoked_only, _) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_REVOKED,
        &None,
        &10,
        &0,
    );
    assert_eq!(revoked_only.len(), 1);
    assert_eq!(revoked_only.get(0).unwrap().0, String::from_str(&env, "2026-02"));
}

#[test]
fn get_attestations_page_limit_capped_at_max() {
    let env = Env::default();
    let (business, client, periods) = setup_with_attestations(&env, 12);
    let (out, _) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_FILTER_ALL,
        &None,
        &100,
        &0,
    );
    assert!(out.len() <= 30);
    assert_eq!(out.len(), 12);
}

#[test]
fn get_attestations_page_empty_result_when_no_match() {
    let env = Env::default();
    let (business, client, periods) = setup_with_attestations(&env, 2);
    let start = Some(String::from_str(&env, "2027-01"));
    let end = Some(String::from_str(&env, "2027-12"));
    let (out, next) = client.get_attestations_page(
        &business,
        &periods,
        &start,
        &end,
        &STATUS_FILTER_ALL,
        &None,
        &10,
        &0,
    );
    assert_eq!(out.len(), 0);
    assert_eq!(next, 2);
}

#[test]
fn init_and_revoke_attestation() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.revoke_attestation(&admin, &business, &period);
    let mut periods = Vec::new(&env);
    periods.push_back(period.clone());
    let (out, _) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_REVOKED,
        &None,
        &10,
        &0,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out.get(0).unwrap().4, STATUS_REVOKED);
}

#[test]
#[should_panic(expected = "caller is not admin")]
fn revoke_attestation_non_admin_panics() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);
    let other = Address::generate(&env);
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-02");
    let root = BytesN::from_array(&env, &[1u8; 32]);
    client.submit_attestation(&business, &period, &root, &1700000000u64, &1u32);
    client.revoke_attestation(&other, &business, &period);
}

#[test]
fn periods_list_includes_missing_attestations_skipped() {
    let env = Env::default();
    let contract_id = env.register(AttestationContract, ());
    let client = AttestationContractClient::new(&env, &contract_id);
    let business = Address::generate(&env);
    let p1 = String::from_str(&env, "2026-01");
    let p2 = String::from_str(&env, "2026-02");
    let p3 = String::from_str(&env, "2026-03");
    client.submit_attestation(&business, &p1, &BytesN::from_array(&env, &[1u8; 32]), &1700000000u64, &1u32);
    client.submit_attestation(&business, &p3, &BytesN::from_array(&env, &[3u8; 32]), &1700000000u64, &1u32);
    let mut periods = Vec::new(&env);
    periods.push_back(p1.clone());
    periods.push_back(p2.clone());
    periods.push_back(p3.clone());
    let (out, next) = client.get_attestations_page(
        &business,
        &periods,
        &None,
        &None,
        &STATUS_FILTER_ALL,
        &None,
        &10,
        &0,
    );
    assert_eq!(out.len(), 2);
    assert_eq!(out.get(0).unwrap().0, p1);
    assert_eq!(out.get(1).unwrap().0, p3);
    assert_eq!(next, 3);
}
