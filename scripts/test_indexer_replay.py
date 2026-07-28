"""
Tests for indexer_replay.py

Run with:  python -m pytest scripts/test_indexer_replay.py -v
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

# Allow importing the sibling module without installing it.
sys.path.insert(0, str(Path(__file__).parent))

from indexer_replay import (
    AttestationRecord,
    AttestationState,
    IndexerReplayer,
    ReplayError,
    RevocationRecord,
    load_snapshot,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BUSINESS = "GABC1234EXAMPLEBUSINESS0000000000000000000000000000001"
ADMIN    = "GADMIN000000000000000000000000000000000000000000000001"
ROOT_A   = "a" * 64
ROOT_B   = "b" * 64
ROOT_C   = "c" * 64


def sub_event(
    ledger: int,
    business: str,
    period: str,
    merkle_root: str,
    timestamp: int = 1000000,
    version: int = 1,
    fee_paid: int = 1_000_000,
    proof_hash=None,
    expiry_timestamp=None,
) -> dict:
    data = {
        "business":         business,
        "period":           period,
        "merkle_root":      merkle_root,
        "timestamp":        timestamp,
        "version":          version,
        "fee_paid":         fee_paid,
        "proof_hash":       proof_hash,
        "expiry_timestamp": expiry_timestamp,
    }
    return {"ledger": ledger, "tx_hash": f"tx{ledger}", "event_index": 0,
            "topic": "att_sub", "business": business, "data": data}


def rev_event(ledger: int, business: str, period: str, reason: str = "test") -> dict:
    data = {"business": business, "period": period,
            "revoked_by": ADMIN, "timestamp": ledger * 100, "reason": reason}
    return {"ledger": ledger, "tx_hash": f"tx{ledger}", "event_index": 0,
            "topic": "att_rev", "business": business, "data": data}


def mig_event(
    ledger: int,
    business: str,
    period: str,
    old_root: str,
    new_root: str,
    old_ver: int = 1,
    new_ver: int = 2,
) -> dict:
    data = {"business": business, "period": period,
            "old_merkle_root": old_root, "new_merkle_root": new_root,
            "old_version": old_ver, "new_version": new_ver, "migrated_by": ADMIN}
    return {"ledger": ledger, "tx_hash": f"tx{ledger}", "event_index": 0,
            "topic": "att_mig", "business": business, "data": data}


def cl_event(ledger: int, business: str, period: str) -> dict:
    data = {"business": business, "period": period, "cleanup_timestamp": ledger * 100}
    return {"ledger": ledger, "tx_hash": f"tx{ledger}", "event_index": 0,
            "topic": "att_cl", "business": business, "data": data}


# ---------------------------------------------------------------------------
# Basic lifecycle tests
# ---------------------------------------------------------------------------

class TestSubmit:
    def test_creates_record(self):
        r = IndexerReplayer()
        r.replay([sub_event(100, BUSINESS, "2026-01", ROOT_A)])
        state = r.state_for(BUSINESS, "2026-01")
        assert state is not None
        assert state.attestation.merkle_root == ROOT_A
        assert state.attestation.version == 1
        assert state.revocation is None

    def test_overwrites_existing_record(self):
        r = IndexerReplayer()
        r.replay([
            sub_event(100, BUSINESS, "2026-01", ROOT_A),
            sub_event(200, BUSINESS, "2026-01", ROOT_B),
        ])
        assert r.state_for(BUSINESS, "2026-01").attestation.merkle_root == ROOT_B

    def test_optional_fields_none(self):
        r = IndexerReplayer()
        r.replay([sub_event(100, BUSINESS, "2026-01", ROOT_A)])
        att = r.state_for(BUSINESS, "2026-01").attestation
        assert att.proof_hash is None
        assert att.expiry_timestamp is None

    def test_optional_fields_set(self):
        r = IndexerReplayer()
        r.replay([sub_event(100, BUSINESS, "2026-01", ROOT_A,
                             proof_hash="f" * 64, expiry_timestamp=9999999)])
        att = r.state_for(BUSINESS, "2026-01").attestation
        assert att.proof_hash == "f" * 64
        assert att.expiry_timestamp == 9999999


class TestRevoke:
    def test_adds_revocation(self):
        r = IndexerReplayer()
        r.replay([
            sub_event(100, BUSINESS, "2026-01", ROOT_A),
            rev_event(200, BUSINESS, "2026-01", reason="fraud"),
        ])
        state = r.state_for(BUSINESS, "2026-01")
        assert state.revocation is not None
        assert state.revocation.reason == "fraud"
        assert state.revocation.revoked_by == ADMIN

    def test_revoke_without_prior_submit_fails_loudly(self):
        r = IndexerReplayer()
        with pytest.raises(ReplayError, match="Missing intermediate event"):
            r.replay([rev_event(200, BUSINESS, "2026-01")])

    def test_revoke_after_cleanup_fails_loudly(self):
        r = IndexerReplayer()
        with pytest.raises(ReplayError, match="Missing intermediate event"):
            r.replay([
                sub_event(100, BUSINESS, "2026-01", ROOT_A),
                cl_event(200, BUSINESS, "2026-01"),
                rev_event(300, BUSINESS, "2026-01"),
            ])


class TestMigrate:
    def test_updates_merkle_root_and_version(self):
        r = IndexerReplayer()
        r.replay([
            sub_event(100, BUSINESS, "2026-01", ROOT_A),
            mig_event(200, BUSINESS, "2026-01", ROOT_A, ROOT_B, old_ver=1, new_ver=2),
        ])
        att = r.state_for(BUSINESS, "2026-01").attestation
        assert att.merkle_root == ROOT_B
        assert att.version == 2

    def test_migrate_without_prior_submit_fails_loudly(self):
        r = IndexerReplayer()
        with pytest.raises(ReplayError, match="Missing intermediate event"):
            r.replay([mig_event(200, BUSINESS, "2026-01", ROOT_A, ROOT_B)])

    def test_migrate_root_mismatch_fails_loudly(self):
        r = IndexerReplayer()
        with pytest.raises(ReplayError, match="old_merkle_root mismatch"):
            r.replay([
                sub_event(100, BUSINESS, "2026-01", ROOT_A),
                mig_event(200, BUSINESS, "2026-01", ROOT_C, ROOT_B),  # wrong old_root
            ])

    def test_migrate_non_monotonic_version_fails_loudly(self):
        r = IndexerReplayer()
        with pytest.raises(ReplayError, match="new_version"):
            r.replay([
                sub_event(100, BUSINESS, "2026-01", ROOT_A),
                mig_event(200, BUSINESS, "2026-01", ROOT_A, ROOT_B, old_ver=2, new_ver=1),
            ])

    def test_chained_migrations(self):
        r = IndexerReplayer()
        r.replay([
            sub_event(100, BUSINESS, "2026-01", ROOT_A),
            mig_event(200, BUSINESS, "2026-01", ROOT_A, ROOT_B, old_ver=1, new_ver=2),
            mig_event(300, BUSINESS, "2026-01", ROOT_B, ROOT_C, old_ver=2, new_ver=3),
        ])
        att = r.state_for(BUSINESS, "2026-01").attestation
        assert att.merkle_root == ROOT_C
        assert att.version == 3


class TestCleanup:
    def test_removes_record(self):
        r = IndexerReplayer()
        r.replay([
            sub_event(100, BUSINESS, "2026-01", ROOT_A),
            cl_event(200, BUSINESS, "2026-01"),
        ])
        assert r.state_for(BUSINESS, "2026-01") is None

    def test_cleanup_without_prior_submit_fails_loudly(self):
        r = IndexerReplayer()
        with pytest.raises(ReplayError, match="Missing intermediate event"):
            r.replay([cl_event(200, BUSINESS, "2026-01")])


# ---------------------------------------------------------------------------
# Field validation
# ---------------------------------------------------------------------------

class TestFieldValidation:
    def test_missing_merkle_root_in_submitted(self):
        evt = sub_event(100, BUSINESS, "2026-01", ROOT_A)
        del evt["data"]["merkle_root"]
        r = IndexerReplayer()
        with pytest.raises(ReplayError, match="missing required fields"):
            r.replay([evt])

    def test_missing_topic_raises(self):
        evt = sub_event(100, BUSINESS, "2026-01", ROOT_A)
        del evt["topic"]
        r = IndexerReplayer()
        with pytest.raises(ReplayError, match="missing 'topic' or 'business'"):
            r.replay([evt])

    def test_missing_business_raises(self):
        evt = sub_event(100, BUSINESS, "2026-01", ROOT_A)
        del evt["business"]
        r = IndexerReplayer()
        with pytest.raises(ReplayError, match="missing 'topic' or 'business'"):
            r.replay([evt])


# ---------------------------------------------------------------------------
# Unknown / non-attestation events are skipped
# ---------------------------------------------------------------------------

class TestUnknownTopics:
    def test_unknown_topic_skipped(self):
        r = IndexerReplayer()
        r.replay([
            sub_event(100, BUSINESS, "2026-01", ROOT_A),
            {"ledger": 150, "tx_hash": "tx150", "event_index": 0,
             "topic": "fee_cfg", "business": BUSINESS, "data": {"enabled": True}},
        ])
        # State unchanged by the unknown event.
        assert r.state_for(BUSINESS, "2026-01").attestation.merkle_root == ROOT_A


# ---------------------------------------------------------------------------
# canonical_snapshot / state_hash
# ---------------------------------------------------------------------------

class TestCanonicalSnapshot:
    def test_snapshot_shape(self):
        r = IndexerReplayer()
        r.replay([sub_event(100, BUSINESS, "2026-01", ROOT_A)])
        snapshot = r.canonical_snapshot(BUSINESS, ["2026-01"])
        assert len(snapshot) == 1
        period, att, rev = snapshot[0]
        assert period == "2026-01"
        assert att == [ROOT_A, 1000000, 1, 1_000_000, None, None]
        assert rev is None

    def test_missing_period_returns_none_tuple(self):
        r = IndexerReplayer()
        r.replay([sub_event(100, BUSINESS, "2026-01", ROOT_A)])
        snapshot = r.canonical_snapshot(BUSINESS, ["2026-99"])
        assert snapshot[0] == ["2026-99", None, None]

    def test_state_hash_is_stable(self):
        r = IndexerReplayer()
        r.replay([sub_event(100, BUSINESS, "2026-01", ROOT_A)])
        h1 = r.state_hash(BUSINESS, ["2026-01"])
        h2 = r.state_hash(BUSINESS, ["2026-01"])
        assert h1 == h2

    def test_state_hash_changes_after_migration(self):
        r = IndexerReplayer()
        r.replay([sub_event(100, BUSINESS, "2026-01", ROOT_A)])
        h_before = r.state_hash(BUSINESS, ["2026-01"])
        r.replay([mig_event(200, BUSINESS, "2026-01", ROOT_A, ROOT_B)])
        h_after = r.state_hash(BUSINESS, ["2026-01"])
        assert h_before != h_after

    def test_state_hash_matches_manual_sha256(self):
        r = IndexerReplayer()
        r.replay([sub_event(100, BUSINESS, "2026-01", ROOT_A)])
        snapshot = r.canonical_snapshot(BUSINESS, ["2026-01"])
        serialised = json.dumps(snapshot, sort_keys=False, separators=(",", ":"))
        expected = hashlib.sha256(serialised.encode()).hexdigest()
        assert r.state_hash(BUSINESS, ["2026-01"]) == expected


# ---------------------------------------------------------------------------
# Fixture file integration
# ---------------------------------------------------------------------------

class TestFixtureFile:
    def test_fixture_replays_without_error(self):
        fixture = Path(__file__).parent / "fixtures" / "attestation_events.json"
        events = json.loads(fixture.read_text())
        r = IndexerReplayer()
        r.replay(events)

    def test_fixture_final_state(self):
        fixture = Path(__file__).parent / "fixtures" / "attestation_events.json"
        events = json.loads(fixture.read_text())
        r = IndexerReplayer()
        r.replay(events)

        # 2026-01 was migrated: root should be "ddd…", version 2
        att_01 = r.state_for(BUSINESS, "2026-01").attestation
        assert att_01.version == 2
        assert att_01.merkle_root == "d" * 64

        # 2026-02 was revoked
        state_02 = r.state_for(BUSINESS, "2026-02")
        assert state_02.revocation is not None
        assert state_02.revocation.reason == "fraudulent submission"

    def test_snapshot_hash_self_consistent(self):
        """Replay fixture and verify the hash round-trips correctly."""
        fixture = Path(__file__).parent / "fixtures" / "attestation_events.json"
        events = json.loads(fixture.read_text())
        r = IndexerReplayer()
        r.replay(events)

        periods = ["2026-01", "2026-02"]
        h = r.state_hash(BUSINESS, periods)
        # Re-compute from canonical snapshot to confirm determinism.
        snapshot = r.canonical_snapshot(BUSINESS, periods)
        serialised = json.dumps(snapshot, sort_keys=False, separators=(",", ":"))
        expected = hashlib.sha256(serialised.encode()).hexdigest()
        assert h == expected
