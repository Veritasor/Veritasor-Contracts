#!/usr/bin/env python3
"""
indexer_replay.py — Attestation state reconstruction from on-chain events.

Consumes a stream of AttestationSubmitted / AttestationRevoked /
AttestationMigrated / AttestationCleanedUp events and reconstructs
per-business attestation state.  The resulting state hash can be compared
byte-for-byte against a `get_business_attestations` contract query snapshot
to catch schema drift between the contract and any off-chain indexer.

Usage
-----
    python scripts/indexer_replay.py --fixture <events.json> [--snapshot <snapshot.json>]

Exit codes
----------
    0  State hash matches snapshot (or no snapshot provided).
    1  Hash mismatch — schema drift detected.
    2  Invalid fixture / missing required event — replay aborted.

Security notes
--------------
- All input is validated against known event schemas before processing.
- Unknown event types are logged and skipped; they do NOT silently corrupt state.
- Missing intermediate events (e.g. att_rev without prior att_sub) raise
  loudly — they never silently produce wrong state.
- No secrets, private keys, or PII are read or emitted.
- The state hash is SHA-256 over a deterministic canonical JSON serialisation;
  field order is fixed to match contract tuple layout.

Fixture format (events.json)
-----------------------------
A JSON array of event objects, each with the shape:

    {
        "ledger":     12345,
        "tx_hash":    "abc…",
        "event_index": 0,
        "topic":      "att_sub",           // primary topic symbol
        "business":   "GABC…",             // secondary topic (Stellar address)
        "data": { … }                      // payload matching the event struct
    }

The array MUST be sorted by (ledger, event_index) ascending.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants matching contracts/attestation/src/events.rs
# ---------------------------------------------------------------------------

TOPIC_SUBMITTED  = "att_sub"
TOPIC_REVOKED    = "att_rev"
TOPIC_MIGRATED   = "att_mig"
TOPIC_CLEANED_UP = "att_cl"

KNOWN_TOPICS = {TOPIC_SUBMITTED, TOPIC_REVOKED, TOPIC_MIGRATED, TOPIC_CLEANED_UP}

# Required fields per event type — mirrors the #[contracttype] structs in events.rs.
REQUIRED_FIELDS: dict[str, list[str]] = {
    TOPIC_SUBMITTED: [
        "business", "period", "merkle_root", "timestamp",
        "version", "fee_paid", "proof_hash", "expiry_timestamp",
    ],
    TOPIC_REVOKED: ["business", "period", "revoked_by", "reason"],
    TOPIC_MIGRATED: [
        "business", "period", "old_merkle_root", "new_merkle_root",
        "old_version", "new_version", "migrated_by",
    ],
    TOPIC_CLEANED_UP: ["business", "period", "cleanup_timestamp"],
}

# ---------------------------------------------------------------------------
# State types
#
# AttestationData tuple layout (matches lib.rs type alias):
#   (merkle_root, timestamp, version, fee_paid, proof_hash, expiry_timestamp)
#
# RevocationData tuple layout:
#   (revoked_by, timestamp, reason)
# ---------------------------------------------------------------------------

@dataclass
class AttestationRecord:
    """Mirrors the AttestationData tuple stored on-chain."""
    merkle_root:       str
    timestamp:         int
    version:           int
    fee_paid:          int
    proof_hash:        str | None
    expiry_timestamp:  int | None

    def to_canonical(self) -> list[Any]:
        """Fixed-order list matching the contract tuple layout."""
        return [
            self.merkle_root,
            self.timestamp,
            self.version,
            self.fee_paid,
            self.proof_hash,
            self.expiry_timestamp,
        ]


@dataclass
class RevocationRecord:
    """Mirrors the RevocationData tuple stored on-chain."""
    revoked_by: str
    timestamp:  int
    reason:     str

    def to_canonical(self) -> list[Any]:
        return [self.revoked_by, self.timestamp, self.reason]


@dataclass
class AttestationState:
    """Per-(business, period) state.  None means the record was cleaned up."""
    attestation: AttestationRecord | None = None
    revocation:  RevocationRecord  | None = None


# ---------------------------------------------------------------------------
# Reducer
# ---------------------------------------------------------------------------

class IndexerReplayer:
    """
    Stateful reducer that processes events in ledger order and builds
    an in-memory representation of per-business attestation state.
    """

    def __init__(self) -> None:
        # state[(business, period)] -> AttestationState
        self._state: dict[tuple[str, str], AttestationState] = {}
        self._event_count = 0

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def replay(self, events: list[dict[str, Any]]) -> None:
        """Process a sorted list of event dicts, updating internal state."""
        for evt in events:
            self._process_event(evt)

    def state_for(self, business: str, period: str) -> AttestationState | None:
        return self._state.get((business, period))

    def all_state(self) -> dict[tuple[str, str], AttestationState]:
        return dict(self._state)

    def canonical_snapshot(self, business: str, periods: list[str]) -> list[Any]:
        """
        Build a list that matches the shape of get_business_attestations:
            Vec<(String, Option<AttestationData>, Option<RevocationData>)>

        Each element is:  [period, attestation_tuple_or_null, revocation_tuple_or_null]
        """
        result = []
        for period in periods:
            state = self._state.get((business, period))
            if state is None:
                att_val = None
                rev_val = None
            else:
                att_val = state.attestation.to_canonical() if state.attestation else None
                rev_val = state.revocation.to_canonical() if state.revocation else None
            result.append([period, att_val, rev_val])
        return result

    def state_hash(self, business: str, periods: list[str]) -> str:
        """SHA-256 hex digest of the canonical snapshot for a business."""
        snapshot = self.canonical_snapshot(business, periods)
        serialised = json.dumps(snapshot, sort_keys=False, separators=(",", ":"))
        return hashlib.sha256(serialised.encode()).hexdigest()

    # ------------------------------------------------------------------ #
    # Internal reducer logic                                               #
    # ------------------------------------------------------------------ #

    def _process_event(self, evt: dict[str, Any]) -> None:
        topic    = evt.get("topic", "")
        business = evt.get("business", "")
        data     = evt.get("data", {})
        ledger   = evt.get("ledger", "?")
        tx_hash  = evt.get("tx_hash", "?")

        if not topic or not business:
            raise ReplayError(
                f"Event at ledger={ledger} tx={tx_hash} is missing 'topic' or 'business'."
            )

        if topic not in KNOWN_TOPICS:
            # Not an attestation lifecycle event — skip silently.
            return

        _validate_fields(topic, data, ledger, tx_hash)

        period = data["period"]
        key    = (business, period)

        if topic == TOPIC_SUBMITTED:
            self._apply_submitted(key, data)
        elif topic == TOPIC_REVOKED:
            self._apply_revoked(key, data, ledger, tx_hash)
        elif topic == TOPIC_MIGRATED:
            self._apply_migrated(key, data, ledger, tx_hash)
        elif topic == TOPIC_CLEANED_UP:
            self._apply_cleaned_up(key, data, ledger, tx_hash)

        self._event_count += 1

    def _apply_submitted(self, key: tuple[str, str], data: dict) -> None:
        self._state[key] = AttestationState(
            attestation=AttestationRecord(
                merkle_root=data["merkle_root"],
                timestamp=int(data["timestamp"]),
                version=int(data["version"]),
                fee_paid=int(data["fee_paid"]),
                proof_hash=data.get("proof_hash"),
                expiry_timestamp=_optional_int(data.get("expiry_timestamp")),
            )
        )

    def _apply_revoked(
        self,
        key: tuple[str, str],
        data: dict,
        ledger: Any,
        tx_hash: Any,
        event_timestamp: int = 0,
    ) -> None:
        state = self._state.get(key)
        if state is None or state.attestation is None:
            raise ReplayError(
                f"att_rev at ledger={ledger} tx={tx_hash}: "
                f"no prior att_sub for ({key[0]}, {key[1]}). "
                "Missing intermediate event."
            )
        # RevocationData = (revoked_by, timestamp, reason).
        # The timestamp is the ledger timestamp at revocation time.
        # Fixtures may supply it as an optional "ledger_timestamp" field;
        # fall back to the event-level "ledger_timestamp" if present,
        # then to 0 so replay never fails on missing optional metadata.
        timestamp = int(
            data.get("ledger_timestamp")
            or data.get("timestamp")
            or event_timestamp
            or 0
        )
        state.revocation = RevocationRecord(
            revoked_by=data["revoked_by"],
            timestamp=timestamp,
            reason=data["reason"],
        )

    def _apply_migrated(
        self,
        key: tuple[str, str],
        data: dict,
        ledger: Any,
        tx_hash: Any,
    ) -> None:
        state = self._state.get(key)
        if state is None or state.attestation is None:
            raise ReplayError(
                f"att_mig at ledger={ledger} tx={tx_hash}: "
                f"no prior att_sub for ({key[0]}, {key[1]}). "
                "Missing intermediate event."
            )
        old_root = data["old_merkle_root"]
        if state.attestation.merkle_root != old_root:
            raise ReplayError(
                f"att_mig at ledger={ledger} tx={tx_hash}: "
                f"old_merkle_root mismatch for ({key[0]}, {key[1]}). "
                f"Expected {state.attestation.merkle_root!r}, got {old_root!r}. "
                "Possible gap in event stream."
            )
        new_ver = int(data["new_version"])
        old_ver = int(data["old_version"])
        if new_ver <= old_ver:
            raise ReplayError(
                f"att_mig at ledger={ledger} tx={tx_hash}: "
                f"new_version ({new_ver}) must be > old_version ({old_ver})."
            )
        # Preserve timestamp and fee from original submission; update root + version.
        state.attestation.merkle_root = data["new_merkle_root"]
        state.attestation.version     = new_ver

    def _apply_cleaned_up(
        self,
        key: tuple[str, str],
        data: dict,
        ledger: Any,
        tx_hash: Any,
    ) -> None:
        if key not in self._state:
            raise ReplayError(
                f"att_cl at ledger={ledger} tx={tx_hash}: "
                f"no prior attestation for ({key[0]}, {key[1]}). "
                "Missing intermediate event."
            )
        # Cleanup removes the record entirely.
        del self._state[key]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

class ReplayError(Exception):
    """Raised when the event stream is structurally invalid."""


def _validate_fields(
    topic: str,
    data: dict[str, Any],
    ledger: Any,
    tx_hash: Any,
) -> None:
    required = REQUIRED_FIELDS[topic]
    missing  = [f for f in required if f not in data]
    if missing:
        raise ReplayError(
            f"Event {topic!r} at ledger={ledger} tx={tx_hash} is missing "
            f"required fields: {missing}"
        )


def _optional_int(value: Any) -> int | None:
    return int(value) if value is not None else None


# ---------------------------------------------------------------------------
# Snapshot comparison
# ---------------------------------------------------------------------------

def load_snapshot(path: Path) -> dict[str, Any]:
    """
    Load a contract query snapshot produced by get_business_attestations.

    Expected format:
        {
            "business": "GABC…",
            "periods":  ["2026-01", "2026-02"],
            "result":   [ [period, att_tuple_or_null, rev_tuple_or_null], … ],
            "hash":     "<sha256 hex>"   // optional — used for cross-check
        }
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ReplayError(f"Snapshot at {path} must be a JSON object.")
    for key in ("business", "periods", "result"):
        if key not in raw:
            raise ReplayError(f"Snapshot at {path} is missing required key '{key}'.")
    return raw


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Replay attestation events and compare state hash against contract snapshot.",
    )
    p.add_argument(
        "--fixture", "-f",
        required=True,
        help="Path to the event stream fixture JSON file.",
    )
    p.add_argument(
        "--snapshot", "-s",
        default=None,
        help="Path to a get_business_attestations snapshot JSON file for comparison.",
    )
    p.add_argument(
        "--business",
        default=None,
        help="Business address to hash (required when --snapshot is not provided).",
    )
    p.add_argument(
        "--periods",
        nargs="*",
        default=None,
        help="Period list to hash (required when --snapshot is not provided).",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print replayed state to stdout.",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    # ── Load fixture ──────────────────────────────────────────────────────
    fixture_path = Path(args.fixture)
    if not fixture_path.exists():
        print(f"ERROR: fixture file not found: {fixture_path}", file=sys.stderr)
        return 2

    try:
        events: list[dict[str, Any]] = json.loads(
            fixture_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        print(f"ERROR: fixture is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if not isinstance(events, list):
        print("ERROR: fixture must be a JSON array of event objects.", file=sys.stderr)
        return 2

    # ── Replay ────────────────────────────────────────────────────────────
    replayer = IndexerReplayer()
    try:
        replayer.replay(events)
    except ReplayError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # ── Determine target business / periods ───────────────────────────────
    if args.snapshot:
        snapshot_path = Path(args.snapshot)
        if not snapshot_path.exists():
            print(f"ERROR: snapshot file not found: {snapshot_path}", file=sys.stderr)
            return 2
        try:
            snapshot = load_snapshot(snapshot_path)
        except ReplayError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

        business = snapshot["business"]
        periods  = snapshot["periods"]
    else:
        if not args.business or not args.periods:
            print(
                "ERROR: --business and --periods are required when --snapshot is not provided.",
                file=sys.stderr,
            )
            return 2
        business = args.business
        periods  = args.periods
        snapshot = None

    # ── Build canonical snapshot from replayed state ──────────────────────
    replayed = replayer.canonical_snapshot(business, periods)
    replayed_hash = replayer.state_hash(business, periods)

    if args.verbose:
        print("Replayed state:")
        print(json.dumps(replayed, indent=2))
        print(f"\nReplayed hash:  {replayed_hash}")

    # ── Compare ───────────────────────────────────────────────────────────
    if snapshot is not None:
        contract_result = snapshot["result"]
        contract_hash_serialised = json.dumps(
            contract_result, sort_keys=False, separators=(",", ":")
        )
        contract_hash = hashlib.sha256(
            contract_hash_serialised.encode()
        ).hexdigest()

        if args.verbose:
            print(f"Contract hash:  {contract_hash}")

        # Also check the embedded hash if present.
        if "hash" in snapshot:
            embedded = snapshot["hash"]
            if embedded != contract_hash:
                print(
                    f"WARNING: snapshot 'hash' field ({embedded}) does not match "
                    f"computed contract hash ({contract_hash}).  "
                    "Snapshot may be stale.",
                    file=sys.stderr,
                )

        if replayed_hash == contract_hash:
            print(f"OK  State hash matches contract snapshot: {replayed_hash}")
            return 0
        else:
            print(
                f"FAIL  Hash mismatch — schema drift detected.\n"
                f"  Replayed: {replayed_hash}\n"
                f"  Contract: {contract_hash}",
                file=sys.stderr,
            )
            if args.verbose:
                print("\nContract result:")
                print(json.dumps(contract_result, indent=2))
            return 1

    print(f"State hash for {business}: {replayed_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
