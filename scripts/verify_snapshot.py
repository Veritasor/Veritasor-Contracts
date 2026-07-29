#!/usr/bin/env python3
"""
Snapshot Verifier CLI — Veritasor Contracts
============================================

Queries a deployed ``AttestationSnapshotContract`` for **all** stored snapshot
data via public Soroban RPC, recomputes the commitment hash locally using the
same algorithm as the contract, and reports whether the on-chain commitment
matches the local recomputation.

**Purpose**
Auditors can trust nothing beyond the published WASM and a public RPC endpoint.
By running this verifier they independently confirm that the contract's
``export_snapshot_commitment()`` matches a local hash of every snapshot record.

**Requirements**
- Python 3.10+
- ``stellar-sdk>=11.0``  (install via ``pip install stellar-sdk``)

**Usage**::

    python scripts/verify_snapshot.py \\
        --rpc-url https://soroban-testnet.stellar.org \\
        --contract-id CCA...
        [--network-passphrase "Test SDF Network ; September 2025"]
        [--page-size 64]

Exit code:
    0   PASS – local commitment matches on-chain commitment.
    1   FAIL – mismatch or error.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
from typing import List, Optional

from stellar_sdk import (
    Keypair,
    Network,
    SorobanServer,
    TransactionBuilder,
)
from stellar_sdk.operation import InvokeHostFunction
from stellar_sdk.soroban_rpc import SimulateTransactionResponse
from stellar_sdk.xdr import (
    ContractID,
    Hash,
    HostFunction,
    HostFunctionType,
    Int128Parts,
    Int64,
    InvokeContractArgs,
    SCAddress,
    SCAddressType,
    SCMap,
    SCMapEntry,
    SCString,
    SCSymbol,
    SCVal,
    SCValType,
    SCVec,
    Uint32,
    Uint64,
)

logger = logging.getLogger("verify_snapshot")


# ══════════════════════════════════════════════════════════════════════
#  ScVal helper functions
# ══════════════════════════════════════════════════════════════════════

def scv_string(s: str) -> SCVal:
    """Build an ``SCVal`` of type ``SCV_STRING``."""
    return SCVal(type=SCValType.SCV_STRING, str=SCString(sc_string=s.encode("utf-8")))


def scv_symbol(s: str) -> SCVal:
    """Build an ``SCVal`` of type ``SCV_SYMBOL``."""
    return SCVal(type=SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol=s.encode("utf-8")))


def scv_u32(v: int) -> SCVal:
    """Build an ``SCVal`` of type ``SCV_U32``."""
    return SCVal(type=SCValType.SCV_U32, u32=Uint32(v))


def scv_u64(v: int) -> SCVal:
    """Build an ``SCVal`` of type ``SCV_U64``."""
    return SCVal(type=SCValType.SCV_U64, u64=Uint64(v))


def scv_i128(v: int) -> SCVal:
    """Build an ``SCVal`` of type ``SCV_I128``."""
    hi = v >> 64
    lo = v & ((1 << 64) - 1)
    return SCVal(
        type=SCValType.SCV_I128,
        i128=Int128Parts(hi=Int64(hi), lo=Uint64(lo)),
    )


def scv_vec(items: List[SCVal]) -> SCVal:
    """Build an ``SCVal`` of type ``SCV_VEC``."""
    return SCVal(type=SCValType.SCV_VEC, vec=SCVec(items))


def scv_address_contract(contract_id: bytes) -> SCVal:
    """Build an ``SCVal`` of type ``SCV_ADDRESS`` for a contract address.

    ``contract_id`` must be exactly 32 bytes (the raw contract hash).
    """
    if len(contract_id) != 32:
        raise ValueError(f"contract_id must be 32 bytes, got {len(contract_id)}")
    return SCVal(
        type=SCValType.SCV_ADDRESS,
        address=SCAddress(
            type=SCAddressType.SC_ADDRESS_TYPE_CONTRACT,
            contract_id=ContractID(contract_id=Hash(contract_id)),
        ),
    )


def scv_address_account(account_id: bytes) -> SCVal:
    """Build an ``SCVal`` of type ``SCV_ADDRESS`` for an account address.

    ``account_id`` must be exactly 32 bytes (the raw ed25519 public key).
    """
    if len(account_id) != 32:
        raise ValueError(f"account_id must be 32 bytes, got {len(account_id)}")
    from stellar_sdk.xdr import AccountID, PublicKey, PublicKeyType, Uint256

    return SCVal(
        type=SCValType.SCV_ADDRESS,
        address=SCAddress(
            type=SCAddressType.SC_ADDRESS_TYPE_ACCOUNT,
            account_id=AccountID(
                type=PublicKeyType.PUBLIC_KEY_TYPE_ED25519,
                ed25519=Uint256(account_id),
            ),
        ),
    )


# ══════════════════════════════════════════════════════════════════════
#  ScVal extraction helpers
# ══════════════════════════════════════════════════════════════════════

def extract_string(sc_val: SCVal) -> str:
    if sc_val.type != SCValType.SCV_STRING:
        raise TypeError(f"expected SCV_STRING, got {sc_val.type}")
    return sc_val.str.sc_string.decode("utf-8")


def extract_u32(sc_val: SCVal) -> int:
    if sc_val.type != SCValType.SCV_U32:
        raise TypeError(f"expected SCV_U32, got {sc_val.type}")
    return sc_val.u32.uint32


def extract_u64(sc_val: SCVal) -> int:
    if sc_val.type != SCValType.SCV_U64:
        raise TypeError(f"expected SCV_U64, got {sc_val.type}")
    return sc_val.u64.uint64


def extract_i128(sc_val: SCVal) -> int:
    if sc_val.type != SCValType.SCV_I128:
        raise TypeError(f"expected SCV_I128, got {sc_val.type}")
    hi = sc_val.i128.hi.int64 if sc_val.i128.hi else 0
    lo = sc_val.i128.lo.uint64 if sc_val.i128.lo else 0
    return (hi << 64) | lo


def extract_address(sc_val: SCVal) -> bytes:
    """Extract the raw 32-byte identifier from an address SCVal."""
    if sc_val.type != SCValType.SCV_ADDRESS:
        raise TypeError(f"expected SCV_ADDRESS, got {sc_val.type}")
    addr = sc_val.address
    if addr.type == SCAddressType.SC_ADDRESS_TYPE_CONTRACT:
        return addr.contract_id.contract_id.hash
    elif addr.type == SCAddressType.SC_ADDRESS_TYPE_ACCOUNT:
        return addr.account_id.ed25519.uint256
    raise ValueError(f"unsupported address type: {addr.type}")


def extract_vec(sc_val: SCVal) -> List[SCVal]:
    """Extract the elements from an SCV_VEC."""
    if sc_val.type != SCValType.SCV_VEC:
        raise TypeError(f"expected SCV_VEC, got {sc_val.type}")
    return list(sc_val.vec.sc_vec)


def extract_map(sc_val: SCVal) -> List[tuple[SCVal, SCVal]]:
    """Extract entries from an SCV_MAP as (key, value) pairs."""
    if sc_val.type != SCValType.SCV_MAP:
        raise TypeError(f"expected SCV_MAP, got {sc_val.type}")
    return [(entry.key, entry.val) for entry in sc_val.map.sc_map]


# ══════════════════════════════════════════════════════════════════════
#  On-chain client
# ══════════════════════════════════════════════════════════════════════

class OnChainClient:
    """Read-only client for an ``AttestationSnapshotContract`` via Soroban RPC."""

    def __init__(self, rpc_url: str, contract_id: str, network_passphrase: str):
        self.server = SorobanServer(rpc_url)
        self.network = Network(network_passphrase)
        self.contract_id = contract_id
        self.source = Keypair.random()

        # Resolve the contract address once
        raw = self._resolve_contract_key(contract_id)
        self.contract_address = scv_address_contract(raw)

    @staticmethod
    def _resolve_contract_key(contract_id_str: str) -> bytes:
        """Decode a stellar contract ID (C... or G...) to 32 raw bytes.

        Uses ``StrKey`` if available, otherwise falls back to hex decoding.
        """
        from stellar_sdk import StrKey

        if StrKey.is_valid_contract(contract_id_str):
            return StrKey.decode_contract(contract_id_str)
        # Fallback: try hex
        raw = bytes.fromhex(contract_id_str)
        if len(raw) == 32:
            return raw
        raise ValueError(
            f"cannot decode contract ID: {contract_id_str!r}"
        )

    def _build_invoke_envelope(self, func_name: str, args: List[SCVal]):
        """Build a ``TransactionEnvelope`` for a read-only contract invocation."""
        host_fn = HostFunction(
            type=HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT,
            invoke_contract=InvokeContractArgs(
                contract_address=self.contract_address.address,
                function_name=SCSymbol(sc_symbol=func_name.encode("utf-8")),
                args=args,
            ),
        )
        op = InvokeHostFunction(host_function=host_fn)

        # Load the source account to get the current sequence number
        # Use a random keypair — for simulation, the account doesn't need
        # to exist on the network (sequence number 0 works).
        tx = (
            TransactionBuilder(
                source_account=self.source,
                network_passphrase=self.network.network_passphrase,
                base_fee=100,
            )
            .add_operation(op)
            .set_timeout(300)
            .build()
        )
        return tx

    def _simulate(self, func_name: str, args: List[SCVal]) -> SCVal:
        """Simulate a contract function call and return the result ``SCVal``."""
        tx = self._build_invoke_envelope(func_name, args)
        resp: SimulateTransactionResponse = self.server.simulate_transaction(tx)
        if resp.error:
            raise RuntimeError(
                f"simulateTransaction failed for {func_name}: {resp.error}"
            )
        if not resp.results:
            raise RuntimeError(
                f"simulateTransaction for {func_name} returned no results"
            )

        # Decode the result XDR (base64-encoded SCVal)
        result_xdr = resp.results[0].xdr
        sc_val = SCVal.from_xdr(result_xdr)
        logger.debug("simulate %s -> %s", func_name, sc_val)
        return sc_val

    def get_commitment(self) -> bytes:
        """Call ``export_snapshot_commitment()``, returns 32-byte hash."""
        sc_val = self._simulate("export_snapshot_commitment", [])
        if sc_val.type != SCValType.SCV_BYTES:
            raise TypeError(
                f"expected SCV_BYTES from export_snapshot_commitment, got {sc_val.type}"
            )
        return bytes(sc_val.bytes.sc_bytes)

    def get_all_epochs(self, page: int = 0, page_size: int = 0) -> List[str]:
        """Call ``get_all_epochs(page, page_size)``, returns epoch strings."""
        sc_val = self._simulate("get_all_epochs", [scv_u32(page), scv_u32(page_size)])
        items = extract_vec(sc_val)
        return [extract_string(item) for item in items]

    def get_total_epoch_count(self) -> int:
        """Call ``get_total_epoch_count()``."""
        sc_val = self._simulate("get_total_epoch_count", [])
        return extract_u32(sc_val)

    def get_epoch_businesses(self, epoch: str) -> List[bytes]:
        """Call ``get_epoch_businesses(epoch)``, returns raw address bytes."""
        sc_val = self._simulate("get_epoch_businesses", [scv_string(epoch)])
        items = extract_vec(sc_val)
        return [extract_address(item) for item in items]

    def get_snapshots_for_business(self, business_key: bytes) -> List[SnapshotRecord]:
        """Call ``get_snapshots_for_business(business)``.

        ``business_key`` is the raw 32-byte address.
        We pass it as an address SCVal.
        """
        # Guess the address type: try contract first, then account
        addr_arg = scv_address_contract(business_key)
        sc_val = self._simulate("get_snapshots_for_business", [addr_arg])
        items = extract_vec(sc_val)
        return [_parse_snapshot_record(item) for item in items]


# ══════════════════════════════════════════════════════════════════════
#  SnapshotRecord parsing
# ══════════════════════════════════════════════════════════════════════

class SnapshotRecord:
    """Python equivalent of the contract's ``SnapshotRecord`` struct.

    Fields (in order):
      period, trailing_revenue, anomaly_count, attestation_count, recorded_at
    """

    __slots__ = (
        "period",
        "trailing_revenue",
        "anomaly_count",
        "attestation_count",
        "recorded_at",
    )

    def __init__(
        self,
        period: str,
        trailing_revenue: int,
        anomaly_count: int,
        attestation_count: int,
        recorded_at: int,
    ):
        self.period = period
        self.trailing_revenue = trailing_revenue
        self.anomaly_count = anomaly_count
        self.attestation_count = attestation_count
        self.recorded_at = recorded_at

    def to_scval(self) -> SCVal:
        """Serialise to an ``SCVal::Vec`` matching the contract encoding."""
        return scv_vec(
            [
                scv_string(self.period),
                scv_i128(self.trailing_revenue),
                scv_u32(self.anomaly_count),
                scv_u64(self.attestation_count),
                scv_u64(self.recorded_at),
            ]
        )


def _parse_snapshot_record(sc_val: SCVal) -> SnapshotRecord:
    """Parse an ``SCVal::Vec`` (tuple encoding) into a ``SnapshotRecord``."""
    items = extract_vec(sc_val)
    if len(items) != 5:
        raise ValueError(f"expected 5 fields in SnapshotRecord, got {len(items)}")
    return SnapshotRecord(
        period=extract_string(items[0]),
        trailing_revenue=extract_i128(items[1]),
        anomaly_count=extract_u32(items[2]),
        attestation_count=extract_u64(items[3]),
        recorded_at=extract_u64(items[4]),
    )


# ══════════════════════════════════════════════════════════════════════
#  Commitment computation
# ══════════════════════════════════════════════════════════════════════

def compute_local_commitment(records: List[SnapshotRecord]) -> bytes:
    """Recompute the commitment hash over a list of ``SnapshotRecord``.

    Mirrors the contract's ``export_snapshot_commitment()``:

    1. Build an ``SCVal::Vec`` whose elements are ``SCVal::Vec`` tuples,
       each representing one ``SnapshotRecord`` in field order.
    2. Serialise the outer ``SCVal::Vec`` to XDR.
    3. Return ``sha256(xdr_bytes)``.
    """
    scv_records = [r.to_scval() for r in records]
    sc_vec = scv_vec(scv_records)
    xdr_bytes = sc_vec.to_xdr_bytes()
    return hashlib.sha256(xdr_bytes).digest()


# ══════════════════════════════════════════════════════════════════════
#  Main verification logic
# ══════════════════════════════════════════════════════════════════════

def verify(
    rpc_url: str,
    contract_id: str,
    network_passphrase: str,
    page_size: int = 64,
) -> bool:
    """
    Main verification routine.

    1. Get the on-chain commitment from the contract.
    2. Page through all epochs.
    3. For each epoch, get all businesses.
    4. For each business, get all snapshot records.
    5. Recompute the commitment locally.
    6. Compare and return PASS / FAIL.
    """
    logger.info("Connecting to %s", rpc_url)
    client = OnChainClient(rpc_url, contract_id, network_passphrase)

    # ── Step 1: On-chain commitment ──
    logger.info("Fetching on-chain commitment…")
    on_chain_commitment = client.get_commitment()
    logger.info("On-chain commitment: %s", on_chain_commitment.hex())

    # ── Step 2: Iterate all epochs and collect records ──
    logger.info("Fetching all epochs…")
    total_epochs = client.get_total_epoch_count()
    logger.info("Total epochs: %d", total_epochs)

    all_records: List[SnapshotRecord] = []
    epoch_offset = 0

    while epoch_offset < total_epochs:
        page = epoch_offset // page_size if page_size > 0 else 0
        remaining = total_epochs - epoch_offset
        fetch_size = min(page_size, remaining) if page_size > 0 else remaining

        chunks = page_size if page_size > 0 else remaining
        epochs = client.get_all_epochs(page, chunks)

        for epoch in epochs:
            logger.debug("  Epoch: %s", epoch)
            businesses = client.get_epoch_businesses(epoch)
            for biz_key in businesses:
                records = client.get_snapshots_for_business(biz_key)
                for rec in records:
                    all_records.append(rec)
            epoch_offset += 1

        # Safety check: if page_size is 0, we got all in one go
        if page_size == 0:
            break

    logger.info("Total snapshot records collected: %d", len(all_records))

    # ── Step 3: Local recomputation ──
    logger.info("Recomputing commitment locally…")
    local_commitment = compute_local_commitment(all_records)
    logger.info("Local commitment:      %s", local_commitment.hex())

    # ── Step 4: Compare ──
    if on_chain_commitment == local_commitment:
        logger.info("✓ PASS — commitments match!")
        return True
    else:
        logger.error("✗ FAIL — commitments do NOT match!")
        return False


# ══════════════════════════════════════════════════════════════════════
#  CLI entry point
# ══════════════════════════════════════════════════════════════════════

def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify on-chain snapshot commitment against local recomputation.",
    )
    parser.add_argument(
        "--rpc-url",
        required=True,
        help="Soroban RPC endpoint (e.g. https://soroban-testnet.stellar.org)",
    )
    parser.add_argument(
        "--contract-id",
        required=True,
        help="Contract ID (C... address) of the AttestationSnapshotContract",
    )
    parser.add_argument(
        "--network-passphrase",
        default=Network.TESTNET_NETWORK_PASSPHRASE,
        help="Stellar network passphrase (default: testnet)",
    )
    parser.add_argument("--page-size", type=int, default=64, help="RPC page size")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose logging"
    )
    return parser.parse_args(argv[1:])


def main() -> None:
    args = parse_args(sys.argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if not args.contract_id:
        logger.error("--contract-id is required")
        sys.exit(1)

    ok = verify(
        rpc_url=args.rpc_url,
        contract_id=args.contract_id,
        network_passphrase=args.network_passphrase,
        page_size=args.page_size,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
