#!/usr/bin/env bash
# Dry-runs a protocol-dao proposal and reports its effect on the
# attestation contract's DAO-visible flat fee config
# (get_effective_flat_fee_config), without ever touching a network you
# don't control.
#
# This ALWAYS targets a local Soroban sandbox network — never a live
# testnet/mainnet directly — so "executing" the proposal to observe its
# effect is side-effect-free from the real network's point of view. To
# validate against real (forked) state rather than a bare local network,
# import a ledger snapshot of the relevant contracts before running this:
#
#   stellar network container start local
#   stellar snapshot create \
#     --network mainnet \
#     --address "$DAO_ID" --address "$ATTESTATION_ID" \
#     --output /tmp/veritasor-snapshot.json
#   stellar snapshot load --network local /tmp/veritasor-snapshot.json
#
# (Snapshot/fork commands are current as of stellar-cli 22.x — check
# `stellar snapshot --help` / `stellar network container --help` for your
# installed version; this repo does not pin a specific stellar-cli
# version.) Without a snapshot, this still works against a freshly
# initialized local sandbox — useful to sanity-check a proposal's
# structure/reachability even without real state to fork.
#
# Usage:
#   scripts/dry_run_proposal.sh \
#     --dao-id <DAO_CONTRACT_ID> \
#     --attestation-id <ATTESTATION_CONTRACT_ID> \
#     --source <FUNDED_SANDBOX_ACCOUNT> \
#     --executor <EXECUTOR_ADDRESS> \
#     --proposal-id <PROPOSAL_ID> \
#     [--network local]
set -euo pipefail

NETWORK="local"
DAO_ID=""
ATTESTATION_ID=""
SOURCE=""
EXECUTOR=""
PROPOSAL_ID=""

while [ $# -gt 0 ]; do
  case "$1" in
    --network) NETWORK="$2"; shift 2 ;;
    --dao-id) DAO_ID="$2"; shift 2 ;;
    --attestation-id) ATTESTATION_ID="$2"; shift 2 ;;
    --source) SOURCE="$2"; shift 2 ;;
    --executor) EXECUTOR="$2"; shift 2 ;;
    --proposal-id) PROPOSAL_ID="$2"; shift 2 ;;
    *) echo "unrecognized argument: $1" >&2; exit 2 ;;
  esac
done

for entry in "DAO_ID:--dao-id" "ATTESTATION_ID:--attestation-id" "SOURCE:--source" "EXECUTOR:--executor" "PROPOSAL_ID:--proposal-id"; do
  name="${entry%%:*}"
  flag="${entry#*:}"
  if [ -z "${!name}" ]; then
    echo "error: $flag is required (see --help usage in this script's header)" >&2
    exit 2
  fi
done

if ! command -v stellar >/dev/null 2>&1; then
  echo "error: the 'stellar' CLI is required (https://developers.stellar.org/docs/tools/cli/install-cli)" >&2
  exit 1
fi

if [ "$NETWORK" != "local" ]; then
  echo "warning: --network is '$NETWORK', not 'local'. This tool executes" >&2
  echo "the proposal for real against whatever network you point it at —" >&2
  echo "only pass a network you are prepared to actually mutate." >&2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_DIR="$SCRIPT_DIR/dry-run-proposal"

echo "Building dry-run-proposal..." >&2
cargo build --quiet --manifest-path "$TOOL_DIR/Cargo.toml" --release

"$TOOL_DIR/target/release/dry-run-proposal" \
  --network "$NETWORK" \
  --dao-id "$DAO_ID" \
  --attestation-id "$ATTESTATION_ID" \
  --source "$SOURCE" \
  --executor "$EXECUTOR" \
  --proposal-id "$PROPOSAL_ID"
