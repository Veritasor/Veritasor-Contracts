#!/bin/bash
# WASM Size Budget Checker for Veritasor Contracts
#
# This script checks if compiled WASM binaries exceed their configured budgets.
# It's designed to run in CI to catch size regressions.
#
# Usage: ./scripts/check-wasm-sizes.sh [--strict] [--verbose]
#
# Options:
#   --strict    Fail on any warning (not just budget exceedance)
#   --verbose   Show detailed output for each contract
#   --help      Show this help message
#
# Exit codes:
#   0 - All contracts within budget
#   1 - One or more contracts exceeded budget
#   2 - Configuration or file not found

set -euo pipefail

CONFIG_FILE=${CONFIG_FILE:-wasm-size-budgets.toml}
WASM_DIR=${WASM_DIR:-target/wasm32-unknown-unknown/release}
STRICT_MODE=false
VERBOSE=false
EXIT_CODE=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --strict)
            STRICT_MODE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo 'Usage:' $0 '[OPTIONS]'
            echo
            echo 'Options:'
            echo '  --strict    Fail on any warning (not just budget exceedance)'
            echo '  --verbose   Show detailed output for each contract'
            echo '  --help      Show this help message'
            echo
            echo 'Environment variables:'
            echo '  CONFIG_FILE   Path to budget configuration (default: wasm-size-budgets.toml)'
            echo '  WASM_DIR      Path to WASM directory (default: target/wasm32-unknown-unknown/release)'
            exit 0
            ;;
        *)
            echo 'Error: Unknown option' $1
            exit 2
            ;;
    esac
done

# Check if config file exists
if [[ ! -f $CONFIG_FILE ]]; then
    echo 'Error: Configuration file not found:' $CONFIG_FILE
    exit 2
fi

# Check if WASM directory exists
if [[ ! -d $WASM_DIR ]]; then
    echo 'Error: WASM directory not found:' $WASM_DIR
    echo 'Build contracts first with: cargo build --release --target wasm32-unknown-unknown'
    exit 2
fi

echo ''
echo '============================================================'
echo ' Wasm Size Budget Check'
echo '============================================================'
echo ''

# Read config and check each contract
check_contract() {
    local package=$1
    local budget=$2
    local baseline=$3
    local warn_threshold=${4:-10}
    local status=$5
    local status_reason=${6:-}

    # Check if contract is blocked (doesn't compile)
    if [[ $status == blocked ]]; then
        if [[ $VERBOSE == false ]]; then
            return 0  # Silent skip unless verbose
        fi
        echo '' $package
        echo '  Status: BLOCKED'
        echo '  Reason:' $status_reason
        return 0
    fi

    # Find the WASM file for this package
    local wasm_pattern=$(echo $package | sed 's/veritasor-//;s/-/_/g')
    local wasm_file=$(ls $WASM_DIR/*.wasm 2>/dev/null | grep -E $wasm_pattern | head -1 || true)

    if [[ -z $wasm_file ]]; then
        if [[ $budget -eq 0 && $baseline -eq 0 ]]; then
            return 0  # Skip if no budget/baseline set
        fi
        echo '' '[ERROR] WASM file not found for' $package
        echo '  Expected pattern:' $WASM_DIR'/*'${wasm_pattern}'*.wasm'
        EXIT_CODE=2
        return
    fi

    # Get actual size
    local actual_size=$(stat -c%s $wasm_file 2>/dev/null || stat -f%z $wasm_file 2>/dev/null)
    local filename=$(basename $wasm_file)

    if $VERBOSE; then
        echo '' $package
        echo '  File:' $filename
        echo '  Size:' $actual_size 'bytes'
        echo '  Baseline:' $baseline 'bytes'
        echo '  Budget:' $budget 'bytes'
    fi

    # Check if within budget
    if [[ $actual_size -gt $budget ]]; then
        echo '' '[FAIL] EXCEEDED BUDGET'
        echo '  ' $filename':'$actual_size 'bytes (budget:' $budget')'
        echo '  Over by:' $((actual_size - budget)) 'bytes'
        EXIT_CODE=1
    elif [[ $baseline -gt 0 && $actual_size -gt $((baseline * (100 + warn_threshold) / 100)) ]]; then
        echo '' '[WARN] Growth exceeds threshold'
        echo '  ' $filename':'$actual_size 'bytes (baseline:' $baseline', threshold:' ${warn_threshold}'%)'
        echo '  Growth:' $(( (actual_size - baseline) * 100 / baseline ))'%'
        if $STRICT_MODE; then
            EXIT_CODE=1
        fi
    else
        if $VERBOSE; then
            echo '' '[PASS] Within budget'
        fi
    fi
}

# Parse the config file manually
current_package=
budget=0
baseline=0
warn_threshold=10
status=ok
status_reason=

while IFS= read -r line; do
    # Skip comments and empty lines
    [[ $line =~ ^# ]] && continue
    [[ -z $line ]] && continue

    # Check for section header
    if [[ $line == '[contract.'* ]]; then
        # Process previous contract if exists
        if [[ -n $current_package ]]; then
            check_contract $current_package $budget $baseline $warn_threshold $status $status_reason
        fi
        # Extract package name from [contract.package-name]
        current_package=${line:10}  # Remove '[contract.'
        current_package=${current_package%]}  # Remove trailing ']'
        budget=0
        baseline=0
        warn_threshold=10
        status=ok
        status_reason=
        continue
    fi

    # Parse key-value pairs
    if [[ $line =~ ^budget[[:space:]]*=[[:space:]]*(.+) ]]; then
        budget=$(echo ${BASH_REMATCH[1]} | tr -d ' ')
    elif [[ $line =~ ^baseline[[:space:]]*=[[:space:]]*(.+) ]]; then
        baseline=$(echo ${BASH_REMATCH[1]} | tr -d ' ')
    elif [[ $line =~ ^warn_threshold[[:space:]]*=[[:space:]]*(.+) ]]; then
        warn_threshold=$(echo ${BASH_REMATCH[1]} | tr -d ' ')
    elif [[ $line =~ ^status[[:space:]]*=[[:space:]]*(.+) ]]; then
        status=$(echo ${BASH_REMATCH[1]} | tr -d ' ')
    elif [[ $line =~ ^status_reason[[:space:]]*=[[:space:]]*(.+) ]]; then
        status_reason=${BASH_REMATCH[1]}
        status_reason=$(echo -n $status_reason | tr -d '\n')  # Trim trailing newline
    fi
done < $CONFIG_FILE

# Process last contract
if [[ -n $current_package ]]; then
    check_contract $current_package $budget $baseline $warn_threshold $status $status_reason
fi

echo ''
echo '============================================================'

if [[ $EXIT_CODE -eq 0 ]]; then
    echo '' '[OK] All contracts within budget'
    echo ''
elif [[ $EXIT_CODE -eq 1 ]]; then
    echo '' '[FAIL] One or more contracts exceeded budget'
    echo 'Run with --verbose for details'
else
    echo '' '[ERROR] Check failed - see errors above'
fi

exit $EXIT_CODE