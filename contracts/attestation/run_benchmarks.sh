#!/bin/bash
# Gas benchmark runner script for Veritasor contracts
#
# Usage:
#   ./run_benchmarks.sh [options]
#
# Options:
#   --all         Run all benchmark tests
#   --core        Run only core operation benchmarks
#   --batch       Run only batch operation benchmarks
#   --fee         Run only fee calculation benchmarks
#   --profiling   Run batch vs single gas profiling
#   --summary     Show summary report only
#   --help        Show this help message

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         Veritasor Contract Gas Benchmarks                      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

run_benchmarks() {
    local filter=$1
    local description=$2
    
    echo -e "${GREEN}Running $description...${NC}"
    echo ""
    
    cargo test "$filter" -- --nocapture --test-threads=1
    
    echo ""
}

show_help() {
    echo "Gas Benchmark Runner for Veritasor Contracts"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --all              Run all benchmark tests"
    echo "  --core             Run only core operation benchmarks"
    echo "  --batch            Run only batch operation benchmarks"
    echo "  --fee              Run only fee calculation benchmarks"
    echo "  --profiling        Run batch vs single gas profiling harness (Issue #783)"
    echo "  --profiling-full   Run full batch-vs-single suite including regression guards"
    echo "  --regression       Run all hard regression gate tests"
    echo "  --summary          Show summary report only"
    echo "  --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --all                    # Run all benchmarks"
    echo "  $0 --core                   # Run core operation benchmarks"
    echo "  $0 --profiling              # Batch vs single comparison (JSON output)"
    echo "  $0 --profiling-full         # Full profiling suite + regression guards"
    echo "  $0 --regression             # CI regression gates only"
    echo "  $0 --summary                # Show summary only"
    echo ""
    echo "JSON output from --profiling can be parsed with:"
    echo "  $0 --profiling 2>&1 | grep '^{\"op\":\"batch_vs_single\"'"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    --all)
        print_header
        run_benchmarks "gas_benchmark_test" "all benchmarks"
        ;;
    --core)
        print_header
        run_benchmarks "gas_benchmark_test::bench_submit_attestation_no_fee" "submit_attestation (no fee)"
        run_benchmarks "gas_benchmark_test::bench_submit_attestation_with_fee" "submit_attestation (with fee)"
        run_benchmarks "gas_benchmark_test::bench_verify_attestation" "verify_attestation"
        run_benchmarks "gas_benchmark_test::bench_revoke_attestation" "revoke_attestation"
        run_benchmarks "gas_benchmark_test::bench_migrate_attestation" "migrate_attestation"
        run_benchmarks "gas_benchmark_test::bench_get_attestation" "get_attestation"
        ;;
    --batch)
        print_header
        run_benchmarks "gas_benchmark_test::bench_submit_batch_small" "batch operations (small)"
        run_benchmarks "gas_benchmark_test::bench_submit_batch_large" "batch operations (large)"
        ;;
    --fee)
        print_header
        run_benchmarks "gas_benchmark_test::bench_fee_with_tier_discount" "fee with tier discount"
        run_benchmarks "gas_benchmark_test::bench_fee_with_volume_discount" "fee with volume discount"
        run_benchmarks "gas_benchmark_test::bench_fee_with_combined_discounts" "fee with combined discounts"
        run_benchmarks "gas_benchmark_test::bench_get_fee_quote" "get_fee_quote"
        ;;
    --profiling)
        print_header
        run_benchmarks "gas_benchmark_test::bench_batch_vs_single_profiling" "batch vs single profiling (Issue #783 — structured JSON report)"
        ;;
    --profiling-full)
        print_header
        run_benchmarks "gas_benchmark_test::bench_batch_vs_single_profiling" "batch vs single profiling harness"
        run_benchmarks "gas_benchmark_test::bench_batch_size_one_vs_single_within_tolerance" "batch size-1 vs single tolerance"
        run_benchmarks "gas_benchmark_test::bench_batch_max_size_within_regression_threshold" "batch MAX_BATCH_SIZE regression check"
        run_benchmarks "gas_benchmark_test::bench_batch_profiling_sequential_batches_independent" "sequential batches independence"
        run_benchmarks "gas_benchmark_test::bench_batch_profiling_backward_compatibility_single_then_batch" "backward compatibility: single then batch"
        run_benchmarks "gas_benchmark_test::regression_batch_vs_single_per_item_cpu" "regression gate: batch vs single per-item CPU"
        ;;
    --regression)
        print_header
        run_benchmarks "gas_benchmark_test::regression_" "all regression gate tests"
        ;;
    --summary)
        print_header
        cargo test gas_benchmark_test::bench_summary_report -- --nocapture
        ;;
    --help)
        show_help
        ;;
    *)
        echo -e "${YELLOW}No option specified. Use --help for usage information.${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}✓ Benchmark run complete${NC}"
echo ""
