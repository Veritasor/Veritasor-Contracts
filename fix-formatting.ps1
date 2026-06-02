# Fix code formatting issues for CI pipeline
# Run this script to auto-format all Rust code

Write-Host "=== Formatting Rust Code ===" -ForegroundColor Green

cargo fmt --all

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Formatting completed successfully" -ForegroundColor Green
    Write-Host ""
    Write-Host "Run the following to verify the build:" -ForegroundColor Yellow
    Write-Host "  cargo build --release --target wasm32-unknown-unknown"
} else {
    Write-Host "❌ Formatting failed" -ForegroundColor Red
    exit 1
}
