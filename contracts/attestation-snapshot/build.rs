// No build-time cargo invocation to avoid deadlock when parent cargo holds the lock.
// For wasm32 builds, build the attestation WASM first, e.g.:
//   cargo build -p veritasor-attestation --release --target wasm32-unknown-unknown
fn main() {}
