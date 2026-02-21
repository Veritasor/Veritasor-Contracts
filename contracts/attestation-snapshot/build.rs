// When building the snapshot contract for WASM, ensure the attestation WASM exists
// so contractimport! can load it (avoids linking the attestation crate and duplicate symbols).
fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("wasm32") {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let workspace_root = std::path::Path::new(&manifest_dir).join("../..");
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "-p",
                "veritasor-attestation",
                "--release",
                "--target",
                &target,
            ])
            .current_dir(workspace_root)
            .status();
        if let Ok(s) = status {
            if !s.success() {
                panic!("failed to build veritasor-attestation WASM (run from workspace root)");
            }
        } else {
            panic!("could not run cargo to build veritasor-attestation");
        }
    }
}
