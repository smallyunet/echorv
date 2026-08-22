use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/illegal-csr-trap.json")
}

#[test]
fn emits_machine_readable_trap_evidence() {
    let output = Command::new(env!("CARGO_BIN_EXE_echorv"))
        .args(["explain", fixture().to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schema"], "echorv.evidence.v1");
    assert_eq!(document["summary"]["inputEvents"], 2);
    assert_eq!(document["summary"]["emittedEvidenceEvents"], 6);
    assert_eq!(document["events"][1]["causedBy"][0], "ev-0000");
}

#[test]
fn rejects_a_zero_limit_at_the_cli_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_echorv"))
        .args(["explain", fixture().to_str().unwrap(), "--limit", "0"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("greater than zero"));
}
