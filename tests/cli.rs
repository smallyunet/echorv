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
    assert_eq!(document["summary"]["emittedEvidenceEvents"], 9);
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

#[test]
fn imports_a_spike_log_to_the_normalized_contract() {
    let log = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/spike/load-page-fault.log");
    let output = Command::new(env!("CARGO_BIN_EXE_echorv"))
        .args(["import", "spike", log.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schema"], "echorv.trace.v1");
    assert!(document["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["trap"]["cause"] == 13));
}

#[test]
fn doctor_fails_closed_when_spike_is_missing() {
    let output = Command::new(env!("CARGO_BIN_EXE_echorv"))
        .args(["doctor", "--spike", "/definitely/missing/echorv-spike"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("unavailable"));
}

#[test]
fn emits_sarif_and_can_fail_the_ci_gate() {
    let output = Command::new(env!("CARGO_BIN_EXE_echorv"))
        .args([
            "explain",
            fixture().to_str().unwrap(),
            "--format",
            "sarif",
            "--fail-on-diagnostic",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["version"], "2.1.0");
    assert_eq!(
        document["runs"][0]["results"][0]["ruleId"],
        "illegal-instruction"
    );
}
