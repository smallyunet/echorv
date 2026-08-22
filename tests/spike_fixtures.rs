use echorv::{analyze, parse_spike_log, EvidenceProfile};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    log: String,
    cause: u64,
    diagnostic: String,
    confidence: String,
}

#[test]
fn parses_the_supported_spike_trap_corpus() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cases: Vec<Case> = serde_json::from_str(
        &fs::read_to_string(root.join("benchmarks/diagnostics/cases.json")).unwrap(),
    )
    .unwrap();

    for case in cases {
        let log = fs::read_to_string(root.join(&case.log)).unwrap();
        let trace = parse_spike_log(&log, "rv64imac_zicsr", &case.log).unwrap();
        assert!(
            trace.events.iter().any(|event| event
                .trap
                .as_ref()
                .is_some_and(|trap| trap.cause == case.cause)),
            "{} did not yield cause {}",
            case.id,
            case.cause
        );
        let evidence = analyze(trace, EvidenceProfile::Auto, 100).unwrap();
        let evidence = serde_json::to_value(evidence).unwrap();
        assert!(
            evidence["events"].as_array().unwrap().iter().any(|event| {
                event["diagnostic"] == case.diagnostic && event["confidence"] == case.confidence
            }),
            "{} did not yield {} with {} confidence",
            case.id,
            case.diagnostic,
            case.confidence
        );
    }
}
