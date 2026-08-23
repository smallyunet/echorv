use crate::model::{DiagnosticCode, EvidenceDocument};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub fn render_sarif(evidence: &EvidenceDocument) -> Value {
    let rules = evidence
        .events
        .iter()
        .filter_map(|event| event.diagnostic)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|diagnostic| {
            let id = diagnostic_id(diagnostic);
            json!({
                "id": id,
                "name": id,
                "shortDescription": {"text": diagnostic_description(diagnostic)},
                "defaultConfiguration": {"level": "error"}
            })
        })
        .collect::<Vec<_>>();
    let results = evidence
        .events
        .iter()
        .filter_map(|event| {
            let diagnostic = event.diagnostic?;
            let mut result = json!({
                "ruleId": diagnostic_id(diagnostic),
                "level": "error",
                "message": {"text": event.explanation},
                "properties": {
                    "evidenceId": event.id,
                    "pc": event.pc,
                    "confidence": format!("{:?}", event.confidence).to_ascii_lowercase(),
                    "causedBy": event.caused_by
                }
            });
            if let Some(source) = &event.source {
                result["locations"] = json!([{
                    "physicalLocation": {
                        "artifactLocation": {"uri": source.file},
                        "region": {
                            "startLine": source.line.unwrap_or(1),
                            "startColumn": source.column.unwrap_or(1)
                        }
                    }
                }]);
            } else if let Some(symbol) = &event.symbol {
                result["locations"] = json!([{"logicalLocations": [{"name": symbol}]}]);
            }
            Some(result)
        })
        .collect::<Vec<_>>();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "EchoRV",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/smallyunet/echorv",
                "rules": rules
            }},
            "automationDetails": {"id": "echorv/firmware"},
            "results": results,
            "properties": {
                "evidenceSchema": evidence.schema,
                "targetIsa": evidence.target.isa,
                "backend": evidence.provenance.backend
            }
        }]
    })
}

fn diagnostic_id(diagnostic: DiagnosticCode) -> String {
    serde_json::to_value(diagnostic)
        .expect("diagnostic serializes")
        .as_str()
        .expect("diagnostic serializes as string")
        .to_owned()
}

fn diagnostic_description(diagnostic: DiagnosticCode) -> &'static str {
    match diagnostic {
        DiagnosticCode::InstructionAddressMisaligned => "Instruction address is misaligned",
        DiagnosticCode::InstructionAccessFault => "Instruction fetch access fault",
        DiagnosticCode::IllegalInstruction => "Illegal instruction trap",
        DiagnosticCode::Breakpoint => "Breakpoint trap",
        DiagnosticCode::LoadAddressMisaligned => "Load address is misaligned",
        DiagnosticCode::LoadAccessFault => "Load access fault",
        DiagnosticCode::StoreAddressMisaligned => "Store address is misaligned",
        DiagnosticCode::StoreAccessFault => "Store access fault",
        DiagnosticCode::EnvironmentCall => "Environment call trap",
        DiagnosticCode::InstructionPageFault => "Instruction page fault",
        DiagnosticCode::LoadPageFault => "Load page fault",
        DiagnosticCode::StorePageFault => "Store page fault",
        DiagnosticCode::UnknownTrap => "Unknown RISC-V trap",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyze, model::EvidenceProfile, TraceDocument};

    #[test]
    fn emits_sarif_rules_and_results_for_diagnostics() {
        let trace: TraceDocument =
            serde_json::from_str(include_str!("../fixtures/illegal-csr-trap.json")).unwrap();
        let evidence = analyze(trace, EvidenceProfile::Auto, 200).unwrap();
        let sarif = render_sarif(&evidence);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(
            sarif["runs"][0]["results"][0]["ruleId"],
            "illegal-instruction"
        );
    }
}
