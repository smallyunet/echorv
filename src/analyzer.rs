use crate::model::{
    EvidenceDocument, EvidenceEvent, EvidenceKind, EvidenceProfile, EvidenceSummary, StateKind,
    TraceDocument, TraceEvent,
};
use crate::{EVIDENCE_SCHEMA, TRACE_SCHEMA};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnalyzeError {
    #[error("unsupported trace schema `{0}`; expected `{TRACE_SCHEMA}`")]
    UnsupportedSchema(String),
    #[error("target architecture must be `risc-v`, got `{0}`")]
    UnsupportedArchitecture(String),
    #[error("target xlen must be 32 or 64, got {0}")]
    UnsupportedXlen(u16),
    #[error("trace sequence must increase strictly; {current} follows {previous}")]
    NonMonotonicSequence { previous: u64, current: u64 },
    #[error("evidence limit must be greater than zero")]
    ZeroLimit,
}

pub fn analyze(
    trace: TraceDocument,
    profile: EvidenceProfile,
    limit: usize,
) -> Result<EvidenceDocument, AnalyzeError> {
    validate(&trace, limit)?;

    let input_events = trace.events.len();
    let selected: Vec<&TraceEvent> = trace
        .events
        .iter()
        .filter(|event| profile == EvidenceProfile::Full || event.trap.is_some())
        .collect();
    let matched_trace_events = selected.len();
    let mut evidence = Vec::new();

    for event in selected {
        append_event_evidence(&mut evidence, event, profile);
    }

    let total_evidence_events = evidence.len();
    evidence.truncate(limit);
    let emitted_evidence_events = evidence.len();
    let truncated = emitted_evidence_events < total_evidence_events;
    let mut warnings = Vec::new();
    if profile == EvidenceProfile::Trap && matched_trace_events == 0 {
        warnings.push("the trace contains no trap events".to_owned());
    }
    if truncated {
        warnings.push(format!(
            "evidence output was limited to {limit} of {total_evidence_events} events"
        ));
    }

    Ok(EvidenceDocument {
        schema: EVIDENCE_SCHEMA.to_owned(),
        target: trace.target,
        provenance: trace.provenance,
        profile: match profile {
            EvidenceProfile::Trap => "trap",
            EvidenceProfile::Full => "full",
        }
        .to_owned(),
        summary: EvidenceSummary {
            input_events,
            matched_trace_events,
            total_evidence_events,
            emitted_evidence_events,
            truncated,
        },
        events: evidence,
        warnings,
    })
}

fn validate(trace: &TraceDocument, limit: usize) -> Result<(), AnalyzeError> {
    if trace.schema != TRACE_SCHEMA {
        return Err(AnalyzeError::UnsupportedSchema(trace.schema.clone()));
    }
    if !trace.target.architecture.eq_ignore_ascii_case("risc-v") {
        return Err(AnalyzeError::UnsupportedArchitecture(
            trace.target.architecture.clone(),
        ));
    }
    if !matches!(trace.target.xlen, 32 | 64) {
        return Err(AnalyzeError::UnsupportedXlen(trace.target.xlen));
    }
    if limit == 0 {
        return Err(AnalyzeError::ZeroLimit);
    }
    for pair in trace.events.windows(2) {
        if pair[1].sequence <= pair[0].sequence {
            return Err(AnalyzeError::NonMonotonicSequence {
                previous: pair[0].sequence,
                current: pair[1].sequence,
            });
        }
    }
    Ok(())
}

fn append_event_evidence(
    output: &mut Vec<EvidenceEvent>,
    event: &TraceEvent,
    profile: EvidenceProfile,
) {
    let instruction_id = next_id(output.len());
    let instruction_explanation = if event.trap.is_some() {
        format!(
            "{}-mode instruction `{}` at {} initiated a trap",
            event.privilege, event.instruction, event.pc
        )
    } else {
        format!(
            "{}-mode executed `{}` at {}",
            event.privilege, event.instruction, event.pc
        )
    };
    output.push(EvidenceEvent {
        id: instruction_id.clone(),
        kind: EvidenceKind::Instruction,
        trace_sequence: event.sequence,
        pc: event.pc.clone(),
        explanation: instruction_explanation,
        caused_by: vec![],
        state: None,
    });

    let mut trap_id = None;
    if let Some(trap) = &event.trap {
        let id = next_id(output.len());
        output.push(EvidenceEvent {
            id: id.clone(),
            kind: EvidenceKind::Trap,
            trace_sequence: event.sequence,
            pc: event.pc.clone(),
            explanation: format!(
                "trap {} ({}) was raised; tval={}, handler={}",
                trap.cause,
                trap.name,
                trap.tval.as_deref().unwrap_or("not recorded"),
                trap.target_pc
            ),
            caused_by: vec![instruction_id.clone()],
            state: None,
        });
        trap_id = Some(id);
    }

    for write in &event.writes {
        let trap_csr = matches!(write.kind, StateKind::Csr)
            && matches!(
                write.name.as_str(),
                "mcause" | "mepc" | "mtval" | "scause" | "sepc" | "stval"
            );
        if profile == EvidenceProfile::Trap && !trap_csr {
            continue;
        }
        output.push(EvidenceEvent {
            id: next_id(output.len()),
            kind: EvidenceKind::StateChange,
            trace_sequence: event.sequence,
            pc: event.pc.clone(),
            explanation: format!(
                "{} `{}` changed from {} to {}",
                write.kind,
                write.name,
                write.before.as_deref().unwrap_or("unknown"),
                write.after
            ),
            caused_by: vec![trap_id.clone().unwrap_or_else(|| instruction_id.clone())],
            state: Some(write.clone()),
        });
    }

    if let Some(trap) = &event.trap {
        output.push(EvidenceEvent {
            id: next_id(output.len()),
            kind: EvidenceKind::PrivilegeTransition,
            trace_sequence: event.sequence,
            pc: event.pc.clone(),
            explanation: format!(
                "control transferred from {}-mode at {} to {}-mode at {}",
                event.privilege, event.pc, trap.to_privilege, trap.target_pc
            ),
            caused_by: vec![trap_id.expect("trap evidence exists")],
            state: None,
        });
    }
}

fn next_id(index: usize) -> String {
    format!("ev-{index:04}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Privilege, Provenance, StateWrite, Target, Trap};

    fn trace() -> TraceDocument {
        TraceDocument {
            schema: TRACE_SCHEMA.to_owned(),
            target: Target {
                architecture: "risc-v".to_owned(),
                xlen: 64,
                isa: "rv64imac_zicsr".to_owned(),
                platform: Some("virt".to_owned()),
            },
            provenance: Provenance::default(),
            events: vec![TraceEvent {
                sequence: 7,
                pc: "0x802001ac".to_owned(),
                instruction: "csrw satp, a0".to_owned(),
                privilege: Privilege::U,
                writes: vec![StateWrite {
                    kind: StateKind::Csr,
                    name: "mcause".to_owned(),
                    before: Some("0x0".to_owned()),
                    after: "0x2".to_owned(),
                }],
                trap: Some(Trap {
                    cause: 2,
                    name: "illegal-instruction".to_owned(),
                    tval: Some("0x18051073".to_owned()),
                    target_pc: "0x80000000".to_owned(),
                    to_privilege: Privilege::M,
                }),
            }],
        }
    }

    #[test]
    fn builds_a_bounded_trap_chain() {
        let evidence = analyze(trace(), EvidenceProfile::Trap, 3).unwrap();
        assert_eq!(evidence.schema, EVIDENCE_SCHEMA);
        assert_eq!(evidence.summary.total_evidence_events, 4);
        assert_eq!(evidence.summary.emitted_evidence_events, 3);
        assert!(evidence.summary.truncated);
        assert_eq!(evidence.events[1].caused_by, vec!["ev-0000"]);
        assert_eq!(evidence.events[2].caused_by, vec!["ev-0001"]);
    }

    #[test]
    fn rejects_non_riscv_input() {
        let mut input = trace();
        input.target.architecture = "arm64".to_owned();
        assert_eq!(
            analyze(input, EvidenceProfile::Full, 10).unwrap_err(),
            AnalyzeError::UnsupportedArchitecture("arm64".to_owned())
        );
    }
}
