use crate::model::{
    Confidence, DiagnosticCode, EvidenceDocument, EvidenceEvent, EvidenceKind, EvidenceProfile,
    EvidenceSummary, Privilege, StateKind, StateWrite, TraceDocument, TraceEvent,
};
use crate::{EVIDENCE_SCHEMA, TRACE_SCHEMA};
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub profile: EvidenceProfile,
    pub limit: usize,
    pub around_pc: Option<String>,
    pub around_trap: Option<u64>,
    pub before: usize,
    pub after: usize,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            profile: EvidenceProfile::Auto,
            limit: 200,
            around_pc: None,
            around_trap: None,
            before: 8,
            after: 4,
        }
    }
}

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
    analyze_with_options(
        trace,
        AnalyzeOptions {
            profile,
            limit,
            before: 0,
            after: 0,
            ..AnalyzeOptions::default()
        },
    )
}

pub fn analyze_with_options(
    trace: TraceDocument,
    options: AnalyzeOptions,
) -> Result<EvidenceDocument, AnalyzeError> {
    validate(&trace, options.limit)?;
    let input_events = trace.events.len();
    let selected = selected_indices(&trace, &options);
    let matched_trace_events = selected.len();
    let mut evidence = Vec::new();
    for index in selected {
        append_event_evidence(&mut evidence, &trace.events[index], options.profile);
    }

    let total_evidence_events = evidence.len();
    evidence.truncate(options.limit);
    let emitted_evidence_events = evidence.len();
    let truncated = emitted_evidence_events < total_evidence_events;
    let mut warnings = trace.provenance.notes.clone();
    if matched_trace_events == 0 {
        warnings.push("no trace events matched the requested evidence selection".to_owned());
    }
    if truncated {
        warnings.push(format!(
            "evidence output was limited to {} of {total_evidence_events} events",
            options.limit
        ));
    }

    Ok(EvidenceDocument {
        schema: EVIDENCE_SCHEMA.to_owned(),
        target: trace.target,
        provenance: trace.provenance,
        profile: profile_name(options.profile).to_owned(),
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

fn selected_indices(trace: &TraceDocument, options: &AnalyzeOptions) -> BTreeSet<usize> {
    let anchors: Vec<usize> = trace
        .events
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            if let Some(pc) = options.around_pc.as_deref() {
                return normalize_hex(&event.pc) == normalize_hex(pc);
            }
            if let Some(cause) = options.around_trap {
                return event.trap.as_ref().is_some_and(|trap| trap.cause == cause);
            }
            matches_profile(event, options.profile, trace)
        })
        .map(|(index, _)| index)
        .collect();

    let mut selected = BTreeSet::new();
    for anchor in anchors {
        let start = anchor.saturating_sub(options.before);
        let end = anchor
            .saturating_add(options.after)
            .saturating_add(1)
            .min(trace.events.len());
        selected.extend(start..end);
    }
    selected
}

fn matches_profile(event: &TraceEvent, profile: EvidenceProfile, trace: &TraceDocument) -> bool {
    match profile {
        EvidenceProfile::Auto => {
            if trace.events.iter().any(|event| event.trap.is_some()) {
                event.trap.is_some()
            } else {
                !event.writes.is_empty()
            }
        }
        EvidenceProfile::Trap => event.trap.is_some(),
        EvidenceProfile::Csr => {
            event.trap.is_some()
                || event
                    .writes
                    .iter()
                    .any(|write| write.kind == StateKind::Csr)
        }
        EvidenceProfile::Memory => {
            event
                .writes
                .iter()
                .any(|write| write.kind == StateKind::Memory)
                || event
                    .trap
                    .as_ref()
                    .is_some_and(|trap| matches!(trap.cause, 0 | 1 | 4 | 5 | 6 | 7 | 12 | 13 | 15))
        }
        EvidenceProfile::Privilege => {
            event.trap.is_some()
                || matches!(
                    event.instruction.split_whitespace().next(),
                    Some("ecall" | "mret" | "sret" | "uret")
                )
        }
        EvidenceProfile::Full => true,
    }
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
    output.push(event_evidence(
        instruction_id.clone(),
        EvidenceKind::Instruction,
        event,
        instruction_explanation,
        Confidence::Observed,
        None,
        Vec::new(),
        None,
    ));

    let mut trap_id = None;
    if let Some(trap) = &event.trap {
        let id = next_id(output.len());
        output.push(event_evidence(
            id.clone(),
            EvidenceKind::Trap,
            event,
            format!(
                "trap {} ({}) was raised; tval={}, handler={}",
                trap.cause,
                trap.name,
                trap.tval.as_deref().unwrap_or("not recorded"),
                trap.target_pc
            ),
            Confidence::Observed,
            Some(diagnostic_code(trap.cause)),
            vec![instruction_id.clone()],
            None,
        ));
        let (explanation, confidence) = diagnosis(trap.cause, event.privilege);
        output.push(event_evidence(
            next_id(output.len()),
            EvidenceKind::Diagnosis,
            event,
            explanation,
            confidence,
            Some(diagnostic_code(trap.cause)),
            vec![id.clone()],
            None,
        ));
        append_derived_trap_csrs(output, event, &id);
        trap_id = Some(id);
    }

    for write in &event.writes {
        if !emit_write(write, profile, event.trap.is_some()) {
            continue;
        }
        output.push(event_evidence(
            next_id(output.len()),
            EvidenceKind::StateChange,
            event,
            format!(
                "{} `{}` changed from {} to {}",
                write.kind,
                write.name,
                write.before.as_deref().unwrap_or("unknown"),
                write.after
            ),
            Confidence::Observed,
            None,
            vec![trap_id.clone().unwrap_or_else(|| instruction_id.clone())],
            Some(write.clone()),
        ));
    }

    if let Some(trap) = &event.trap {
        output.push(event_evidence(
            next_id(output.len()),
            EvidenceKind::PrivilegeTransition,
            event,
            format!(
                "control transferred from {}-mode at {} to {}-mode at {}{}",
                event.privilege,
                event.pc,
                trap.to_privilege,
                trap.target_pc,
                if trap.delegated == Some(true) {
                    " through delegated trap handling"
                } else {
                    ""
                }
            ),
            Confidence::Derived,
            None,
            vec![trap_id.expect("trap evidence exists")],
            None,
        ));
    }
}

fn append_derived_trap_csrs(output: &mut Vec<EvidenceEvent>, event: &TraceEvent, trap_id: &str) {
    let Some(trap) = event.trap.as_ref() else {
        return;
    };
    let prefix = if trap.to_privilege == Privilege::M {
        "m"
    } else {
        "s"
    };
    let values = [
        (format!("{prefix}cause"), format!("0x{:x}", trap.cause)),
        (format!("{prefix}epc"), event.pc.clone()),
        (
            format!("{prefix}tval"),
            trap.tval.clone().unwrap_or_else(|| "unknown".to_owned()),
        ),
    ];
    for (name, after) in values {
        if event
            .writes
            .iter()
            .any(|write| write.kind == StateKind::Csr && write.name == name)
        {
            continue;
        }
        let state = StateWrite {
            kind: StateKind::Csr,
            name: name.clone(),
            before: None,
            after: after.clone(),
        };
        output.push(event_evidence(
            next_id(output.len()),
            EvidenceKind::StateChange,
            event,
            format!("trap handling derives CSR `{name}` = {after}"),
            Confidence::Derived,
            None,
            vec![trap_id.to_owned()],
            Some(state),
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn event_evidence(
    id: String,
    kind: EvidenceKind,
    event: &TraceEvent,
    explanation: String,
    confidence: Confidence,
    diagnostic: Option<DiagnosticCode>,
    caused_by: Vec<String>,
    state: Option<StateWrite>,
) -> EvidenceEvent {
    EvidenceEvent {
        id,
        kind,
        trace_sequence: event.sequence,
        pc: event.pc.clone(),
        explanation,
        confidence,
        diagnostic,
        symbol: event.symbol.clone(),
        source: event.source.clone(),
        caused_by,
        state,
    }
}

fn emit_write(write: &StateWrite, profile: EvidenceProfile, trapped: bool) -> bool {
    match profile {
        EvidenceProfile::Csr => write.kind == StateKind::Csr,
        EvidenceProfile::Memory => write.kind == StateKind::Memory,
        EvidenceProfile::Trap => trapped && write.kind == StateKind::Csr,
        EvidenceProfile::Privilege => write.kind == StateKind::Csr,
        EvidenceProfile::Auto | EvidenceProfile::Full => true,
    }
}

fn diagnostic_code(cause: u64) -> DiagnosticCode {
    match cause {
        0 => DiagnosticCode::InstructionAddressMisaligned,
        1 => DiagnosticCode::InstructionAccessFault,
        2 => DiagnosticCode::IllegalInstruction,
        3 => DiagnosticCode::Breakpoint,
        4 => DiagnosticCode::LoadAddressMisaligned,
        5 => DiagnosticCode::LoadAccessFault,
        6 => DiagnosticCode::StoreAddressMisaligned,
        7 => DiagnosticCode::StoreAccessFault,
        8 | 9 | 11 => DiagnosticCode::EnvironmentCall,
        12 => DiagnosticCode::InstructionPageFault,
        13 => DiagnosticCode::LoadPageFault,
        15 => DiagnosticCode::StorePageFault,
        _ => DiagnosticCode::UnknownTrap,
    }
}

fn diagnosis(cause: u64, privilege: Privilege) -> (String, Confidence) {
    match cause {
        0 => ("instruction fetch address was not aligned for the active ISA; inspect the branch target and compressed-instruction support".to_owned(), Confidence::Derived),
        1 => ("physical instruction fetch failed; PMP, PMA, or an unmapped region are candidates because a generic Spike trace does not identify the rejecting check".to_owned(), Confidence::Inferred),
        2 => (format!("the instruction is unavailable or not permitted in {privilege}-mode; verify enabled ISA extensions, encoding, and CSR privilege"), Confidence::Derived),
        3 => ("execution reached an EBREAK or debug breakpoint".to_owned(), Confidence::Derived),
        4 | 6 => ("the effective data address violated the active alignment requirement; inspect the base register and immediate offset".to_owned(), Confidence::Derived),
        5 | 7 => ("physical data access failed; PMP, PMA, or an unmapped region are candidates because a generic Spike trace does not identify the rejecting check".to_owned(), Confidence::Inferred),
        8 | 9 | 11 => (format!("ECALL intentionally transferred control from {privilege}-mode; inspect the ABI number, arguments, delegation CSRs, and handler return value"), Confidence::Derived),
        12 | 13 | 15 => ("virtual address translation or PTE permission checks failed; inspect satp and the PTE V/R/W/X/U/A/D bits for the faulting address".to_owned(), Confidence::Derived),
        _ => ("the backend reported a trap that EchoRV does not yet classify".to_owned(), Confidence::Observed),
    }
}

fn profile_name(profile: EvidenceProfile) -> &'static str {
    match profile {
        EvidenceProfile::Auto => "auto",
        EvidenceProfile::Trap => "trap",
        EvidenceProfile::Csr => "csr",
        EvidenceProfile::Memory => "memory",
        EvidenceProfile::Privilege => "privilege",
        EvidenceProfile::Full => "full",
    }
}

fn normalize_hex(value: &str) -> String {
    let trimmed = value.trim().to_ascii_lowercase();
    let digits = trimmed.trim_start_matches("0x").trim_start_matches('0');
    format!("0x{}", if digits.is_empty() { "0" } else { digits })
}

fn next_id(index: usize) -> String {
    format!("ev-{index:04}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Privilege, Provenance, Target, Trap};

    fn trace(cause: u64) -> TraceDocument {
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
                hart: Some(0),
                pc: "0x802001ac".to_owned(),
                instruction: "csrw satp, a0".to_owned(),
                instruction_bytes: Some("0x18051073".to_owned()),
                privilege: Privilege::U,
                symbol: Some("enter_user_mode".to_owned()),
                source: None,
                writes: Vec::new(),
                trap: Some(Trap {
                    cause,
                    name: "illegal-instruction".to_owned(),
                    tval: Some("0x18051073".to_owned()),
                    target_pc: "0x80000000".to_owned(),
                    to_privilege: Privilege::M,
                    delegated: Some(false),
                }),
            }],
        }
    }

    #[test]
    fn builds_a_bounded_trap_chain_with_diagnosis() {
        let evidence = analyze(trace(2), EvidenceProfile::Trap, 4).unwrap();
        assert_eq!(evidence.schema, EVIDENCE_SCHEMA);
        assert!(evidence.summary.total_evidence_events >= 7);
        assert_eq!(evidence.summary.emitted_evidence_events, 4);
        assert!(evidence.summary.truncated);
        assert_eq!(evidence.events[1].caused_by, vec!["ev-0000"]);
        assert_eq!(
            evidence.events[2].diagnostic,
            Some(DiagnosticCode::IllegalInstruction)
        );
        assert_eq!(evidence.events[3].caused_by, vec!["ev-0001"]);
    }

    #[test]
    fn classifies_all_supported_fault_families() {
        for cause in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 15] {
            let evidence = analyze(trace(cause), EvidenceProfile::Auto, 100).unwrap();
            assert!(evidence
                .events
                .iter()
                .any(|event| event.kind == EvidenceKind::Diagnosis));
        }
    }

    #[test]
    fn accepts_padded_pc_queries() {
        let evidence = analyze_with_options(
            trace(2),
            AnalyzeOptions {
                around_pc: Some("0x00000000802001ac".to_owned()),
                ..AnalyzeOptions::default()
            },
        )
        .unwrap();
        assert_eq!(evidence.summary.matched_trace_events, 1);
    }

    #[test]
    fn rejects_non_riscv_input() {
        let mut input = trace(2);
        input.target.architecture = "arm64".to_owned();
        assert_eq!(
            analyze(input, EvidenceProfile::Full, 10).unwrap_err(),
            AnalyzeError::UnsupportedArchitecture("arm64".to_owned())
        );
    }
}
