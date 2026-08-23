use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EvidenceProfile {
    /// Select the most relevant evidence for the observed execution.
    Auto,
    /// Emit only trap-related causal chains.
    Trap,
    /// Emit CSR writes and related traps.
    Csr,
    /// Emit memory changes and memory-related traps.
    Memory,
    /// Emit privilege-changing instructions and traps.
    Privilege,
    /// Emit instructions, state changes, and traps.
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EvidenceFormat {
    Human,
    Json,
    Jsonl,
    Sarif,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceDocument {
    pub schema: String,
    pub target: Target,
    #[serde(default)]
    pub provenance: Provenance,
    pub events: Vec<TraceEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub architecture: String,
    pub xlen: u16,
    pub isa: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceEvent {
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hart: Option<u64>,
    pub pc: String,
    pub instruction: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction_bytes: Option<String>,
    pub privilege: Privilege,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocation>,
    #[serde(default)]
    pub writes: Vec<StateWrite>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap: Option<Trap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Privilege {
    M,
    S,
    U,
}

impl std::fmt::Display for Privilege {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateWrite {
    pub kind: StateKind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    pub after: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StateKind {
    Register,
    Csr,
    Memory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceLocation {
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

impl std::fmt::Display for StateKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Register => "register",
            Self::Csr => "CSR",
            Self::Memory => "memory",
        };
        formatter.write_str(label)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Trap {
    pub cause: u64,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tval: Option<String>,
    pub target_pc: String,
    pub to_privilege: Privilege,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDocument {
    pub schema: String,
    pub target: Target,
    pub provenance: Provenance,
    pub profile: String,
    pub summary: EvidenceSummary,
    pub events: Vec<EvidenceEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceSummary {
    pub input_events: usize,
    pub matched_trace_events: usize,
    pub total_evidence_events: usize,
    pub emitted_evidence_events: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceEvent {
    pub id: String,
    pub kind: EvidenceKind,
    pub trace_sequence: u64,
    pub pc: String,
    pub explanation: String,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<DiagnosticCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caused_by: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateWrite>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Instruction,
    StateChange,
    Trap,
    Diagnosis,
    PrivilegeTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Observed,
    Derived,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticCode {
    InstructionAddressMisaligned,
    InstructionAccessFault,
    IllegalInstruction,
    Breakpoint,
    LoadAddressMisaligned,
    LoadAccessFault,
    StoreAddressMisaligned,
    StoreAccessFault,
    EnvironmentCall,
    InstructionPageFault,
    LoadPageFault,
    StorePageFault,
    UnknownTrap,
}
