//! Core types and analysis for EchoRV.

pub mod analyzer;
pub mod elf;
pub mod model;
pub mod sarif;
pub mod spike;

pub use analyzer::{analyze, analyze_with_options, AnalyzeError, AnalyzeOptions};
pub use elf::{enrich_trace, inspect_elf, ElfInfo, ElfInspectError};
pub use model::{EvidenceDocument, EvidenceFormat, EvidenceProfile, TraceDocument};
pub use sarif::render_sarif;
pub use spike::{parse_spike_log, run_spike, SpikeRunOptions};

pub const TRACE_SCHEMA: &str = "echorv.trace.v1";
pub const EVIDENCE_SCHEMA: &str = "echorv.evidence.v1";
