//! Core types and analysis for EchoRV.

pub mod analyzer;
pub mod model;

pub use analyzer::{analyze, AnalyzeError};
pub use model::{EvidenceDocument, EvidenceFormat, EvidenceProfile, TraceDocument};

pub const TRACE_SCHEMA: &str = "echorv.trace.v1";
pub const EVIDENCE_SCHEMA: &str = "echorv.evidence.v1";
