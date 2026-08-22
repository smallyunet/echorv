use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use echorv::{analyze, EvidenceDocument, EvidenceFormat, EvidenceProfile, TraceDocument};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "echorv",
    version,
    about = "Bounded causal execution evidence for RISC-V firmware"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Explain a normalized RISC-V execution trace.
    Explain {
        /// Path to an echorv.trace.v1 JSON document.
        #[arg(value_name = "TRACE")]
        trace: PathBuf,
        /// Evidence selection profile.
        #[arg(long, value_enum, default_value_t = EvidenceProfile::Trap)]
        profile: EvidenceProfile,
        /// Maximum number of evidence events to emit.
        #[arg(long, default_value_t = 100, value_parser = parse_limit)]
        limit: usize,
        /// Output representation.
        #[arg(long, value_enum, default_value_t = EvidenceFormat::Human)]
        format: EvidenceFormat,
        /// Write output to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Explain {
            trace,
            profile,
            limit,
            format,
            output,
        } => explain(trace, profile, limit, format, output),
    }
}

fn explain(
    path: PathBuf,
    profile: EvidenceProfile,
    limit: usize,
    format: EvidenceFormat,
    output: Option<PathBuf>,
) -> Result<()> {
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("failed to read trace {}", path.display()))?;
    let trace: TraceDocument = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse trace {}", path.display()))?;
    let evidence = analyze(trace, profile, limit).context("failed to analyze trace")?;

    let rendered = match format {
        EvidenceFormat::Human => render_human(&evidence),
        EvidenceFormat::Json => serde_json::to_string_pretty(&evidence)?,
        EvidenceFormat::Jsonl => render_jsonl(&evidence)?,
    };

    match output {
        Some(path) => fs::write(&path, format!("{rendered}\n"))
            .with_context(|| format!("failed to write evidence {}", path.display())),
        None => {
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{rendered}").context("failed to write evidence")
        }
    }
}

fn render_human(evidence: &EvidenceDocument) -> String {
    let mut lines = vec![format!(
        "EchoRV evidence | {} | {} | profile={} | {}/{} events{}",
        evidence.target.isa,
        evidence.target.xlen,
        evidence.profile,
        evidence.summary.emitted_evidence_events,
        evidence.summary.total_evidence_events,
        if evidence.summary.truncated {
            " (truncated)"
        } else {
            ""
        }
    )];
    for event in &evidence.events {
        let cause = if event.caused_by.is_empty() {
            String::new()
        } else {
            format!(" <- {}", event.caused_by.join(","))
        };
        lines.push(format!(
            "{} [{:?}] {}{}",
            event.id, event.kind, event.explanation, cause
        ));
    }
    for warning in &evidence.warnings {
        lines.push(format!("warning: {warning}"));
    }
    lines.join("\n")
}

fn render_jsonl(evidence: &EvidenceDocument) -> Result<String> {
    let mut lines = vec![serialize_line(&json!({
        "recordType": "header",
        "schema": evidence.schema,
        "target": evidence.target,
        "provenance": evidence.provenance,
        "profile": evidence.profile,
    }))?];
    for event in &evidence.events {
        lines.push(serialize_line(&json!({
            "recordType": "event",
            "event": event,
        }))?);
    }
    lines.push(serialize_line(&json!({
        "recordType": "summary",
        "summary": evidence.summary,
        "warnings": evidence.warnings,
    }))?);
    Ok(lines.join("\n"))
}

fn serialize_line<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("failed to serialize JSONL record")
}

fn parse_limit(value: &str) -> std::result::Result<usize, String> {
    let limit = value
        .parse::<usize>()
        .map_err(|_| "limit must be a positive integer".to_owned())?;
    if limit == 0 {
        return Err("limit must be greater than zero".to_owned());
    }
    Ok(limit)
}
