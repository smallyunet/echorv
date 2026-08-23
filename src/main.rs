use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use echorv::spike::spike_version;
use echorv::{
    analyze_with_options, enrich_trace, inspect_elf, parse_spike_log, render_sarif, run_spike,
    AnalyzeOptions, ElfInfo, EvidenceDocument, EvidenceFormat, EvidenceProfile, SpikeRunOptions,
    TraceDocument,
};
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

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
        /// Optional ELF used for symbol and DWARF source enrichment.
        #[arg(long)]
        elf: Option<PathBuf>,
        #[command(flatten)]
        evidence: EvidenceArgs,
    },
    /// Execute a RISC-V ELF with Spike and emit causal evidence.
    Run {
        #[arg(value_name = "ELF")]
        elf: PathBuf,
        /// Spike executable path.
        #[arg(long, default_value = "spike")]
        spike: PathBuf,
        /// RISC-V ISA string passed to Spike.
        #[arg(long, default_value = "rv64imac_zicsr")]
        isa: String,
        /// Kill Spike after this many seconds.
        #[arg(long, default_value_t = 10, value_parser = parse_positive_u64)]
        timeout: u64,
        /// Additional argument passed to Spike before the ELF path.
        #[arg(long = "spike-arg", allow_hyphen_values = true)]
        spike_args: Vec<String>,
        /// Save the normalized echorv.trace.v1 document.
        #[arg(long)]
        trace_output: Option<PathBuf>,
        #[command(flatten)]
        evidence: EvidenceArgs,
    },
    /// Normalize a backend execution log into echorv.trace.v1.
    Import {
        #[arg(value_enum)]
        backend: Backend,
        #[arg(value_name = "LOG")]
        log: PathBuf,
        /// ISA used by the recorded execution.
        #[arg(long, default_value = "rv64imac_zicsr")]
        isa: String,
        /// Optional ELF used for symbols and DWARF source locations.
        #[arg(long)]
        elf: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Inspect RISC-V ELF architecture, entry point, DWARF, and symbols.
    Inspect {
        #[arg(value_name = "ELF")]
        elf: PathBuf,
        #[arg(long, value_enum, default_value_t = InspectFormat::Human)]
        format: InspectFormat,
    },
    /// Check external backend availability and versions.
    Doctor {
        #[arg(long, default_value = "spike")]
        spike: PathBuf,
        #[arg(long, value_enum, default_value_t = InspectFormat::Human)]
        format: InspectFormat,
    },
}

#[derive(Debug, Clone, Args)]
struct EvidenceArgs {
    /// Evidence selection profile.
    #[arg(long, value_enum, default_value_t = EvidenceProfile::Auto)]
    profile: EvidenceProfile,
    /// Maximum number of evidence events to emit.
    #[arg(long, alias = "max-events", default_value_t = 200, value_parser = parse_limit)]
    limit: usize,
    /// Select context around an exact PC.
    #[arg(long)]
    around_pc: Option<String>,
    /// Select context around traps with this numeric cause.
    #[arg(long)]
    around_trap: Option<u64>,
    /// Include this many trace events before each match.
    #[arg(long, default_value_t = 8)]
    before: usize,
    /// Include this many trace events after each match.
    #[arg(long, default_value_t = 4)]
    after: usize,
    /// Output representation.
    #[arg(long, value_enum, default_value_t = EvidenceFormat::Human)]
    format: EvidenceFormat,
    /// Write output to a file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Exit non-zero after writing evidence when a diagnostic is present.
    #[arg(long)]
    fail_on_diagnostic: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Backend {
    Spike,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InspectFormat {
    Human,
    Json,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Explain {
            trace,
            elf,
            evidence,
        } => {
            let mut trace = read_trace(&trace)?;
            if let Some(elf) = elf {
                enrich_trace(&mut trace, elf).context("failed to enrich trace from ELF")?;
            }
            explain_trace(trace, evidence)
        }
        Command::Run {
            elf,
            spike,
            isa,
            timeout,
            spike_args,
            trace_output,
            evidence,
        } => {
            let mut trace = run_spike(
                &elf,
                &SpikeRunOptions {
                    spike,
                    isa,
                    timeout: Duration::from_secs(timeout),
                    extra_args: spike_args,
                },
            )
            .context("Spike execution failed")?;
            enrich_trace(&mut trace, &elf).context("failed to enrich Spike trace from ELF")?;
            if let Some(path) = trace_output {
                write_output(Some(path), &serde_json::to_string_pretty(&trace)?)?;
            }
            explain_trace(trace, evidence)
        }
        Command::Import {
            backend,
            log,
            isa,
            elf,
            output,
        } => {
            let contents = fs::read_to_string(&log)
                .with_context(|| format!("failed to read backend log {}", log.display()))?;
            let input = elf.as_ref().unwrap_or(&log);
            let mut trace = match backend {
                Backend::Spike => {
                    parse_spike_log(&contents, &isa, input).context("failed to parse Spike log")?
                }
            };
            if let Some(elf) = elf {
                enrich_trace(&mut trace, elf).context("failed to enrich trace from ELF")?;
            }
            write_output(output, &serde_json::to_string_pretty(&trace)?)
        }
        Command::Inspect { elf, format } => {
            let info = inspect_elf(elf).context("ELF inspection failed")?;
            match format {
                InspectFormat::Human => write_output(None, &render_elf(&info)),
                InspectFormat::Json => write_output(None, &serde_json::to_string_pretty(&info)?),
            }
        }
        Command::Doctor { spike, format } => doctor(spike, format),
    }
}

fn read_trace(path: &PathBuf) -> Result<TraceDocument> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read trace {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse trace {}", path.display()))
}

fn explain_trace(trace: TraceDocument, args: EvidenceArgs) -> Result<()> {
    let evidence = analyze_with_options(
        trace,
        AnalyzeOptions {
            profile: args.profile,
            limit: args.limit,
            around_pc: args.around_pc,
            around_trap: args.around_trap,
            before: args.before,
            after: args.after,
        },
    )
    .context("failed to analyze trace")?;
    let rendered = match args.format {
        EvidenceFormat::Human => render_human(&evidence),
        EvidenceFormat::Json => serde_json::to_string_pretty(&evidence)?,
        EvidenceFormat::Jsonl => render_jsonl(&evidence)?,
        EvidenceFormat::Sarif => serde_json::to_string_pretty(&render_sarif(&evidence))?,
    };
    write_output(args.output, &rendered)?;
    if args.fail_on_diagnostic
        && evidence
            .events
            .iter()
            .any(|event| event.diagnostic.is_some())
    {
        bail!("RISC-V execution produced one or more diagnostics")
    }
    Ok(())
}

fn doctor(spike: PathBuf, format: InspectFormat) -> Result<()> {
    let version = spike_version(&spike);
    let report = json!({
        "schema": "echorv.doctor.v1",
        "echorvVersion": env!("CARGO_PKG_VERSION"),
        "spike": {
            "path": spike,
            "available": version.is_some(),
            "version": version,
        }
    });
    match format {
        InspectFormat::Human => {
            let available = report["spike"]["available"].as_bool().unwrap_or(false);
            let version = report["spike"]["version"].as_str().unwrap_or("not found");
            write_output(
                None,
                &format!(
                    "EchoRV {}\nSpike: {} ({version})",
                    env!("CARGO_PKG_VERSION"),
                    if available {
                        "available"
                    } else {
                        "unavailable"
                    }
                ),
            )?;
            if !available {
                bail!("Spike is required by `echorv run`; use `echorv import spike` without it")
            }
            Ok(())
        }
        InspectFormat::Json => {
            write_output(None, &serde_json::to_string_pretty(&report)?)?;
            if report["spike"]["available"].as_bool() == Some(false) {
                bail!("Spike is unavailable")
            }
            Ok(())
        }
    }
}

fn render_human(evidence: &EvidenceDocument) -> String {
    let mut lines = vec![format!(
        "EchoRV evidence | {} | RV{} | profile={} | {}/{} events{}",
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
        let location = match (&event.symbol, &event.source) {
            (_, Some(source)) => format!(
                " @ {}:{}{}",
                source.file,
                source
                    .line
                    .map_or_else(|| "?".to_owned(), |line| line.to_string()),
                event
                    .symbol
                    .as_ref()
                    .map_or_else(String::new, |symbol| format!(" ({symbol})"))
            ),
            (Some(symbol), None) => format!(" @ {symbol}"),
            _ => String::new(),
        };
        lines.push(format!(
            "{} [{:?}/{:?}] {}{}{}",
            event.id, event.kind, event.confidence, event.explanation, location, cause
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

fn render_elf(info: &ElfInfo) -> String {
    let mut lines = vec![
        format!("ELF: {}", info.path.display()),
        format!("Architecture: {} (RV{})", info.architecture, info.xlen),
        format!("Entry point: {}", info.entry_point),
        format!(
            "Endianness: {}",
            if info.little_endian { "little" } else { "big" }
        ),
        format!(
            "DWARF: {}",
            if info.has_dwarf { "present" } else { "absent" }
        ),
        format!("Loadable segments: {}", info.loadable_segments),
        format!("Symbols: {}", info.symbols.len()),
    ];
    for symbol in info.symbols.iter().take(20) {
        lines.push(format!(
            "  {} {} +{} ({})",
            symbol.address, symbol.name, symbol.size, symbol.kind
        ));
    }
    if info.symbols.len() > 20 {
        lines.push(format!("  ... {} more", info.symbols.len() - 20));
    }
    lines.join("\n")
}

fn write_output(path: Option<PathBuf>, rendered: &str) -> Result<()> {
    match path {
        Some(path) => fs::write(&path, format!("{rendered}\n"))
            .with_context(|| format!("failed to write {}", path.display())),
        None => {
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{rendered}").context("failed to write output")
        }
    }
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

fn parse_positive_u64(value: &str) -> std::result::Result<u64, String> {
    let number = value
        .parse::<u64>()
        .map_err(|_| "value must be a positive integer".to_owned())?;
    if number == 0 {
        return Err("value must be greater than zero".to_owned());
    }
    Ok(number)
}
