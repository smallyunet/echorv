use crate::model::{
    Privilege, Provenance, StateKind, StateWrite, Target, TraceDocument, TraceEvent, Trap,
};
use crate::TRACE_SCHEMA;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;
use thiserror::Error;
use wait_timeout::ChildExt;

#[derive(Debug, Clone)]
pub struct SpikeRunOptions {
    pub spike: PathBuf,
    pub isa: String,
    pub timeout: Duration,
    pub extra_args: Vec<String>,
}

impl Default for SpikeRunOptions {
    fn default() -> Self {
        Self {
            spike: PathBuf::from("spike"),
            isa: "rv64imac_zicsr".to_owned(),
            timeout: Duration::from_secs(10),
            extra_args: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum SpikeError {
    #[error("failed to create temporary execution files: {0}")]
    TemporaryFile(#[from] std::io::Error),
    #[error("failed to start Spike `{path}`: {source}")]
    Spawn {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Spike exceeded the {seconds}s execution timeout")]
    Timeout { seconds: u64 },
    #[error("Spike produced no parseable execution events; stderr: {stderr}")]
    EmptyTrace { stderr: String },
    #[error("invalid Spike log parser expression: {0}")]
    Parser(#[from] regex::Error),
}

#[derive(Debug)]
struct PendingTrap {
    name: String,
    epc: String,
    tval: Option<String>,
    from_privilege: Privilege,
}

pub fn run_spike(
    elf: impl AsRef<Path>,
    options: &SpikeRunOptions,
) -> Result<TraceDocument, SpikeError> {
    let log = NamedTempFile::new()?;
    let stdout = NamedTempFile::new()?;
    let stderr = NamedTempFile::new()?;
    let mut command_args = vec![
        format!("--isa={}", options.isa),
        "-l".to_owned(),
        "--log-commits".to_owned(),
        format!("--log={}", log.path().display()),
    ];
    command_args.extend(options.extra_args.clone());
    command_args.push(elf.as_ref().display().to_string());

    let mut child = Command::new(&options.spike)
        .args(&command_args)
        .stdout(Stdio::from(stdout.reopen()?))
        .stderr(Stdio::from(stderr.reopen()?))
        .spawn()
        .map_err(|source| SpikeError::Spawn {
            path: options.spike.clone(),
            source,
        })?;

    let status = match child.wait_timeout(options.timeout)? {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SpikeError::Timeout {
                seconds: options.timeout.as_secs(),
            });
        }
    };

    let log_contents = fs::read_to_string(log.path())?;
    let stderr_contents = fs::read_to_string(stderr.path())?;
    let mut trace = parse_spike_log(&log_contents, &options.isa, elf.as_ref())?;
    trace.provenance.backend_version = spike_version(&options.spike);
    trace.provenance.command = std::iter::once(options.spike.display().to_string())
        .chain(command_args)
        .collect();
    if !status.success() {
        trace.provenance.notes.push(format!(
            "Spike exited with {status}; evidence was retained because a trace was produced"
        ));
    }
    if !stderr_contents.trim().is_empty() {
        trace
            .provenance
            .notes
            .push("Spike wrote diagnostic output to stderr".to_owned());
    }
    if trace.events.is_empty() {
        return Err(SpikeError::EmptyTrace {
            stderr: stderr_contents.trim().to_owned(),
        });
    }
    Ok(trace)
}

pub fn parse_spike_log(
    contents: &str,
    isa: &str,
    input: impl AsRef<Path>,
) -> Result<TraceDocument, SpikeError> {
    let instruction = Regex::new(
        r"^core\s+(?P<hart>\d+):\s+(?:(?P<priv>[013])\s+)?(?P<pc>0x[0-9a-fA-F]+)\s+\((?P<bits>0x[0-9a-fA-F]+)\)(?:\s+(?P<tail>.*))?$",
    )?;
    let exception =
        Regex::new(r"^core\s+\d+:\s+exception\s+(?P<name>[^,]+),\s+epc\s+(?P<epc>0x[0-9a-fA-F]+)")?;
    let tval = Regex::new(r"^core\s+\d+:\s+tval\s+(?P<tval>0x[0-9a-fA-F]+)")?;
    let write = Regex::new(
        r"(?P<name>(?:x|f|v)\s*\d+|csr\s+[A-Za-z0-9_]+|mem\s+0x[0-9a-fA-F]+)\s+(?P<value>0x[0-9a-fA-F]+)",
    )?;

    let mut events: Vec<TraceEvent> = Vec::new();
    let mut pending: Option<PendingTrap> = None;
    let mut current_privilege = Privilege::M;

    for line in contents.lines().map(str::trim) {
        if let Some(captures) = exception.captures(line) {
            pending = Some(PendingTrap {
                name: normalize_name(&captures["name"]),
                epc: captures["epc"].to_ascii_lowercase(),
                tval: None,
                from_privilege: current_privilege,
            });
            continue;
        }
        if let Some(captures) = tval.captures(line) {
            if let Some(pending) = pending.as_mut() {
                pending.tval = Some(captures["tval"].to_ascii_lowercase());
            }
            continue;
        }
        let Some(captures) = instruction.captures(line) else {
            continue;
        };
        let privilege = captures
            .name("priv")
            .map(|value| parse_privilege(value.as_str()))
            .unwrap_or(current_privilege);
        current_privilege = privilege;
        let pc = captures["pc"].to_ascii_lowercase();
        let bits = captures["bits"].to_ascii_lowercase();
        let tail = captures
            .name("tail")
            .map(|value| value.as_str().trim())
            .unwrap_or_default();

        if let Some(trap) = pending.take() {
            attach_trap(&mut events, trap, &pc, privilege);
        }

        let writes = parse_writes(tail, &write);
        let has_disassembly = !tail.is_empty() && writes.is_empty();
        if let Some(previous) = events.last_mut().filter(|event| {
            event.pc == pc && event.instruction_bytes.as_deref() == Some(bits.as_str())
        }) {
            previous.privilege = privilege;
            previous.writes.extend(writes);
            if has_disassembly {
                previous.instruction = tail.to_owned();
            }
            continue;
        }

        events.push(TraceEvent {
            sequence: events.len() as u64,
            hart: captures["hart"].parse().ok(),
            pc,
            instruction: if has_disassembly {
                tail.to_owned()
            } else {
                "unknown".to_owned()
            },
            instruction_bytes: Some(bits),
            privilege,
            symbol: None,
            source: None,
            writes,
            trap: None,
        });
    }

    if let Some(trap) = pending {
        attach_trap(&mut events, trap, "unknown", current_privilege);
    }
    for (sequence, event) in events.iter_mut().enumerate() {
        event.sequence = sequence as u64;
    }

    let xlen = if isa.to_ascii_lowercase().starts_with("rv32") {
        32
    } else {
        64
    };
    Ok(TraceDocument {
        schema: TRACE_SCHEMA.to_owned(),
        target: Target {
            architecture: "risc-v".to_owned(),
            xlen,
            isa: isa.to_ascii_lowercase(),
            platform: Some("spike".to_owned()),
        },
        provenance: Provenance {
            backend: Some("spike".to_owned()),
            backend_version: None,
            input: Some(input.as_ref().display().to_string()),
            command: Vec::new(),
            notes: Vec::new(),
        },
        events,
    })
}

pub fn spike_version(path: impl AsRef<Path>) -> Option<String> {
    let output = Command::new(path.as_ref()).arg("--version").output().ok()?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr)
    } else {
        String::from_utf8_lossy(&output.stdout)
    };
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

fn attach_trap(
    events: &mut Vec<TraceEvent>,
    pending: PendingTrap,
    target_pc: &str,
    to_privilege: Privilege,
) {
    let cause = trap_cause(&pending.name);
    let trap = Trap {
        cause,
        name: pending.name.clone(),
        tval: pending.tval.clone(),
        target_pc: target_pc.to_owned(),
        to_privilege,
        delegated: Some(to_privilege != Privilege::M),
    };
    if let Some(event) = events
        .iter_mut()
        .rev()
        .find(|event| event.pc == pending.epc)
    {
        event.trap = Some(trap);
        return;
    }
    events.push(TraceEvent {
        sequence: events.len() as u64,
        hart: Some(0),
        pc: pending.epc,
        instruction: "uncommitted faulting instruction".to_owned(),
        instruction_bytes: pending.tval,
        privilege: pending.from_privilege,
        symbol: None,
        source: None,
        writes: Vec::new(),
        trap: Some(trap),
    });
}

fn parse_writes(tail: &str, pattern: &Regex) -> Vec<StateWrite> {
    pattern
        .captures_iter(tail)
        .map(|capture| {
            let raw_name = capture["name"].replace(' ', "");
            let (kind, name) = if let Some(name) = raw_name.strip_prefix("csr") {
                (StateKind::Csr, name.to_owned())
            } else if raw_name.starts_with("mem") {
                (StateKind::Memory, raw_name)
            } else {
                (StateKind::Register, raw_name)
            };
            StateWrite {
                kind,
                name,
                before: None,
                after: capture["value"].to_ascii_lowercase(),
            }
        })
        .collect()
}

fn parse_privilege(value: &str) -> Privilege {
    match value {
        "0" => Privilege::U,
        "1" => Privilege::S,
        _ => Privilege::M,
    }
}

fn normalize_name(value: &str) -> String {
    value
        .trim()
        .strip_prefix("trap_")
        .unwrap_or(value.trim())
        .replace('_', "-")
        .to_ascii_lowercase()
}

fn trap_cause(name: &str) -> u64 {
    match name {
        "instruction-address-misaligned" => 0,
        "instruction-access-fault" => 1,
        "illegal-instruction" => 2,
        "breakpoint" => 3,
        "load-address-misaligned" => 4,
        "load-access-fault" => 5,
        "store-address-misaligned" => 6,
        "store-access-fault" => 7,
        "user-ecall" | "environment-call-from-u-mode" => 8,
        "supervisor-ecall" | "environment-call-from-s-mode" => 9,
        "machine-ecall" | "environment-call-from-m-mode" => 11,
        "instruction-page-fault" => 12,
        "load-page-fault" => 13,
        "store-page-fault" => 15,
        _ => u64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commit_writes_and_traps() {
        let log = r#"
core   0: 0 0x00000000802001ac (0x18051073) csrw satp, a0
core   0: exception illegal_instruction, epc 0x00000000802001ac
core   0: tval 0x0000000018051073
core   0: 3 0x0000000080000000 (0x34202573) x10 0x0000000000000002
"#;
        let trace = parse_spike_log(log, "rv64imac_zicsr", "firmware.elf").unwrap();
        assert_eq!(trace.events.len(), 2);
        assert_eq!(trace.events[0].privilege, Privilege::U);
        let trap = trace.events[0].trap.as_ref().unwrap();
        assert_eq!(trap.cause, 2);
        assert_eq!(trap.to_privilege, Privilege::M);
        assert_eq!(trace.events[1].writes[0].name, "x10");
    }

    #[test]
    fn synthesizes_an_uncommitted_faulting_instruction() {
        let log = r#"
core   0: exception load_access_fault, epc 0x0000000080200100
core   0: tval 0xffffffffffffffff
core   0: 3 0x0000000080000000 (0x00000013) nop
"#;
        let trace = parse_spike_log(log, "rv64i", "firmware.elf").unwrap();
        assert_eq!(trace.events[0].pc, "0x0000000080200100");
        assert_eq!(trace.events[0].trap.as_ref().unwrap().cause, 5);
    }

    #[cfg(unix)]
    #[test]
    fn kills_a_backend_that_exceeds_the_timeout() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let backend = directory.path().join("slow-spike");
        fs::write(&backend, "#!/bin/sh\nsleep 2\n").unwrap();
        let mut permissions = fs::metadata(&backend).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&backend, permissions).unwrap();

        let error = run_spike(
            "unused.elf",
            &SpikeRunOptions {
                spike: backend,
                timeout: Duration::from_millis(10),
                ..SpikeRunOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(error, SpikeError::Timeout { .. }));
    }
}
