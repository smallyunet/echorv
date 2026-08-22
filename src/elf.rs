use crate::model::{SourceLocation, TraceDocument};
use object::{Object, ObjectSymbol, SymbolKind};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ElfInspectError {
    #[error("failed to read ELF `{path}`: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse `{path}` as an object file: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("`{path}` targets {architecture}, not RISC-V")]
    NotRiscV { path: PathBuf, architecture: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfInfo {
    pub path: PathBuf,
    pub architecture: String,
    pub xlen: u16,
    pub entry_point: String,
    pub little_endian: bool,
    pub has_dwarf: bool,
    pub loadable_segments: usize,
    pub symbols: Vec<ElfSymbol>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfSymbol {
    pub name: String,
    pub address: String,
    pub size: u64,
    pub kind: String,
}

#[derive(Debug, Clone)]
struct SymbolRange {
    name: String,
    address: u64,
    size: u64,
}

pub fn inspect_elf(path: impl AsRef<Path>) -> Result<ElfInfo, ElfInspectError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    let file = object::File::parse(bytes.as_slice()).map_err(|error| ElfInspectError::Parse {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let (architecture, xlen) = riscv_architecture(path, file.architecture())?;
    let mut symbols: Vec<ElfSymbol> = file
        .symbols()
        .filter(|symbol| symbol.address() != 0)
        .filter_map(|symbol| {
            Some(ElfSymbol {
                name: symbol.name().ok()?.to_owned(),
                address: hex(symbol.address()),
                size: symbol.size(),
                kind: format!("{:?}", symbol.kind()).to_ascii_lowercase(),
            })
        })
        .collect();
    symbols.sort_by_key(|symbol| parse_hex(&symbol.address).unwrap_or_default());

    Ok(ElfInfo {
        path: path.to_owned(),
        architecture,
        xlen,
        entry_point: hex(file.entry()),
        little_endian: file.is_little_endian(),
        has_dwarf: file.section_by_name(".debug_info").is_some(),
        loadable_segments: file.segments().count(),
        symbols,
    })
}

pub fn enrich_trace(
    trace: &mut TraceDocument,
    elf_path: impl AsRef<Path>,
) -> Result<Vec<String>, ElfInspectError> {
    let elf_path = elf_path.as_ref();
    let bytes = read(elf_path)?;
    let file = object::File::parse(bytes.as_slice()).map_err(|error| ElfInspectError::Parse {
        path: elf_path.to_owned(),
        message: error.to_string(),
    })?;
    let (_, xlen) = riscv_architecture(elf_path, file.architecture())?;
    if trace.target.xlen != xlen {
        trace.provenance.notes.push(format!(
            "trace XLEN {} differs from ELF XLEN {xlen}",
            trace.target.xlen
        ));
    }
    let mut ranges: Vec<SymbolRange> = file
        .symbols()
        .filter(|symbol| symbol.address() != 0 && symbol.kind() == SymbolKind::Text)
        .filter_map(|symbol| {
            Some(SymbolRange {
                name: symbol.name().ok()?.to_owned(),
                address: symbol.address(),
                size: symbol.size(),
            })
        })
        .collect();
    ranges.sort_by_key(|symbol| symbol.address);

    let loader = addr2line::Loader::new(elf_path).ok();
    let mut warnings = Vec::new();
    if loader.is_none() && file.section_by_name(".debug_info").is_some() {
        warnings.push("DWARF sections were present but could not be loaded".to_owned());
    }

    for event in &mut trace.events {
        let Some(address) = parse_hex(&event.pc) else {
            warnings.push(format!(
                "could not parse PC `{}` for ELF enrichment",
                event.pc
            ));
            continue;
        };
        event.symbol = symbol_for(&ranges, address);
        if let Some(loader) = loader.as_ref() {
            match loader.find_location(address) {
                Ok(Some(location)) => {
                    if let Some(file) = location.file {
                        event.source = Some(SourceLocation {
                            file: file.to_owned(),
                            line: location.line,
                            column: location.column,
                        });
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    warnings.push(format!("DWARF lookup failed for {}: {error}", event.pc))
                }
            }
        }
    }
    trace.provenance.input = Some(elf_path.display().to_string());
    trace.provenance.notes.extend(warnings.iter().cloned());
    Ok(warnings)
}

fn read(path: &Path) -> Result<Vec<u8>, ElfInspectError> {
    fs::read(path).map_err(|source| ElfInspectError::Read {
        path: path.to_owned(),
        source,
    })
}

fn riscv_architecture(
    path: &Path,
    architecture: object::Architecture,
) -> Result<(String, u16), ElfInspectError> {
    match architecture {
        object::Architecture::Riscv32 => Ok(("risc-v".to_owned(), 32)),
        object::Architecture::Riscv64 => Ok(("risc-v".to_owned(), 64)),
        other => Err(ElfInspectError::NotRiscV {
            path: path.to_owned(),
            architecture: format!("{other:?}"),
        }),
    }
}

fn symbol_for(symbols: &[SymbolRange], address: u64) -> Option<String> {
    symbols
        .iter()
        .rev()
        .find(|symbol| {
            symbol.address <= address
                && (symbol.size == 0 || address < symbol.address.saturating_add(symbol.size))
        })
        .map(|symbol| symbol.name.clone())
}

pub(crate) fn parse_hex(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}
