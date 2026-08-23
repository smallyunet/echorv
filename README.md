# EchoRV

[![CI](https://github.com/smallyunet/echorv/actions/workflows/ci.yml/badge.svg)](https://github.com/smallyunet/echorv/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/smallyunet/echorv?style=flat&color=blue)](https://github.com/smallyunet/echorv/releases)
[![Rust](https://img.shields.io/badge/rust-1.88+-CE422B?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat)](LICENSE)
[![Playground](https://img.shields.io/badge/playground-GitHub_Pages-f59e0b)](https://smallyunet.github.io/echorv/)

**Bounded causal execution evidence for RISC-V firmware.**

EchoRV runs or imports RISC-V execution traces and turns them into compact, source-aware explanations for people, coding agents, CI systems, and IDEs. It is an evidence layer, not another instruction-set simulator.

[Static playground](https://smallyunet.github.io/echorv/) ·
[latest release](https://github.com/smallyunet/echorv/releases/latest) ·
[documentation](docs/README.md) ·
[evidence schema](schemas/echorv.evidence.v1.schema.json)

> The playground is a static GitHub Pages site backed by committed evidence
> snapshots. Spike execution and log import remain local CLI workflows.

```text
U-mode executes csrw satp, a0 at firmware.S:31
  -> illegal-instruction trap (mcause=2)
  -> mepc records the faulting PC
  -> mtval records the instruction encoding
  -> control transfers to M-mode at mtvec
```

## Quick start

```bash
cargo install --git https://github.com/smallyunet/echorv --tag v0.2.0
echorv --version

# With Spike and a RISC-V ELF available:
echorv doctor
echorv run firmware.elf --isa rv64imac_zicsr --profile auto --format json
```

`echorv explain`, `import`, and `inspect` are self-contained. `echorv run`
expects a recent `spike` executable in `PATH` or at the path supplied through
`--spike`.

## CI diagnostics with SARIF

SARIF 2.1.0 output includes stable diagnostic rule IDs, source-backed physical
locations, and symbol-backed logical locations. `--fail-on-diagnostic` writes
the evidence before returning a non-zero status for CI gating.

```bash
echorv run firmware.elf --format sarif --output echorv.sarif \
  --fail-on-diagnostic
```

## Core capabilities

- direct `ELF -> Spike -> evidence` execution;
- import of existing Spike `-l --log-commits` logs;
- Spike discovery, version provenance, timeouts, and non-zero-exit warnings;
- RISC-V ELF inspection, symbol lookup, and DWARF file/line enrichment;
- `observed`, `derived`, and `inferred` confidence boundaries;
- diagnoses for illegal instructions, breakpoints, ECALL, alignment faults, access faults, and page faults;
- automatic, trap, CSR, memory, privilege, and full evidence profiles;
- PC/trap-centered context selection with bounded output;
- eight frozen Spike log compatibility cases and seven real ELF/Spike CI cases.

## Run a real ELF

```bash
echorv doctor

echorv run firmware.elf \
  --isa rv64imac_zicsr \
  --profile auto \
  --format json
```

EchoRV currently has one execution backend, so `run` does not require an explicit `--backend` flag:

```bash
echorv run firmware.elf --spike /opt/riscv/bin/spike
```

Save the normalized trace as well as evidence:

```bash
echorv run firmware.elf \
  --trace-output firmware.trace.json \
  --output firmware.evidence.json \
  --format json
```

Spike arguments that must precede the ELF can be repeated:

```bash
echorv run firmware.elf --spike-arg=-m0x80000000:0x10000000
```

## Import an existing Spike log

Capture a log:

```bash
spike --isa=rv64imac_zicsr -l --log-commits --log=spike.log firmware.elf
```

Normalize and enrich it:

```bash
echorv import spike spike.log \
  --isa rv64imac_zicsr \
  --elf firmware.elf \
  --output firmware.trace.json

echorv explain firmware.trace.json --profile auto
```

## Inspect an ELF

```bash
echorv inspect firmware.elf
echorv inspect firmware.elf --format json
```

Inspection rejects non-RISC-V objects and reports XLEN, entry point, endianness, DWARF availability, loadable segments, and symbols.

## Select evidence

```bash
echorv explain trace.json --profile auto
echorv explain trace.json --profile memory
echorv explain trace.json --around-pc 0x802001ac --before 12 --after 6
echorv explain trace.json --around-trap 13 --max-events 100
```

Profiles:

- `auto`: traps when present; otherwise state-changing instructions;
- `trap`: trap chains and trap CSRs;
- `csr`: CSR changes and related traps;
- `memory`: memory changes and memory-related faults;
- `privilege`: ECALL/return instructions and privilege transitions;
- `full`: all normalized execution events.

Formats are `human`, `json`, streaming `jsonl`, and SARIF 2.1.0.

## Evidence boundaries

Every evidence event declares confidence:

- `observed`: present in backend output;
- `derived`: architecturally determined from observed fields;
- `inferred`: a likely explanation that the backend output cannot prove.

For example, a generic Spike access-fault trace proves the cause, EPC, TVAL, and handler transition. It does not identify the exact PMP entry or PMA rule that rejected the access, so EchoRV lists PMP/PMA/unmapped memory as inferred candidates instead of claiming a specific rule.

## Architecture

```text
RISC-V ELF ----------------------+
   |                             |
   +-> Spike subprocess          +-> ELF symbols + DWARF
           |                              |
           +-> Spike adapter <------------+
                     |
             echorv.trace.v1
                     |
          selection + causal analysis
                     |
           echorv.evidence.v1
                     |
              human / JSON / JSONL
```

Backend-specific parsing stays outside the analyzer. The stable normalized trace contract also permits future Sail, QEMU, RVFI, and RTL adapters.

## Schemas

- [`echorv.trace.v1`](schemas/echorv.trace.v1.schema.json)
- [`echorv.evidence.v1`](schemas/echorv.evidence.v1.schema.json)

Evidence includes stable IDs, source provenance, state changes, explicit `causedBy` links, diagnostics, confidence, warnings, and total/matched/emitted/truncated metadata.

## Validation corpus

`fixtures/spike/` contains minimized compatibility logs for eight trap paths. `fixtures/programs/trap_cases.S` is compiled into seven real RV64 ELFs in CI and executed by a pinned Spike commit before EchoRV validates the emitted trace, diagnosis, and DWARF location.

The corpus is a conformance gate, not a measured claim that EchoRV improves Agent accuracy. The benchmark contract in [`benchmarks/diagnostics/README.md`](benchmarks/diagnostics/README.md) keeps those claims separate.

## Documentation

| Goal | Start here |
|---|---|
| Find the right guide | [Documentation index](docs/README.md) |
| Integrate normalized traces | [Trace schema](schemas/echorv.trace.v1.schema.json) |
| Integrate bounded evidence | [Evidence schema](schemas/echorv.evidence.v1.schema.json) |
| Upload diagnostics to code scanning | [SARIF workflow](#ci-diagnostics-with-sarif) |
| Evaluate diagnostic quality | [Benchmark contract](benchmarks/diagnostics/README.md) |

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo run -- explain fixtures/illegal-csr-trap.json --format json
```

With `riscv64-unknown-elf-gcc`, `jq`, and Spike available:

```bash
bash scripts/spike-e2e.sh /path/to/spike
```

## Current limits

- Spike is the only direct execution adapter.
- Generic commit logs do not expose the exact PMP/PMA decision path.
- Hypervisor/VS/VU privilege is not represented yet.
- Vector lane semantics, multi-hart causality, weak memory, full Linux boot analysis, and RTL timing are outside v0.2.0.
- Source information depends on DWARF being present and readable.

## Echo family

| Project | Execution domain | Static playground |
|---|---|---|
| [EchoEVM](https://github.com/smallyunet/echoevm) | Solidity and EVM bytecode | [Open](https://smallyunet.github.io/echoevm/) |
| [EchoSVM](https://github.com/smallyunet/echosvm) | Solana transactions and sBPF | [Open](https://smallyunet.github.io/echosvm/) |
| [EchoRV](https://github.com/smallyunet/echorv) | RISC-V firmware and traces | [Open](https://smallyunet.github.io/echorv/) |
| [EchoScript](https://github.com/smallyunet/echoscript) | Bitcoin Tapscript inputs | [Open](https://smallyunet.github.io/echoscript/) |

Each project executes locally, emits a versioned evidence schema, and publishes
frozen reproducible cases through the same static playground contract.

## License

MIT
