# EchoRV

**Bounded causal execution evidence for RISC-V firmware.**

EchoRV turns normalized RISC-V execution traces into compact explanations for people, coding agents, CI systems, and IDEs. It is an evidence layer, not another instruction-set simulator.

```text
U-mode executes csrw satp, a0
  -> illegal-instruction trap (mcause=2)
  -> mepc records 0x802001ac
  -> control transfers to M-mode at mtvec
```

## v0.0.1 scope

This first release establishes:

- `echorv.trace.v1`, a backend-neutral normalized trace format;
- `echorv.evidence.v1`, bounded causal evidence for downstream tools;
- trap and full evidence profiles;
- human, JSON, and streaming JSONL output;
- strict RISC-V target and trace-order validation;
- a working illegal-CSR trap fixture;
- adapter boundaries for future Sail and Spike integrations.

EchoRV v0.0.1 does **not** execute ELF files itself. A Sail or Spike adapter must first normalize backend events into `echorv.trace.v1`. Native backend adapters, ELF/DWARF enrichment, PMP, page-table, and SBI-specific analysis are roadmap work.

## Install

Download a release archive from GitHub, or build from source:

```bash
cargo install --path .
```

## Quick start

```bash
echorv explain fixtures/illegal-csr-trap.json
```

Machine-readable evidence:

```bash
echorv explain fixtures/illegal-csr-trap.json \
  --profile trap \
  --limit 100 \
  --format json
```

Streaming output for an agent or CI pipeline:

```bash
echorv explain fixtures/illegal-csr-trap.json --format jsonl
```

Use `--profile full` to include ordinary instruction and state-change evidence in addition to trap chains.

## Architecture

```text
Sail / Spike / QEMU / RTL
          |
       adapter
          |
  echorv.trace.v1
          |
   validation + analysis
          |
 echorv.evidence.v1
          |
 human / JSON / JSONL
```

Backend-specific parsing belongs in adapters. The analyzer only consumes normalized architectural events, keeping the evidence contract stable when a simulator changes.

## Schema

The input and output contracts are documented at [`schemas/echorv.trace.v1.schema.json`](schemas/echorv.trace.v1.schema.json) and [`schemas/echorv.evidence.v1.schema.json`](schemas/echorv.evidence.v1.schema.json). Evidence contains:

- stable event IDs;
- trace sequence and PC provenance;
- state before/after values when available;
- explicit `causedBy` links;
- total, emitted, and truncation metadata;
- warnings when evidence is incomplete or bounded.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo run -- explain fixtures/illegal-csr-trap.json --format json
```

## License

MIT
