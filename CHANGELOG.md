# Changelog

All notable changes to EchoRV are documented in this file.

## [0.1.0] - 2026-08-22

### Added

- Direct RISC-V ELF execution through an external Spike subprocess.
- Spike commit-log import with instruction, register, memory, trap, EPC, TVAL, and privilege normalization.
- Execution timeout, backend command/version provenance, and non-zero-exit warnings.
- RISC-V ELF inspection with architecture, XLEN, entry point, segment, symbol, and DWARF metadata.
- Symbol and source file/line enrichment for trace and evidence events.
- Auto, CSR, memory, and privilege profiles plus PC/trap-centered context selection.
- Observed, derived, and inferred confidence on every evidence event.
- Diagnoses for illegal instructions, breakpoints, ECALL, misalignment, access faults, and page faults.
- `run`, `import`, `inspect`, and `doctor` commands.
- Eight Spike log parser fixtures, seven real ELF/Spike CI cases, and an Agent benchmark contract.

### Changed

- Raised the minimum supported Rust version from 1.85 to 1.88 for current DWARF tooling.
- Increased the default evidence limit to 200 and made `auto` the default profile.

[0.1.0]: https://github.com/smallyunet/echorv/releases/tag/v0.1.0

## [0.0.1] - 2026-08-22

### Added

- Initial Rust CLI and library structure.
- Backend-neutral `echorv.trace.v1` input contract.
- Bounded `echorv.evidence.v1` causal evidence.
- Trap and full selection profiles.
- Human, JSON, and JSONL renderers.
- Illegal CSR trap fixture and analyzer tests.
- CI and tagged-release automation for Linux x86-64 and macOS arm64.

[0.0.1]: https://github.com/smallyunet/echorv/releases/tag/v0.0.1
