# EchoRV documentation

EchoRV turns RISC-V execution traces into bounded, source-aware evidence without
pretending that inferred platform behavior was directly observed.

| Goal | Document |
|---|---|
| Understand the execution and evidence pipeline | [README architecture](../README.md#architecture) |
| Integrate normalized traces | [Trace schema](../schemas/echorv.trace.v1.schema.json) |
| Integrate bounded evidence | [Evidence schema](../schemas/echorv.evidence.v1.schema.json) |
| Upload diagnostics to code scanning | [SARIF workflow](../README.md#ci-diagnostics-with-sarif) |
| Evaluate diagnostic quality | [Benchmark contract](../benchmarks/diagnostics/README.md) |

## Recommended path

1. Run the [README quick start](../README.md#quick-start).
2. Explore the [committed evidence playground](https://smallyunet.github.io/echorv/).
3. Confirm whether a fact is observed, architecturally derived, or inferred.
4. Use the normalized trace when building another backend adapter.

## Trust boundary

Spike is the current execution adapter. EchoRV explains its trace plus ELF and
DWARF metadata; it does not claim the exact PMP/PMA decision or RTL timing when
the backend does not expose those facts.

