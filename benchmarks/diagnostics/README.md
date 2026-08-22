# Agent diagnostic benchmark contract

This directory defines the acceptance boundary for future claims that EchoRV evidence helps an Agent diagnose RISC-V failures.

Each case in `cases.json` freezes a backend log, expected trap cause, expected diagnostic family, and confidence boundary. A measured run must compare two inputs for the same task:

1. the bounded raw Spike log;
2. EchoRV `echorv.evidence.v1` generated from that log with the same event budget.

Report at least:

- exact trap-cause accuracy;
- root-cause-family accuracy;
- faulting-PC accuracy;
- fresh input tokens;
- time to first correct diagnosis;
- missing or unsupported evidence.

Run every case at least three times with a frozen model and prompt. Do not publish an improvement claim unless the evidence condition has no worse accuracy and uses at least 25% fewer fresh input tokens at the task-clustered upper 95% confidence bound.

No Agent benchmark result is included in v0.1.0. The current corpus validates implementation behavior only.
