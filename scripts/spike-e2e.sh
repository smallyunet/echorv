#!/usr/bin/env bash
set -euo pipefail

spike_bin="${1:-spike}"
work_dir="${TMPDIR:-/tmp}/echorv-spike-e2e"
mkdir -p "$work_dir"

cases=(
  "illegal-instruction:2:illegal-instruction"
  "breakpoint:3:breakpoint"
  "load-address-misaligned:4:load-address-misaligned"
  "load-access-fault:5:load-access-fault"
  "store-address-misaligned:6:store-address-misaligned"
  "store-access-fault:7:store-access-fault"
  "machine-ecall:11:environment-call"
)

for item in "${cases[@]}"; do
  IFS=: read -r name cause diagnostic <<< "$item"
  elf="$work_dir/${name}.elf"
  trace="$work_dir/${name}.trace.json"
  evidence="$work_dir/${name}.evidence.json"

  riscv64-unknown-elf-gcc \
    -march=rv64imac_zicsr \
    -mabi=lp64 \
    -nostdlib \
    -nostartfiles \
    -g \
    -DCASE="$cause" \
    -DEXPECTED_CAUSE="$cause" \
    -T fixtures/programs/linker.ld \
    fixtures/programs/trap_cases.S \
    -o "$elf"

  cargo run --locked -- inspect "$elf" --format json > "$work_dir/${name}.inspect.json"
  cargo run --locked -- run "$elf" \
    --spike "$spike_bin" \
    --isa rv64imac_zicsr \
    --timeout 15 \
    --profile auto \
    --format json \
    --trace-output "$trace" \
    --output "$evidence"

  jq -e '.architecture == "risc-v" and .xlen == 64 and .hasDwarf == true' "$work_dir/${name}.inspect.json"
  jq -e --argjson cause "$cause" '.schema == "echorv.trace.v1" and any(.events[]; .trap.cause == $cause)' "$trace"
  jq -e --arg diagnostic "$diagnostic" '.schema == "echorv.evidence.v1" and any(.events[]; .diagnostic == $diagnostic)' "$evidence"
  jq -e 'any(.events[]; .source.line != null)' "$evidence"
done
