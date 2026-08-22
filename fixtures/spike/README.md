# Spike log compatibility fixtures

These minimized logs preserve the public text emitted by Spike with `-l --log-commits`. They cover parser behavior for committed instructions, register and memory writes, trap names, EPC, TVAL, and handler privilege transitions.

They are parser fixtures, not benchmark results. The CI `spike-e2e` job builds and executes the assembly program under `fixtures/programs/` against a pinned Spike revision to verify the complete ELF-to-evidence path.
