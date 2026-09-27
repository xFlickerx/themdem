# Devirtualization framework — design & scope

This document describes `themdem.devirt`, a **VM-analysis framework** aimed at
virtualization-obfuscated code (Themida / WinLicense / Code Virtualizer and
similar). It is deliberately honest about what is *proven here* versus what
requires a real protected sample to complete.

## Why this is a scaffold, not a finished Themida devirtualizer

Fully devirtualizing commercial Themida (the Fish/Tiger/Dolphin VMs) is a
research-grade problem. The current state of the art, **Pushan** (Sudhir et
al., 2026), uses `angr`, VPC-sensitive constraint-free symbolic emulation, and
an SMT solver, and still needs up to ~80 GB RAM and hours per function. This
repository has:

* **no Themida sample** to validate against, and
* **no `angr`/`miasm`** available in the build environment.

So instead of shipping unproven, Themida-specific code, `themdem.devirt`
implements the *generic engine* every VM devirtualizer needs and proves it
against a **real (synthetic) x86 stack VM** (`tests/_vm_fixture.py`). To target
real Themida you plug in two things: the VM **entry/VPC/bytecode locations**
(from static or dynamic triage) and a **`VMArchitecture` spec** describing the
handlers once reverse-engineered.

## Pipeline

```
 detect ─▶ emulate ─▶ find VPC ─▶ segment ─▶ VPC-sensitive CFG ─▶ classify ─▶ disasm+lift
(static)  (Unicorn)  (heuristic)  (per iter)  ((addr,vpc) nodes)  (fingerprint) (needs spec)
```

| Stage | Module | Status | Notes |
|-------|--------|--------|-------|
| Protection & bytecode detection | `detect.py` | **proven (mechanics)** | Shannon entropy, Themida 2.x/3.x section+import+stub fingerprints, high-entropy region ranking. Version heuristics follow public `unlicense`/DIE knowledge; need real samples to tune thresholds. |
| VPC-sensitive CFG | `cfg.py` | **proven** | Nodes keyed by `(address, vpc)`; each key emulated once; back-edges merge. This is the core Pushan/Kinder idea. |
| VPC identification | `vpc.py` | **proven (mechanics)** | Ranks locations that point into the bytecode region and evolve monotonically (VMDoctor-style). Verified: picks `esi` over noise on the fixture. |
| Emulation engine | `emulator.py` | **proven** | Unicorn x86-32, register snapshots per step, sentinel-return stop, dispatcher detection via backward-edge frequency, virtual-instruction segmentation. Verified: recovers the exact opcode sequence of the fixture VM. |
| Handler classification | `vm.py` | **proven** | Groups handler bodies by relocation-independent fingerprint → recovers opcode count/stream with no spec. |
| Disassembly + lifting | `vm.py`, `lifter.py` | **proven (with spec)** | Given a `VMArchitecture`, disassembles bytecode and folds the operand stack into pseudocode. Verified: lifts the fixture to `return (((0xa + 0x14) * 0x3) - 0x5);`. |

## What you must supply for a real target

1. **Triage** — unpack first (out of scope; use a dumper), then locate the VM
   interpreter entry, the VPC location, and the bytecode region. `detect` helps
   with sections and entropy; the VPC tracker helps confirm the VPC from a
   trace.
2. **A `VMArchitecture` spec** — one `OpcodeSpec` per handler
   (mnemonic, operand width, semantic kind). Build it by studying the handler
   bodies that `classify_handlers` groups for you. This is the bulk of the
   manual work and is inherently per-variant.
3. **Register/memory init** — the interpreter usually expects the VPC and the
   VM stack pointer in specific registers; pass them via `reg_init`.

## Known limitations & next steps

* **Single-path (concrete) emulation.** The engine follows one execution path,
  like a trace, so conditional VM branches not taken aren't explored. The CFG
  structure already supports multiple edges/blocks; the missing piece is
  Pushan's *symbolization* + *branch forcing* (replace merged/constant values
  with fresh symbols and re-explore). Adding a small symbolic value domain (or
  wiring in `z3`, which is installed) is the natural extension.
* **No MBA/opaque-predicate simplification** of jump-target expressions. Pushan
  uses an SMT solver as an expression simplifier here; `z3` is available to add
  this.
* **Handler semantics are spec-driven, not auto-synthesised.** Auto-recovering
  a handler's semantics (e.g. via I/O sampling or program synthesis) would
  remove the manual spec step and is a worthwhile follow-up.
* **x86-32 only**, matching the mutation passes and the validator.

## References

* Sudhir et al., *Pushan: Trace-Free Deobfuscation of Virtualization-Obfuscated
  Binaries*, arXiv:2603.18355.
* Kinder, *Towards Static Analysis of Virtualization-Obfuscated Binaries* (VPC
  sensitivity).
* Rolles, *Unpacking Virtualization Obfuscators*, WOOT'09.
