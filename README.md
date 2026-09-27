# themdem

**themdem** is an educational **Themida / WinLicense / Code Virtualizer mutation
deobfuscator** for 32-bit x86 code.

Commercial protectors like Themida apply two broad families of code protection:

* **Mutation** — the original instructions are kept, but padded and rewritten
  with large amounts of semantically-neutral *junk* and with obfuscated
  equivalents (e.g. `push eax` becomes `sub esp,4; mov [esp],eax`, a register
  negate becomes a `push 0; sub [esp],reg; pop reg` sandwich, etc.).
* **Virtualization** — the original instructions are translated into a custom
  bytecode executed by an embedded interpreter (a "virtual CPU").

`themdem` targets the **mutation** layer. It disassembles a mutated code region,
recognises the protector's junk/rewrite patterns, and reassembles compact,
readable, **semantically-equivalent** x86. Every rewrite is verified by
emulating both the original and the rewritten bytes with **Unicorn** and
comparing the resulting CPU state, so a pass can never silently change program
behaviour.

It also ships a **VM-analysis / devirtualization framework** (`themdem.devirt`)
for the *virtualization* layer — a Unicorn-based, VPC-sensitive engine that
recovers a virtualized function's structure and, given a VM spec, lifts its
bytecode back to readable pseudocode. See
[Devirtualization](#devirtualization-themdemdevirt).

> ⚠️ **Scope & intended use.** This is a reverse-engineering research/education
> tool. Use it on software you are authorised to analyse — your own binaries,
> CTF challenges, or malware inside a lab.

## How it works

```
            ┌─────────────┐   ┌──────────────────────┐   ┌──────────────┐
  bytes ───▶│  Capstone   │──▶│  simplification pass  │──▶│   Keystone   │──▶ bytes
  (region)  │ disassemble │   │  pipeline (AllPass)   │   │  reassemble  │
            └─────────────┘   └──────────┬───────────┘   └──────────────┘
                                         │ every substitution is
                                         ▼ checked with Unicorn
                                 ┌────────────────┐
                                 │  validate()    │  original state == rewritten state ?
                                 └────────────────┘
```

The core lives in two layers:

* **`passes/`** — the pattern library. Each pass is a `BasePass` subclass that
  (1) *matches* a mutation pattern in the instruction stream and (2) *generates*
  a smaller equivalent substitution. `AllPass` combines them and iterates to a
  fixed point (`ZeroPass`). Passes cover indirect `push`/`pop`/`mov`,
  stack-based arithmetic sandwiches, `xchg` idioms, constant propagation, dead
  store elimination, `lea` fusion, and more.
* **`themdem/`** — the runnable engine and front-end:
  * `Deobfuscator` — disassemble a region, run the pipeline, return the
    simplified instructions plus reduction stats. The trailing branch
    (`jmp`/`call`/`ret`) is preserved verbatim so relative targets stay valid.
  * `PEDeobfuscator` — load a 32-bit PE with **LIEF**, simplify the requested
    functions, overwrite the mutated body in place (NOP-padding up to the
    untouched terminator), and rebuild the file.
  * `cli` — the `themdem` command.

## Installation

```bash
pip install -r requirements.txt
# or, to get the `themdem` console script:
pip install -e .
```

Requires Python 3.10+ and Capstone, Keystone, Unicorn, LIEF and colorama.

## Usage

### Deobfuscate functions inside a PE

Give the virtual addresses of the mutated functions (the ones a trampoline
jumps to). `themdem` rewrites each in place and writes a new binary:

```bash
python -m themdem pe protected.exe -a 0x401000 0x401230 -o clean.exe
```

Preview without writing anything:

```bash
python -m themdem pe protected.exe -a 0x401000 --dry-run -v
```

```
=== function 0x00401000 ===
--- before ---
0x00401000:  sub esp, 4
0x00401003:  mov dword ptr [esp], eax
0x00401006:  push ebx
0x00401007:  mov dword ptr [esp], ecx
--- after ---
0x00401000:  push eax
0x00401006:  push ecx
(terminator kept: ret)
[+] 4 -> 2 instructions (2 removed)
```

### Deobfuscate a raw code blob

For a flat dump of machine code with no PE container:

```bash
python -m themdem raw body.bin -b 0x401000 -o body_clean.bin -v
```

### As a library

```python
from themdem import Deobfuscator

engine = Deobfuscator()
result = engine.simplify(code_bytes, address=0x401000)
print(result.format_listing())          # simplified assembly
print(result.reduction, "instructions removed")
patched = result.simplified_bytes        # ready to write back
```

```python
from themdem import PEDeobfuscator

deob = PEDeobfuscator("protected.exe")
deob.rewrite([0x401000, 0x401230])
deob.save("clean.exe")
```

## Tests

```bash
python -m pytest
```

The suite assembles each mutation pattern with Keystone, runs it through the
pipeline, and asserts the expected collapse. Because every substitution is
gated by the Unicorn validator, passing tests also demonstrate semantic
equivalence. PE tests build a minimal in-memory PE32 fixture, so no sample
binary is needed.

## Devirtualization (`themdem.devirt`)

Recovering code from Themida's *virtualized* handlers is a harder, separate
problem. `themdem.devirt` is a **VM-analysis framework** implementing the
generic engine every devirtualizer needs, following the design of **Pushan**
(Sudhir et al., 2026): label each basic block by `(address, VPC)`, emulate each
such block once (bounding state growth), and un-flatten the interpreter loop
into the original control flow.

Pipeline:

```
 detect ─▶ emulate ─▶ find VPC ─▶ segment ─▶ VPC-sensitive CFG ─▶ classify ─▶ disasm+lift
```

* `detect` — static Themida version/section fingerprinting, Shannon entropy,
  high-entropy bytecode-region ranking.
* `emulator` — Unicorn x86-32 engine: single-steps the interpreter, snapshots
  registers, finds the dispatch loop, and segments the trace into virtual
  instructions.
* `vpc` — ranks VPC candidates (pointer into bytecode + monotonic evolution).
* `cfg` — the `(address, VPC)`-keyed CFG.
* `vm` / `lifter` — a pluggable `VMArchitecture` spec disassembles the bytecode;
  the lifter folds the operand stack back into pseudocode.

End-to-end demo against a real (synthetic) stack VM:

```bash
python examples/devirt_demo.py
```

```
--- virtual assembly ---        --- pseudocode ---
0x0000:  PUSH 0xa               return (((0xa + 0x14) * 0x3) - 0x5);
0x0005:  PUSH 0x14
0x000a:  ADD
...
```

CLI (static triage + analysis):

```bash
python -m themdem detect protected.exe
python -m themdem devirt protected.exe --vm-entry 0x401000 \
       --bytecode 0x500000:0x40 --reg esi=0x500000 --arch example --dot cfg.dot
```

**Scope.** This is a *scaffold aimed at real Themida*, not a finished Themida
devirtualizer. The engine is proven against a synthetic x86 VM in the test
suite; targeting a real binary additionally requires (1) locating the VM
entry/VPC/bytecode and (2) writing a `VMArchitecture` spec for the handlers.
The engine is currently single-path (concrete) emulation; Pushan-style
symbolization + branch forcing (using the installed `z3`) is the main
extension. See [`docs/DEVIRT_DESIGN.md`](docs/DEVIRT_DESIGN.md) for the full
proven-vs-needs-a-sample breakdown.

## References & prior art

* Sudhir, Basque, Gibbs, Bajaj, et al. — *Pushan: Trace-Free Deobfuscation of
  Virtualization-Obfuscated Binaries* (arXiv:2603.18355).
* Di Gennaro, D'Onghia, Polino, Zanero, Carminati — *PackHero: A Scalable
  Graph-based Approach for Efficient Packer Identification* (arXiv:2506.00659) —
  static identification of Themida/WinLicense-packed binaries.
* [`ergrelet/themida-unmutate`](https://github.com/ergrelet/themida-unmutate) —
  a Miasm-based static demutator for Themida ≤ 3.1.9 (trampoline resolution +
  symbolic simplification), the closest sibling to this project.
* [`ergrelet/unlicense`](https://github.com/ergrelet/unlicense) — dynamic
  unpacker / import reconstruction for Themida/WinLicense.

## License

See [LICENSE](LICENSE).
