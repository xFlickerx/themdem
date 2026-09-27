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

> ⚠️ **Scope & intended use.** This is a reverse-engineering research/education
> tool. Use it on software you are authorised to analyse — your own binaries,
> CTF challenges, or malware inside a lab. Full *de-virtualization* (recovering
> the original code from VM bytecode) is **not** implemented; see
> [Devirtualization](#devirtualization-not-yet-implemented) below.

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

## Devirtualization (not yet implemented)

Recovering code from Themida's *virtualized* handlers is a harder, separate
problem and is intentionally out of scope for this mutation-focused tool. The
current state of the art is **Pushan** (Sudhir et al., 2026), which recovers a
complete control-flow graph via *VPC-sensitive, constraint-free symbolic
emulation* — uniquely labelling each basic block by `(address, VPC)`, emulating
each block at most once to bound state growth, using an SMT solver purely as an
expression simplifier/value enumerator (never for path feasibility), and
"symbolizing" merged values to recover missed edges — then applying
semantics-preserving simplifications and decompiling to C. A practical bridge
from `themdem` would be:

1. locate a virtualized function's VM entry and its Virtual Program Counter,
2. recover a VPC-sensitive CFG by constraint-free symbolic emulation,
3. run the existing `passes/` simplifications over the recovered ("flat") CFG,
4. hand the cleaned CFG to a decompiler.

Contributions in that direction are welcome.

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
