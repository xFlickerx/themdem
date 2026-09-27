#!/usr/bin/env python3
"""Self-contained demo: build a mutated code blob, then deobfuscate it.

Run from the repository root:

    python examples/demo.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import KS_ARCH_X86, KS_MODE_32, Ks  # noqa: E402

from themdem import Deobfuscator  # noqa: E402

# A hand-written "mutated" version of:
#     push eax
#     neg ebx
#     mov ecx, 8            (constant-folded from mov ecx,5; add ecx,3)
#     pop eax
#     ret
# expressed with the junk idioms Themida's mutation engine emits. (Keystone
# does not accept `;` comments, so the annotations stay in Python comments.)
MUTATED = "\n".join([
    "sub esp, 4",                    # \
    "mov dword ptr [esp], eax",      # == push eax
    "push 0",                        # \
    "sub dword ptr [esp], ebx",      #  |
    "pop ebx",                       # == neg ebx
    "mov ecx, 5",                    # \
    "add ecx, 3",                    # == mov ecx, 8
    "mov eax, dword ptr [esp]",      # \
    "add esp, 4",                    # == pop eax
    "ret",
])


def main() -> None:
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    code = bytes(ks.asm(MUTATED)[0])

    engine = Deobfuscator()
    result = engine.simplify(code, address=0x401000, profile=True)

    print("\n--- mutated ---")
    print(result.format_listing(simplified=False))
    print("\n--- deobfuscated ---")
    print(result.format_listing())
    if result.terminator is not None:
        print(f"(terminator kept: {result.terminator.mnemonic} {result.terminator.op_str})".rstrip())
    print(
        f"\n{len(result.original_instructions)} -> "
        f"{len(result.simplified_instructions)} instructions "
        f"({result.reduction} removed); "
        f"{result.stats['bytes_before']} -> {result.stats['bytes_after']} bytes"
    )


if __name__ == "__main__":
    main()
