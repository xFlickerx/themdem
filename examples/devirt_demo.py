#!/usr/bin/env python3
"""Self-contained devirtualization demo.

Builds a real x86-32 stack VM, virtualizes a small arithmetic program into
bytecode, then runs the analysis pipeline to recover the opcode structure,
disassemble the bytecode, and lift it back to pseudocode.

    python examples/devirt_demo.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"))

from _vm_fixture import ADD, HALT, MUL, PUSH, SUB, build_vm, reference_eval  # noqa: E402
from themdem.devirt import Devirtualizer, Range, Segment, STACK_VM_EXAMPLE  # noqa: E402


def main() -> None:
    # (10 + 20) * 3 - 5  ==  85
    program = [
        (PUSH, 10), (PUSH, 20), (ADD,),
        (PUSH, 3), (MUL,),
        (PUSH, 5), (SUB,),
        (HALT,),
    ]
    img = build_vm(program)

    print("virtualized bytecode:", img.bytecode.hex())
    print("(this is what an analyst would see instead of the original code)\n")

    segments = [
        Segment(img.code_base, img.interp_code),
        Segment(img.bc_base, img.bytecode),
        Segment(img.stack_data, b"\x00" * 0x1000, writable=True),
    ]
    deob = Devirtualizer(
        segments,
        arch=STACK_VM_EXAMPLE,
        reg_init={"esi": img.bc_base, "edi": img.stack_data},
    )
    result = deob.run(img.code_base, Range(img.bc_base, img.bc_base + len(img.bytecode)))

    print(result.report())
    print(f"\nground-truth evaluation: {reference_eval(program)}")


if __name__ == "__main__":
    main()
