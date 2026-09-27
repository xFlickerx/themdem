"""Lift a disassembled VM program into readable output.

Two views are produced:

* a flat *virtual assembly* listing (one line per virtual instruction), and
* a reconstructed *pseudocode* view, obtained by simulating the operand stack
  symbolically so that stack-machine sequences fold back into expressions
  (e.g. ``PUSH 10; PUSH 20; ADD`` becomes ``(0xa + 0x14)``).

The pseudocode reconstruction is the analysis payoff: it turns opaque bytecode
into something a human can read.
"""

from __future__ import annotations

from typing import List

from .vm import VMInstr


def to_vasm(instrs: List[VMInstr]) -> str:
    """Render a flat virtual-assembly listing."""
    lines = []
    for ins in instrs:
        if ins.operand is not None:
            lines.append(f"0x{ins.offset:04x}:  {ins.mnemonic} 0x{ins.operand:x}")
        else:
            lines.append(f"0x{ins.offset:04x}:  {ins.mnemonic}")
    return "\n".join(lines)


def lift_pseudocode(instrs: List[VMInstr]) -> List[str]:
    """Simulate the operand stack symbolically and emit pseudocode lines.

    Supports the common stack-VM kinds: ``push``, ``binop``, ``unop``,
    ``halt``. Unknown kinds are emitted verbatim so nothing is silently lost.
    """
    stack: List[str] = []
    lines: List[str] = []

    for ins in instrs:
        kind = ins.spec.kind
        if kind == "push":
            stack.append(f"0x{ins.operand:x}" if ins.operand is not None else "?")
        elif kind == "binop":
            if len(stack) < 2:
                lines.append(f"; stack underflow at {ins.mnemonic}")
                stack.clear()
                continue
            b = stack.pop()
            a = stack.pop()
            stack.append(f"({a} {ins.spec.py_op} {b})")
        elif kind == "unop":
            if not stack:
                lines.append(f"; stack underflow at {ins.mnemonic}")
                continue
            a = stack.pop()
            stack.append(f"{ins.spec.py_op}({a})")
        elif kind == "halt":
            result = stack[-1] if stack else "void"
            lines.append(f"return {result};")
        else:
            lines.append(f"{ins.mnemonic}"
                         + (f" 0x{ins.operand:x}" if ins.operand is not None else ""))

    if not any(line.startswith("return") for line in lines) and stack:
        lines.append(f"result = {stack[-1]};")
    return lines
