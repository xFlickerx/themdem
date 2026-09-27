"""A tiny but real x86-32 stack-based VM, used to prove the devirt engine.

This mirrors the classic stack-VM architecture that Tigress and CTF challenges
(and, in spirit, commercial protectors) use: a fetch-decode-execute loop with a
Virtual Program Counter, an operand stack, and per-opcode handlers. We compile a
small program to bytecode *and* assemble a working interpreter for it, so the
devirtualizer can be run against genuine emulated execution rather than a mock.

Layout produced by :func:`build_vm`:
* interpreter machine code at ``CODE_BASE`` (ESI = VPC, EDI = operand stack ptr)
* bytecode at ``BC_BASE``
* operand stack at ``STACK_DATA``

Opcodes (1 byte, big operands little-endian):
    0x01 PUSH imm32   push imm
    0x02 ADD          b=pop; a=pop; push a+b
    0x03 SUB          b=pop; a=pop; push a-b
    0x04 MUL          b=pop; a=pop; push a*b
    0x05 HALT         ret (top of stack is the result, left in EAX)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from keystone import KS_ARCH_X86, KS_MODE_32, Ks

CODE_BASE = 0x00401000
BC_BASE = 0x00500000
STACK_DATA = 0x00600000

PUSH, ADD, SUB, MUL, HALT = 1, 2, 3, 4, 5


def compile_program(ops: List[Tuple]) -> bytes:
    """Assemble a list of (opcode, [imm]) tuples into VM bytecode."""
    out = bytearray()
    for op in ops:
        code = op[0]
        out.append(code)
        if code == PUSH:
            out += int(op[1] & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out)


# The interpreter. ESI holds the VPC (into the bytecode), EDI the operand-stack
# pointer. Labels are resolved by Keystone.
_INTERP_SRC = """
dispatch:
    movzx eax, byte ptr [esi]
    inc esi
    cmp eax, 1
    je h_push
    cmp eax, 2
    je h_add
    cmp eax, 3
    je h_sub
    cmp eax, 4
    je h_mul
    cmp eax, 5
    je h_halt
    jmp dispatch

h_push:
    mov eax, dword ptr [esi]
    add esi, 4
    mov dword ptr [edi], eax
    add edi, 4
    jmp dispatch

h_add:
    sub edi, 4
    mov ebx, dword ptr [edi]
    sub edi, 4
    mov ecx, dword ptr [edi]
    add ecx, ebx
    mov dword ptr [edi], ecx
    add edi, 4
    jmp dispatch

h_sub:
    sub edi, 4
    mov ebx, dword ptr [edi]
    sub edi, 4
    mov ecx, dword ptr [edi]
    sub ecx, ebx
    mov dword ptr [edi], ecx
    add edi, 4
    jmp dispatch

h_mul:
    sub edi, 4
    mov ebx, dword ptr [edi]
    sub edi, 4
    mov ecx, dword ptr [edi]
    imul ecx, ebx
    mov dword ptr [edi], ecx
    add edi, 4
    jmp dispatch

h_halt:
    sub edi, 4
    mov eax, dword ptr [edi]
    ret
"""


@dataclass
class VMImage:
    interp_code: bytes
    bytecode: bytes
    code_base: int = CODE_BASE
    bc_base: int = BC_BASE
    stack_data: int = STACK_DATA


def build_vm(ops: List[Tuple]) -> VMImage:
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    interp, _ = ks.asm(_INTERP_SRC, CODE_BASE)
    bc = compile_program(ops)
    return VMImage(interp_code=bytes(interp), bytecode=bc)


def build_vm_pe(ops: List[Tuple]):
    """Build a PE embedding the interpreter + bytecode in one .text section.

    Returns ``(pe_bytes, vm_entry, bytecode_va, bytecode_size, reg_init)``.
    The operand-stack pointer (EDI) is pointed inside the emulator's own mapped
    stack so ``Devirtualizer.from_pe`` needs no extra data mapping.
    """
    from _pe_fixture import IMAGE_BASE, SECTION_RVA, build_pe32

    img = build_vm(ops)
    # Place bytecode 0x1000 bytes after the interpreter within the same section.
    bc_offset = 0x1000
    content = bytearray(img.interp_code)
    content += b"\x00" * (bc_offset - len(content))
    content += img.bytecode

    pe_bytes = build_pe32(bytes(content))
    vm_entry = IMAGE_BASE + SECTION_RVA  # == CODE_BASE (0x401000)
    bytecode_va = IMAGE_BASE + SECTION_RVA + bc_offset
    reg_init = {"esi": bytecode_va, "edi": 0x00210000}
    return pe_bytes, vm_entry, bytecode_va, len(img.bytecode), reg_init


def reference_eval(ops: List[Tuple]) -> int:
    """Concretely evaluate the VM program in Python (ground truth)."""
    stack: List[int] = []
    for op in ops:
        if op[0] == PUSH:
            stack.append(op[1] & 0xFFFFFFFF)
        elif op[0] == ADD:
            b = stack.pop(); a = stack.pop(); stack.append((a + b) & 0xFFFFFFFF)
        elif op[0] == SUB:
            b = stack.pop(); a = stack.pop(); stack.append((a - b) & 0xFFFFFFFF)
        elif op[0] == MUL:
            b = stack.pop(); a = stack.pop(); stack.append((a * b) & 0xFFFFFFFF)
        elif op[0] == HALT:
            break
    return stack[-1] & 0xFFFFFFFF
