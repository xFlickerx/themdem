"""Tests for the individual simplification passes.

Every pass is validated internally by the Unicorn-based ``validate()`` helper
(it raises ``AssertionError`` if the substituted code is not semantically
equivalent to the original). These tests therefore assert *both* that the
expected mutation pattern collapses and, implicitly, that the result is
semantically equivalent.
"""

from __future__ import annotations

import pytest
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from keystone import KS_ARCH_X86, KS_MODE_32, Ks

from passes import AllPass


@pytest.fixture(scope="module")
def tools():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    return md, ks


def simplify(tools, asm: str, address: int = 0x1000):
    md, ks = tools
    code = bytes(ks.asm(asm)[0])
    insns = list(md.disasm(code, address))
    out = AllPass(md, ks)(insns)
    return [f"{i.mnemonic} {i.op_str}".strip() for i in out]


def test_indirect_push(tools):
    # sub esp,4 ; mov [esp], eax  ==>  push eax
    result = simplify(tools, "sub esp, 4\nmov dword ptr [esp], eax\nnop")
    assert result == ["push eax", "nop"]


def test_indirect_pop(tools):
    # mov eax, [esp] ; add esp, 4  ==>  pop eax
    result = simplify(tools, "mov eax, dword ptr [esp]\nadd esp, 4\nnop")
    assert result == ["pop eax", "nop"]


def test_indirect_mov_via_stack(tools):
    # push ecx ; pop eax  ==>  mov eax, ecx
    result = simplify(tools, "push ecx\npop eax\nnop")
    assert result == ["mov eax, ecx", "nop"]


def test_constant_propagation(tools):
    # mov eax, 5 ; add eax, 3  ==>  mov eax, 8
    result = simplify(tools, "mov eax, 5\nadd eax, 3\nnop")
    assert result == ["mov eax, 8", "nop"]


def test_sandwich_arithmetic(tools):
    # push eax ; mov eax, 7 ; add eax, ... no -- pattern is:
    # push reg ; mov reg, imm ; <op> reg2, reg ; pop reg  ==> <op> reg2, imm
    result = simplify(tools, "push eax\nmov eax, 0x10\nadd ebx, eax\npop eax\nnop")
    assert result == ["add ebx, 0x10", "nop"]


def test_stack_neg(tools):
    # push 0 ; sub [esp], eax ; pop eax  ==>  neg eax
    result = simplify(tools, "push 0\nsub dword ptr [esp], eax\npop eax\nnop")
    assert result == ["neg eax", "nop"]


def test_double_xchg(tools):
    # xchg eax, ebx ; inc eax ; xchg eax, ebx  ==>  inc ebx
    result = simplify(tools, "xchg eax, ebx\ninc eax\nxchg eax, ebx\nnop")
    assert result == ["inc ebx", "nop"]


def test_dead_store_elimination(tools):
    # mov eax, 1 ; mov eax, 2  ==>  mov eax, 2 (first store is dead)
    result = simplify(tools, "mov eax, 1\nmov eax, 2\nnop")
    assert result == ["mov eax, 2", "nop"]


def test_leaves_non_mutation_code_untouched(tools):
    # Independent, non-redundant instructions match no mutation pattern and
    # must survive unchanged. (No terminator in the body: the Unicorn validator
    # emulates it linearly, so branches belong to the region terminator.)
    result = simplify(tools, "inc eax\ndec ebx\nxor ecx, edx\nnop")
    assert result == ["inc eax", "dec ebx", "xor ecx, edx", "nop"]
