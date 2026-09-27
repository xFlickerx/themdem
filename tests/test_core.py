"""Tests for the high-level Deobfuscator engine."""

from __future__ import annotations

import pytest
from keystone import KS_ARCH_X86, KS_MODE_32, Ks

from themdem import Deobfuscator


@pytest.fixture(scope="module")
def ks():
    return Ks(KS_ARCH_X86, KS_MODE_32)


@pytest.fixture(scope="module")
def engine():
    return Deobfuscator()


def asm(ks, text: str) -> bytes:
    return bytes(ks.asm(text)[0])


def test_terminator_is_preserved(engine, ks):
    code = asm(ks, "sub esp, 4\nmov dword ptr [esp], eax\nret")
    result = engine.simplify(code, 0x401000)
    assert result.terminator is not None
    assert result.terminator.mnemonic == "ret"
    assert [f"{i.mnemonic} {i.op_str}".strip() for i in result.simplified_instructions] == ["push eax"]


def test_simplified_bytes_include_terminator(engine, ks):
    code = asm(ks, "sub esp, 4\nmov dword ptr [esp], eax\nret")
    result = engine.simplify(code, 0x401000)
    # push eax (0x50) + ret (0xc3)
    assert result.simplified_bytes == b"\x50\xc3"


def test_reduction_counts(engine, ks):
    code = asm(ks, "mov eax, 5\nadd eax, 3\nret")
    result = engine.simplify(code, 0x401000)
    assert result.reduction == 1
    assert result.stats["instructions_before"] == 2
    assert result.stats["instructions_after"] == 1


def test_body_never_grows(engine, ks):
    # De-mutation only removes instructions: output must fit the original body.
    code = asm(ks, "push eax\nmov eax, 0x10\nadd ebx, eax\npop eax\nret")
    result = engine.simplify(code, 0x401000)
    body_before = sum(i.size for i in result.original_instructions)
    body_after = sum(i.size for i in result.simplified_instructions)
    assert body_after <= body_before


def test_empty_region_raises(engine):
    with pytest.raises(ValueError):
        engine.simplify(b"", 0x401000)


def test_no_terminator_when_disabled(engine, ks):
    # With keep_terminator=False the whole blob is treated as the body. This is
    # only safe when the body has no control-flow instruction, since the
    # validator emulates it linearly.
    code = asm(ks, "push ecx\npop eax\nnop")
    result = engine.simplify(code, 0x401000, keep_terminator=False)
    assert result.terminator is None
    assert [f"{i.mnemonic} {i.op_str}".strip() for i in result.simplified_instructions] == [
        "mov eax, ecx",
        "nop",
    ]
