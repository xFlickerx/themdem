"""End-to-end tests for the PE loader/rewriter."""

from __future__ import annotations

import pytest
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from keystone import KS_ARCH_X86, KS_MODE_32, Ks

lief = pytest.importorskip("lief")

from _pe_fixture import IMAGE_BASE, SECTION_RVA, build_pe32  # noqa: E402
from themdem import PEDeobfuscator  # noqa: E402

VA = IMAGE_BASE + SECTION_RVA


@pytest.fixture(scope="module")
def ks():
    return Ks(KS_ARCH_X86, KS_MODE_32)


def make_pe(tmp_path, ks, asm_text):
    code = bytes(ks.asm(asm_text)[0])
    path = tmp_path / "protected.exe"
    path.write_bytes(build_pe32(code))
    return str(path)


def test_read_va(tmp_path, ks):
    path = make_pe(tmp_path, ks, "sub esp, 4\nmov dword ptr [esp], eax\nret")
    deob = PEDeobfuscator(path)
    data = deob.read_va(VA, 3)
    assert data == b"\x83\xec\x04"  # sub esp, 4


def test_rewrite_and_save(tmp_path, ks):
    path = make_pe(tmp_path, ks, "sub esp, 4\nmov dword ptr [esp], eax\npush ebx\nmov dword ptr [esp], ecx\nret")
    deob = PEDeobfuscator(path)
    reports = deob.rewrite([VA], max_size=0x200)
    assert reports[0].result.reduction == 2

    out = tmp_path / "clean.exe"
    deob.save(str(out))

    # Re-parse and disassemble the rewritten section.
    rebuilt = lief.PE.parse(str(out))
    section = rebuilt.get_section(".text")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    disasm = [f"{i.mnemonic} {i.op_str}".strip() for i in md.disasm(bytes(section.content), VA)]
    assert disasm[:2] == ["push eax", "push ecx"]
    # NOP padding, then the preserved terminator.
    assert "ret" in disasm
    assert disasm[2] == "nop"


def test_refuses_to_grow(tmp_path, ks, monkeypatch):
    # If simplification somehow produced larger code, rewrite must refuse.
    path = make_pe(tmp_path, ks, "nop\nret")
    deob = PEDeobfuscator(path)

    class FakeResult:
        original_instructions = [type("I", (), {"size": 1})()]
        simplified_instructions = [
            type("I", (), {"size": 1, "bytes": b"\x90\x90"})()
        ]

    monkeypatch.setattr(deob, "simplify_function", lambda *a, **k: FakeResult())
    with pytest.raises(RuntimeError):
        deob.rewrite([VA])
