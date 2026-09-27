"""Tests for the command-line interface."""

from __future__ import annotations

import pytest
from keystone import KS_ARCH_X86, KS_MODE_32, Ks

from themdem.cli import main

lief = pytest.importorskip("lief")

from _pe_fixture import IMAGE_BASE, SECTION_RVA, build_pe32  # noqa: E402

VA = IMAGE_BASE + SECTION_RVA


@pytest.fixture(scope="module")
def ks():
    return Ks(KS_ARCH_X86, KS_MODE_32)


def test_raw_command(tmp_path, ks, capsys):
    blob = tmp_path / "body.bin"
    blob.write_bytes(bytes(ks.asm("sub esp, 4\nmov dword ptr [esp], eax\nret")[0]))
    out = tmp_path / "body_clean.bin"
    rc = main(["raw", str(blob), "-b", "0x1000", "-o", str(out)])
    assert rc == 0
    captured = capsys.readouterr().out
    assert "push eax" in captured
    # push eax + ret
    assert out.read_bytes() == b"\x50\xc3"


def test_pe_dry_run_writes_nothing(tmp_path, ks, capsys):
    path = tmp_path / "p.exe"
    path.write_bytes(build_pe32(bytes(ks.asm("sub esp, 4\nmov dword ptr [esp], eax\nret")[0])))
    rc = main(["pe", str(path), "-a", hex(VA), "--dry-run"])
    assert rc == 0
    assert "push eax" in capsys.readouterr().out


def test_pe_rewrite(tmp_path, ks):
    path = tmp_path / "p.exe"
    path.write_bytes(build_pe32(bytes(ks.asm("sub esp, 4\nmov dword ptr [esp], eax\nret")[0])))
    out = tmp_path / "clean.exe"
    rc = main(["pe", str(path), "-a", hex(VA), "-o", str(out)])
    assert rc == 0
    assert out.exists()


def test_missing_file_returns_error(capsys):
    rc = main(["raw", "/definitely/not/here.bin"])
    assert rc == 1
    assert "error:" in capsys.readouterr().err
