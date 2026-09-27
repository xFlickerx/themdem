"""CLI tests for the detect and devirt subcommands."""

from __future__ import annotations

import pytest

from themdem.cli import main

lief = pytest.importorskip("lief")

from _pe_fixture import build_pe32  # noqa: E402
from _vm_fixture import ADD, HALT, MUL, PUSH, SUB, build_vm_pe  # noqa: E402

PROG = [(PUSH, 10), (PUSH, 20), (ADD,), (PUSH, 3), (MUL,), (PUSH, 5), (SUB,), (HALT,)]


def test_detect_reports_sections(tmp_path, capsys):
    path = tmp_path / "p.exe"
    # A .themida section flags version 3.
    path.write_bytes(build_pe32(b"\x90" * 64, section_name=".themida"))
    rc = main(["detect", str(path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Themida/WinLicense 3.x" in out
    assert ".themida" in out


def test_devirt_cli_lifts_program(tmp_path, capsys):
    pe_bytes, entry, bc_va, bc_size, reg_init = build_vm_pe(PROG)
    path = tmp_path / "vm.exe"
    path.write_bytes(pe_bytes)
    dot = tmp_path / "cfg.dot"

    argv = [
        "devirt",
        str(path),
        "--vm-entry",
        hex(entry),
        "--bytecode",
        f"{hex(bc_va)}:{hex(bc_size)}",
        "--reg",
        f"esi={hex(reg_init['esi'])}",
        "--reg",
        f"edi={hex(reg_init['edi'])}",
        "--arch",
        "example",
        "--dot",
        str(dot),
    ]
    rc = main(argv)
    assert rc == 0
    out = capsys.readouterr().out
    assert "return (((0xa + 0x14) * 0x3) - 0x5);" in out
    assert dot.exists()
