"""Tests for the VM devirtualization / analysis framework.

These prove the *mechanics* of the pipeline against a real (synthetic) x86 VM:
detection, entropy, VPC tracking, the VPC-sensitive CFG, the emulation engine,
handler classification, disassembly and lifting. A real Themida VM would need
its own ``VMArchitecture`` spec, but the engine driving it is exercised here.
"""

from __future__ import annotations

import pytest

from themdem.devirt import (
    STACK_VM_EXAMPLE,
    Devirtualizer,
    Range,
    Segment,
    VMArchitecture,
    VMEmulator,
    VPCSensitiveCFG,
    VPCTracker,
    classify_handlers,
    find_vpc,
    shannon_entropy,
)
from themdem.devirt.lifter import lift_pseudocode, to_vasm

from _vm_fixture import (  # noqa: E402
    ADD,
    HALT,
    MUL,
    PUSH,
    SUB,
    build_vm,
    build_vm_pe,
    reference_eval,
)

PROG = [(PUSH, 10), (PUSH, 20), (ADD,), (PUSH, 3), (MUL,), (PUSH, 5), (SUB,), (HALT,)]


# -- entropy -----------------------------------------------------------------
def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0
    assert shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0, abs=0.01)


# -- VPC tracker -------------------------------------------------------------
def test_vpc_tracker_prefers_monotonic_in_region():
    bc = Range(0x1000, 0x1100)
    tracker = VPCTracker(bc)
    # esi advances sequentially inside the region; ecx is random noise outside.
    for i in range(8):
        tracker.observe({"esi": 0x1000 + i * 4, "ecx": 0x99999 + i})
    best = tracker.best()
    assert best is not None
    assert best.location == "esi"


# -- CFG structure -----------------------------------------------------------
def test_vpc_sensitive_cfg_merges_by_id():
    cfg = VPCSensitiveCFG()
    cfg.add_edge((0x10, 0), (0x20, 1))
    cfg.add_edge((0x20, 1), (0x10, 0))  # back edge to an existing node
    assert len(cfg) == 2
    assert cfg.vpc_values() == {0, 1}
    assert (0x10, 0) in cfg.successors((0x20, 1))


# -- architecture disassembly + lift -----------------------------------------
def test_disassemble_and_lift_example_vm():
    from _vm_fixture import compile_program

    bc = compile_program(PROG)
    instrs = STACK_VM_EXAMPLE.disassemble(bc)
    assert [i.mnemonic for i in instrs] == [
        "PUSH", "PUSH", "ADD", "PUSH", "MUL", "PUSH", "SUB", "HALT",
    ]
    pseudo = lift_pseudocode(instrs)
    assert pseudo == ["return (((0xa + 0x14) * 0x3) - 0x5);"]
    assert "PUSH 0xa" in to_vasm(instrs)


def test_unknown_opcode_raises():
    arch = VMArchitecture(name="x", opcodes={})
    with pytest.raises(KeyError):
        arch.disassemble(b"\xff")


# -- emulation engine --------------------------------------------------------
def test_engine_recovers_program_from_segments():
    img = build_vm(PROG)
    segs = [
        Segment(img.code_base, img.interp_code),
        Segment(img.bc_base, img.bytecode),
        Segment(img.stack_data, b"\x00" * 0x1000, writable=True),
    ]
    emu = VMEmulator(segs, reg_init={"esi": img.bc_base, "edi": img.stack_data})
    trace = emu.run(img.code_base, max_steps=5000)
    assert trace.stopped_reason == "completed"

    bc = Range(img.bc_base, img.bc_base + len(img.bytecode))
    vpc = find_vpc(trace, bc)
    assert vpc == "esi"

    disp = emu.find_dispatcher(trace)
    vinstrs = emu.segment(trace, vpc, disp)
    assert len(vinstrs) == len(PROG)

    classes, sequence = classify_handlers(vinstrs, disp)
    # PUSH appears 4x and must map to a single handler class.
    assert sequence[0] == sequence[1]
    assert sequence.count(sequence[0]) == 4
    # 5 distinct opcodes were used (PUSH, ADD, MUL, SUB, HALT).
    assert len(classes) == 5

    cfg = emu.build_cfg(vinstrs)
    assert len(cfg) == len(PROG)


# -- full pipeline via Devirtualizer -----------------------------------------
def test_devirtualizer_segments():
    img = build_vm(PROG)
    segs = [
        Segment(img.code_base, img.interp_code),
        Segment(img.bc_base, img.bytecode),
        Segment(img.stack_data, b"\x00" * 0x1000, writable=True),
    ]
    d = Devirtualizer(segs, arch=STACK_VM_EXAMPLE, reg_init={"esi": img.bc_base, "edi": img.stack_data})
    res = d.run(img.code_base, Range(img.bc_base, img.bc_base + len(img.bytecode)))
    assert res.vpc_location == "esi"
    assert res.virtual_instruction_count == len(PROG)
    assert res.pseudocode == ["return (((0xa + 0x14) * 0x3) - 0x5);"]
    assert reference_eval(PROG) == 85


# -- full pipeline from a PE -------------------------------------------------
def test_devirtualizer_from_pe(tmp_path):
    pe_bytes, entry, bc_va, bc_size, reg_init = build_vm_pe(PROG)
    path = tmp_path / "vm.exe"
    path.write_bytes(pe_bytes)

    d = Devirtualizer.from_pe(str(path), arch=STACK_VM_EXAMPLE, reg_init=reg_init)
    res = d.run(entry, Range(bc_va, bc_va + bc_size))
    assert res.virtual_instruction_count == len(PROG)
    assert res.pseudocode == ["return (((0xa + 0x14) * 0x3) - 0x5);"]

    dot = res.cfg.to_dot()
    assert dot.startswith("digraph")
