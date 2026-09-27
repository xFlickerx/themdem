"""Unicorn-based constraint-free emulation engine for VM interpreters.

This is the heart of the analysis: given the interpreter's entry point and the
VM bytecode range, it single-steps the interpreter (x86, 32-bit) under Unicorn,
snapshots registers at every native instruction, and then segments the trace
into *virtual instructions* by watching the VPC advance. Grouping the native
instructions executed between two VPC advances yields, per virtual instruction,
the handler body that implemented it.

The engine is single-path (it follows concrete execution, like a trace). The
``VPCSensitiveCFG`` it produces is keyed by ``(handler_addr, vpc)`` so that, as
branch-forcing / symbolization is added, additional edges and blocks can be
merged in without changing the recovered structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_MODE_32,
    Uc,
    UcError,
)
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_EBP,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDI,
    UC_X86_REG_EDX,
    UC_X86_REG_EIP,
    UC_X86_REG_ESI,
    UC_X86_REG_ESP,
)

from .cfg import VPCSensitiveCFG
from .vpc import Range, VPCTracker

_REGS = {
    "eax": UC_X86_REG_EAX,
    "ebx": UC_X86_REG_EBX,
    "ecx": UC_X86_REG_ECX,
    "edx": UC_X86_REG_EDX,
    "esi": UC_X86_REG_ESI,
    "edi": UC_X86_REG_EDI,
    "ebp": UC_X86_REG_EBP,
    "esp": UC_X86_REG_ESP,
}

_PAGE = 0x1000
_RETURN_SENTINEL = 0xDEAD0000


@dataclass
class Segment:
    """A chunk of the target's address space to map into the emulator."""

    base: int
    data: bytes
    writable: bool = False


@dataclass
class Step:
    index: int
    address: int
    regs: Dict[str, int]


@dataclass
class VirtualInstruction:
    """One recovered virtual instruction (a handler invocation)."""

    vpc: int
    handler_addr: int
    native_addresses: List[int] = field(default_factory=list)
    #: Register snapshot at handler entry.
    entry_regs: Dict[str, int] = field(default_factory=dict)


@dataclass
class EmulationTrace:
    steps: List[Step] = field(default_factory=list)
    stopped_reason: str = ""

    def register_snapshots(self, locations: List[str]) -> List[Dict[str, int]]:
        return [{loc: s.regs[loc] for loc in locations if loc in s.regs} for s in self.steps]


class VMEmulator:
    def __init__(
        self,
        segments: List[Segment],
        stack_base: int = 0x00200000,
        stack_size: int = 0x00040000,
        reg_init: Optional[Dict[str, int]] = None,
    ) -> None:
        self.segments = segments
        self.stack_base = stack_base
        self.stack_size = stack_size
        self.reg_init = reg_init or {}

    # -- setup ---------------------------------------------------------------
    def _map_and_init(self) -> Uc:
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for seg in self.segments:
            base = seg.base & ~(_PAGE - 1)
            end = (seg.base + len(seg.data) + _PAGE - 1) & ~(_PAGE - 1)
            uc.mem_map(base, end - base)
            uc.mem_write(seg.base, seg.data)
        # Stack.
        uc.mem_map(self.stack_base, self.stack_size)
        sp = self.stack_base + self.stack_size - 0x100
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_EBP, sp)
        # Push a sentinel return address so a final `ret` leaves mapped memory
        # and stops emulation cleanly.
        uc.mem_write(sp, _RETURN_SENTINEL.to_bytes(4, "little"))
        for name, value in self.reg_init.items():
            if name in _REGS:
                uc.reg_write(_REGS[name], value)
        return uc

    # -- run -----------------------------------------------------------------
    def run(self, entry: int, max_steps: int = 200_000) -> EmulationTrace:
        uc = self._map_and_init()
        trace = EmulationTrace()

        def on_code(uc_: Uc, address: int, size: int, _ud) -> None:
            if len(trace.steps) >= max_steps:
                trace.stopped_reason = "max_steps"
                uc_.emu_stop()
                return
            regs = {name: uc_.reg_read(const) for name, const in _REGS.items()}
            regs["eip"] = address
            trace.steps.append(Step(index=len(trace.steps), address=address, regs=regs))

        def on_invalid(uc_: Uc, _type, address: int, _size, _val, _ud) -> bool:
            # Reaching the sentinel (or any unmapped access) ends the run.
            if address & ~(_PAGE - 1) == _RETURN_SENTINEL & ~(_PAGE - 1):
                trace.stopped_reason = "returned"
            else:
                trace.stopped_reason = f"unmapped@0x{address:x}"
            uc_.emu_stop()
            return False

        uc.hook_add(UC_HOOK_CODE, on_code)
        uc.hook_add(
            UC_HOOK_MEM_FETCH_UNMAPPED
            | UC_HOOK_MEM_READ_UNMAPPED
            | UC_HOOK_MEM_WRITE_UNMAPPED,
            on_invalid,
        )

        try:
            uc.emu_start(entry, _RETURN_SENTINEL, timeout=30 * 1_000_000, count=max_steps)
            if not trace.stopped_reason:
                trace.stopped_reason = "completed"
        except UcError as exc:
            if not trace.stopped_reason:
                trace.stopped_reason = f"uc_error:{exc}"
        return trace

    # -- recovery ------------------------------------------------------------
    @staticmethod
    def find_dispatcher(trace: EmulationTrace) -> int:
        """Find the interpreter's dispatch-loop head.

        The loop head is the native address most frequently entered via a
        *backward* control-flow edge (the ``jmp dispatcher`` that ends each
        handler). This robustly marks the start of each fetch-decode-execute
        iteration, independent of how many bytes each handler consumes.
        """
        from collections import Counter

        counter: Counter = Counter()
        for i in range(1, len(trace.steps)):
            addr = trace.steps[i].address
            prev = trace.steps[i - 1].address
            if addr <= prev:  # backward edge target
                counter[addr] += 1
        if not counter:
            return trace.steps[0].address if trace.steps else 0
        return counter.most_common(1)[0][0]

    @staticmethod
    def segment(
        trace: EmulationTrace,
        vpc_location: str,
        dispatcher: Optional[int] = None,
    ) -> List[VirtualInstruction]:
        """Split a trace into virtual instructions at each dispatcher visit.

        Each iteration from one dispatcher visit to the next is one virtual
        instruction; its VPC is the bytecode pointer at the fetch, and its
        native-address set is the handler body that implemented it.
        """
        if dispatcher is None:
            dispatcher = VMEmulator.find_dispatcher(trace)

        vinstrs: List[VirtualInstruction] = []
        current: Optional[VirtualInstruction] = None
        for step in trace.steps:
            if step.address == dispatcher:
                current = VirtualInstruction(
                    vpc=step.regs.get(vpc_location, step.address),
                    handler_addr=step.address,
                    entry_regs=dict(step.regs),
                )
                vinstrs.append(current)
            if current is not None:
                current.native_addresses.append(step.address)
        return vinstrs

    @staticmethod
    def handler_fingerprint(vi: "VirtualInstruction", base: int = 0) -> tuple:
        """A relocatable signature of a handler body (native offsets executed).

        Offsets are taken relative to ``base`` (e.g. the dispatcher) so the same
        handler reached for different VPCs produces the same fingerprint.
        """
        return tuple(sorted({a - base for a in vi.native_addresses}))

    @staticmethod
    def build_cfg(vinstrs: List[VirtualInstruction]) -> VPCSensitiveCFG:
        """Build a VPC-sensitive CFG from a sequence of virtual instructions."""
        cfg = VPCSensitiveCFG()
        prev = None
        for vi in vinstrs:
            nid = (vi.handler_addr, vi.vpc)
            node = cfg.add_node(nid)
            node.instructions = list(vi.native_addresses)
            if prev is not None and prev != nid:
                cfg.add_edge(prev, nid)
            prev = nid
        return cfg


def find_vpc(trace: EmulationTrace, bytecode: Range) -> Optional[str]:
    """Rank VPC candidates from a trace's register snapshots."""
    tracker = VPCTracker(bytecode)
    for snap in trace.register_snapshots(list(_REGS.keys())):
        tracker.observe(snap)
    best = tracker.best()
    return best.location if best is not None else None
