"""Orchestrator: drive the full VM-analysis pipeline.

This wires the pieces together:

    detect  ->  emulate  ->  find VPC  ->  segment into virtual instructions
            ->  recover VPC-sensitive CFG  ->  classify handlers
            ->  (optional) disassemble + lift with a VM spec

For real Themida binaries you supply the VM entry address (and, once known, a
``VMArchitecture`` describing the handlers). Without a spec you still get the
recovered opcode structure and per-handler bodies, which is what you use to
*build* the spec.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import lief

from . import detect
from .cfg import VPCSensitiveCFG
from .emulator import Segment, VMEmulator, find_vpc
from .lifter import lift_pseudocode, to_vasm
from .vm import HandlerClass, VMArchitecture, VMInstr, classify_handlers
from .vpc import Range


@dataclass
class DevirtResult:
    entry: int
    steps: int
    stopped_reason: str
    vpc_location: Optional[str]
    dispatcher: int
    bytecode_range: Range
    virtual_instruction_count: int
    cfg: VPCSensitiveCFG
    handler_classes: List[HandlerClass] = field(default_factory=list)
    opcode_sequence: List[str] = field(default_factory=list)
    disassembly: Optional[List[VMInstr]] = None
    pseudocode: Optional[List[str]] = None

    def report(self) -> str:
        lines = [
            f"VM entry:        0x{self.entry:x}",
            f"emulated steps:  {self.steps} ({self.stopped_reason})",
            f"VPC location:    {self.vpc_location}",
            f"dispatcher:      0x{self.dispatcher:x}",
            f"bytecode range:  0x{self.bytecode_range.start:x}-0x{self.bytecode_range.end:x}",
            f"virtual instrs:  {self.virtual_instruction_count}",
            f"CFG nodes:       {len(self.cfg)}  (distinct VPCs: {len(self.cfg.vpc_values())})",
            f"handler classes: {len(self.handler_classes)}",
        ]
        if self.handler_classes:
            lines.append("recovered opcodes:")
            for hc in sorted(self.handler_classes, key=lambda c: c.label):
                lines.append(
                    f"  {hc.label}: {hc.occurrences}x, {len(hc.fingerprint)} native insns"
                )
        if self.opcode_sequence:
            lines.append("opcode stream: " + " ".join(self.opcode_sequence))
        if self.disassembly is not None:
            lines.append("\n--- virtual assembly ---")
            lines.append(to_vasm(self.disassembly))
        if self.pseudocode is not None:
            lines.append("\n--- pseudocode ---")
            lines.extend(self.pseudocode)
        return "\n".join(lines)


class Devirtualizer:
    def __init__(
        self,
        segments: List[Segment],
        arch: Optional[VMArchitecture] = None,
        reg_init: Optional[dict] = None,
    ) -> None:
        self.segments = segments
        self.arch = arch
        self.reg_init = reg_init or {}
        self.emulator = VMEmulator(segments, reg_init=self.reg_init)

    # -- constructors --------------------------------------------------------
    @classmethod
    def from_pe(
        cls,
        pe_path: str,
        arch: Optional[VMArchitecture] = None,
        reg_init: Optional[dict] = None,
        writable_all: bool = True,
    ) -> "Devirtualizer":
        pe = lief.PE.parse(pe_path)
        if pe is None:
            raise ValueError(f"Failed to parse PE: {pe_path!r}")
        base = pe.imagebase
        segments: List[Segment] = []
        for s in pe.sections:
            content = bytes(s.content)
            if not content:
                continue
            C = lief.PE.Section.CHARACTERISTICS
            writable = writable_all or bool(s.characteristics & C.MEM_WRITE.value)
            segments.append(Segment(base + s.virtual_address, content, writable=writable))
        return cls(segments, arch=arch, reg_init=reg_init)

    # -- pipeline ------------------------------------------------------------
    def run(
        self,
        entry: int,
        bytecode: Range,
        max_steps: int = 200_000,
        disassemble: bool = True,
    ) -> DevirtResult:
        trace = self.emulator.run(entry, max_steps=max_steps)

        vpc_location = find_vpc(trace, bytecode)
        dispatcher = self.emulator.find_dispatcher(trace)

        vinstrs = []
        if vpc_location is not None:
            vinstrs = self.emulator.segment(trace, vpc_location, dispatcher)

        cfg = self.emulator.build_cfg(vinstrs)
        classes, sequence = classify_handlers(vinstrs, dispatcher)

        disasm = None
        pseudo = None
        if disassemble and self.arch is not None:
            # Read the bytecode bytes from the mapped segment.
            bc_bytes = self._read_range(bytecode)
            try:
                disasm = self.arch.disassemble(bc_bytes)
                pseudo = lift_pseudocode(disasm)
                # Attach mnemonics onto the CFG nodes for readability.
                for ins in disasm:
                    for node in cfg.nodes():
                        if node.vpc - bytecode.start == ins.offset:
                            node.handler = ins.mnemonic
            except KeyError:
                disasm = None

        return DevirtResult(
            entry=entry,
            steps=len(trace.steps),
            stopped_reason=trace.stopped_reason,
            vpc_location=vpc_location,
            dispatcher=dispatcher,
            bytecode_range=bytecode,
            virtual_instruction_count=len(vinstrs),
            cfg=cfg,
            handler_classes=list(classes.values()),
            opcode_sequence=sequence,
            disassembly=disasm,
            pseudocode=pseudo,
        )

    def _read_range(self, rng: Range) -> bytes:
        for seg in self.segments:
            if seg.base <= rng.start < seg.base + len(seg.data):
                off = rng.start - seg.base
                return seg.data[off : off + (rng.end - rng.start)]
        raise ValueError(f"No segment contains range 0x{rng.start:x}")


def analyze_pe(pe_path: str) -> detect.DetectionResult:
    """Convenience wrapper for the static-detection stage."""
    return detect.analyze(pe_path)
