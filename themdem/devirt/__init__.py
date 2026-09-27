"""VM devirtualization / analysis framework (Themida-oriented scaffold).

This subpackage recovers structure from *virtualization*-obfuscated code, as
opposed to the mutation deobfuscator in the parent package. The pipeline follows
the design of Pushan (VPC-sensitive recovery) adapted to a Unicorn-based,
constraint-free emulator:

    detect  ->  emulate  ->  find VPC  ->  segment virtual instructions
            ->  VPC-sensitive CFG  ->  classify handlers  ->  disassemble + lift

See ``docs/DEVIRT_DESIGN.md`` for what is proven here versus what needs a real
Themida sample and a hand-written VM spec to complete.
"""

from .cfg import Node, NodeID, VPCSensitiveCFG
from .detect import DetectionResult, analyze, shannon_entropy
from .devirtualizer import DevirtResult, Devirtualizer, analyze_pe
from .emulator import EmulationTrace, Segment, VirtualInstruction, VMEmulator, find_vpc
from .vm import (
    STACK_VM_EXAMPLE,
    HandlerClass,
    OpcodeSpec,
    VMArchitecture,
    VMInstr,
    classify_handlers,
)
from .vpc import Range, VPCCandidate, VPCTracker

__all__ = [
    "analyze",
    "analyze_pe",
    "DetectionResult",
    "shannon_entropy",
    "VPCSensitiveCFG",
    "Node",
    "NodeID",
    "Range",
    "VPCTracker",
    "VPCCandidate",
    "Segment",
    "VMEmulator",
    "EmulationTrace",
    "VirtualInstruction",
    "find_vpc",
    "VMArchitecture",
    "OpcodeSpec",
    "VMInstr",
    "HandlerClass",
    "classify_handlers",
    "STACK_VM_EXAMPLE",
    "Devirtualizer",
    "DevirtResult",
]
