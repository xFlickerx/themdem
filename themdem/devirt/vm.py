"""VM architecture specifications and handler classification.

A ``VMArchitecture`` describes a virtual machine's instruction set: how wide an
opcode is, and, per opcode byte, its mnemonic, operand width, and semantic kind.
Supplying such a spec turns the bytecode region into a *disassemblable* stream —
this is the pluggable seam where a real Themida VM variant (Fish/Tiger/Dolphin)
would be described once its handlers are reverse-engineered.

When no spec is available, :func:`classify_handlers` groups the recovered
handler bodies by a relocation-independent fingerprint, so the *structure* of
the VM (how many distinct opcodes, and their execution sequence) can still be
studied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class OpcodeSpec:
    mnemonic: str
    operand_size: int = 0  # bytes of immediate following the opcode
    kind: str = "misc"  # push | binop | unop | load | store | jump | halt | misc
    py_op: Optional[str] = None  # for binop/unop: '+', '-', '*', '&', ...
    signed: bool = False


@dataclass
class VMInstr:
    offset: int  # offset into the bytecode region
    opcode: int
    spec: OpcodeSpec
    operand: Optional[int] = None
    size: int = 1

    @property
    def mnemonic(self) -> str:
        return self.spec.mnemonic


@dataclass
class VMArchitecture:
    name: str
    opcodes: Dict[int, OpcodeSpec]
    opcode_size: int = 1
    endianness: str = "little"

    def decode_one(self, bytecode: bytes, offset: int) -> VMInstr:
        opcode = int.from_bytes(
            bytecode[offset : offset + self.opcode_size], self.endianness
        )
        spec = self.opcodes.get(opcode)
        if spec is None:
            raise KeyError(f"unknown opcode 0x{opcode:x} at offset 0x{offset:x}")
        operand = None
        size = self.opcode_size
        if spec.operand_size:
            raw = bytecode[
                offset + self.opcode_size : offset + self.opcode_size + spec.operand_size
            ]
            operand = int.from_bytes(raw, self.endianness, signed=spec.signed)
            size += spec.operand_size
        return VMInstr(offset=offset, opcode=opcode, spec=spec, operand=operand, size=size)

    def disassemble(self, bytecode: bytes, start: int = 0) -> List[VMInstr]:
        """Linearly disassemble the bytecode into virtual instructions."""
        out: List[VMInstr] = []
        offset = start
        while offset < len(bytecode):
            instr = self.decode_one(bytecode, offset)
            out.append(instr)
            offset += instr.size
            if instr.spec.kind == "halt":
                break
        return out


@dataclass
class HandlerClass:
    """A group of recovered handler bodies that share a fingerprint."""

    label: str
    fingerprint: Tuple
    occurrences: int = 0
    example_vpcs: List[int] = field(default_factory=list)


def classify_handlers(vinstrs, dispatcher: int) -> Tuple[Dict[Tuple, HandlerClass], List[str]]:
    """Group recovered virtual instructions by handler fingerprint.

    Returns a mapping ``fingerprint -> HandlerClass`` and the per-virtual-
    instruction sequence of class labels (the recovered "opcode" stream).
    """
    classes: Dict[Tuple, HandlerClass] = {}
    sequence: List[str] = []
    next_id = 0
    for vi in vinstrs:
        fp = tuple(sorted({a - dispatcher for a in vi.native_addresses}))
        cls = classes.get(fp)
        if cls is None:
            label = f"op_{chr(ord('A') + next_id)}" if next_id < 26 else f"op_{next_id}"
            cls = HandlerClass(label=label, fingerprint=fp)
            classes[fp] = cls
            next_id += 1
        cls.occurrences += 1
        cls.example_vpcs.append(vi.vpc)
        sequence.append(cls.label)
    return classes, sequence


# --- Example specification matching tests/_vm_fixture.py --------------------
STACK_VM_EXAMPLE = VMArchitecture(
    name="example-stack-vm",
    opcodes={
        0x01: OpcodeSpec("PUSH", operand_size=4, kind="push"),
        0x02: OpcodeSpec("ADD", kind="binop", py_op="+"),
        0x03: OpcodeSpec("SUB", kind="binop", py_op="-"),
        0x04: OpcodeSpec("MUL", kind="binop", py_op="*"),
        0x05: OpcodeSpec("HALT", kind="halt"),
    },
)
