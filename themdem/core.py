"""Core disassemble -> simplify -> reassemble engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from capstone import (
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_32,
    Cs,
    CsInsn,
)
from keystone import KS_ARCH_X86, KS_MODE_32, Ks

from passes import AllPass

# Instruction groups that end a straight-line (mutated) code region. Themida's
# mutation engine works on the linear body of a basic block; the terminating
# branch/return marks the boundary of what we should simplify.
_TERMINATOR_GROUPS = (CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET)


@dataclass
class SimplificationResult:
    """Outcome of simplifying a single code region."""

    address: int
    original_instructions: List[CsInsn]
    simplified_instructions: List[CsInsn]
    #: Bytes of the simplified body (terminator included when it was kept).
    simplified_bytes: bytes
    #: The trailing control-flow instruction that was preserved verbatim, if any.
    terminator: Optional[CsInsn] = None
    stats: dict = field(default_factory=dict)

    @property
    def original_size(self) -> int:
        return sum(i.size for i in self.original_instructions) + (
            self.terminator.size if self.terminator is not None else 0
        )

    @property
    def simplified_size(self) -> int:
        return len(self.simplified_bytes)

    @property
    def reduction(self) -> int:
        """Number of instructions removed by simplification."""
        orig = len(self.original_instructions)
        new = len(self.simplified_instructions)
        return orig - new

    def format_listing(self, simplified: bool = True) -> str:
        insns = self.simplified_instructions if simplified else self.original_instructions
        lines = [f"0x{i.address:08x}:  {i.mnemonic} {i.op_str}".rstrip() for i in insns]
        return "\n".join(lines)


class Deobfuscator:
    """Simplify Themida-style *mutated* x86 code.

    The engine is deliberately architecture-narrow (x86, 32-bit): the bundled
    passes and the Unicorn-based validator both assume 32-bit semantics, which
    matches Themida/WinLicense/Code Virtualizer's mutation output.
    """

    def __init__(self) -> None:
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.pipeline = AllPass(self.md, self.ks)

    # -- disassembly ---------------------------------------------------------
    def disassemble(self, data: bytes, address: int) -> List[CsInsn]:
        """Linearly disassemble ``data`` starting at ``address``."""
        return list(self.md.disasm(data, address))

    @staticmethod
    def _is_terminator(insn: CsInsn) -> bool:
        return any(insn.group(g) for g in _TERMINATOR_GROUPS)

    # -- simplification ------------------------------------------------------
    def simplify(
        self,
        data: bytes,
        address: int,
        keep_terminator: bool = True,
        profile: bool = False,
    ) -> SimplificationResult:
        """Disassemble ``data`` at ``address`` and remove mutation junk.

        The trailing control-flow instruction (``jmp``/``call``/``ret``) is, by
        default, split off and preserved verbatim so that relative branch
        targets stay valid; only the linear body is rewritten. This mirrors how
        a mutated basic block should be patched back into a binary.
        """
        insns = self.disassemble(data, address)
        if not insns:
            raise ValueError(f"No instructions decoded at 0x{address:x}")

        terminator: Optional[CsInsn] = None
        body = insns
        if keep_terminator and self._is_terminator(insns[-1]):
            terminator = insns[-1]
            body = insns[:-1]

        # AllPass mutates and returns a sanitised list; work on a copy so the
        # caller's `original_instructions` stay intact.
        simplified_body = self.pipeline(list(body), profile=profile)

        simplified_bytes = b"".join(i.bytes for i in simplified_body)
        simplified_all = list(simplified_body)
        if terminator is not None:
            simplified_bytes += terminator.bytes
            simplified_all.append(terminator)

        stats = {
            "instructions_before": len(body),
            "instructions_after": len(simplified_body),
            "bytes_before": sum(i.size for i in body),
            "bytes_after": len(b"".join(i.bytes for i in simplified_body)),
        }

        return SimplificationResult(
            address=address,
            original_instructions=list(body),
            simplified_instructions=simplified_body,
            simplified_bytes=simplified_bytes,
            terminator=terminator,
            stats=stats,
        )
