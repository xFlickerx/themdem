"""PE loading and in-place rewriting via LIEF.

This drives :class:`~themdem.core.Deobfuscator` over functions inside a PE
image and rewrites the mutated bodies with simplified code. The mutated body is
overwritten and NOP-padded up to (but not including) the region's terminating
branch, which is left untouched so that relative targets remain valid.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import lief

from .core import Deobfuscator, SimplificationResult

# x86 `NOP`
_NOP = 0x90


@dataclass
class PatchReport:
    address: int
    result: SimplificationResult
    patched_bytes: int


class PEDeobfuscator:
    """Simplify mutated functions inside a 32-bit PE and rewrite them in place."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.pe = lief.PE.parse(path)
        if self.pe is None:
            raise ValueError(f"Failed to parse PE: {path!r}")
        self.image_base = self.pe.imagebase
        self.engine = Deobfuscator()

    # -- section helpers -----------------------------------------------------
    def _section_for_va(self, va: int) -> Optional["lief.PE.Section"]:
        rva = va - self.image_base
        for s in self.pe.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.size):
                return s
        return None

    def read_va(self, va: int, size: int) -> bytes:
        """Read ``size`` bytes of file content at virtual address ``va``."""
        section = self._section_for_va(va)
        if section is None:
            raise ValueError(f"No section contains VA 0x{va:x}")
        offset = va - self.image_base - section.virtual_address
        content = bytes(section.content)
        return content[offset : offset + size]

    # -- simplification ------------------------------------------------------
    def simplify_function(
        self,
        va: int,
        max_size: int = 0x2000,
        profile: bool = False,
    ) -> SimplificationResult:
        """Disassemble the mutated region at ``va`` and simplify it.

        ``max_size`` bounds how many bytes are read for the linear sweep; the
        engine stops the simplified body at the first terminating branch.
        """
        data = self.read_va(va, max_size)
        return self.engine.simplify(data, va, keep_terminator=True, profile=profile)

    # -- rewriting -----------------------------------------------------------
    def rewrite(
        self,
        addresses: List[int],
        max_size: int = 0x2000,
        profile: bool = False,
    ) -> List[PatchReport]:
        """Simplify each function and overwrite its mutated body in place.

        The simplified body must not be larger than the original body; because
        de-mutation only removes instructions this always holds. The remaining
        space up to the terminator is filled with NOPs.
        """
        reports: List[PatchReport] = []
        for va in addresses:
            result = self.simplify_function(va, max_size=max_size, profile=profile)
            body_size = sum(i.size for i in result.original_instructions)
            simplified_body = b"".join(i.bytes for i in result.simplified_instructions)
            if len(simplified_body) > body_size:
                raise RuntimeError(
                    f"Simplified body for 0x{va:x} is larger than original "
                    f"({len(simplified_body)} > {body_size}); refusing to patch."
                )
            # NOP-pad up to the terminator, which stays in place untouched.
            patch = simplified_body + bytes([_NOP] * (body_size - len(simplified_body)))

            section = self._section_for_va(va)
            assert section is not None
            offset = va - self.image_base - section.virtual_address
            content = bytearray(section.content)
            content[offset : offset + len(patch)] = patch
            section.content = memoryview(content)

            reports.append(PatchReport(address=va, result=result, patched_bytes=len(patch)))

        return reports

    def save(self, output_path: str) -> None:
        # LIEF >= 1.0 requires an explicit builder config; older releases take
        # just the binary. Support both.
        try:
            builder = lief.PE.Builder(self.pe, lief.PE.Builder.config_t())
        except TypeError:
            builder = lief.PE.Builder(self.pe)
        builder.build()
        builder.write(output_path)
