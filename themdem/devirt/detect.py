"""Static detection of Themida/WinLicense protection and VM bytecode regions.

Everything here is *static analysis* (classification + entropy scanning) over a
PE image — it never runs the target. The version/section heuristics follow the
public knowledge encoded in tools like ``unlicense`` and ``Detect It Easy``; the
bytecode-region scan follows the entropy/indexing intuition described by
VMDoctor and Pushan (VM bytecode lives in high-entropy, read-mostly regions).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional

import lief

# Section names used by Themida/WinLicense 3.x.
_TH3_SECTIONS = {".themida", ".winlice", ".boot"}

# Import fingerprint of Themida/WinLicense 2.x (see unlicense).
_TH2_MODS = {"kernel32.dll", "comctl32.dll"}
_TH2_FUNCS = {"lstrcpy", "initcommoncontrols"}

# Byte stubs that appear at the start of a Themida/WinLicense 2.x section.
_TH2_STUBS = [
    bytes([0x56, 0x50, 0x53, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xCC, 0x58]),
    bytes([0x83, 0xEC, 0x04, 0x50, 0x53, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xCC, 0x58]),
]


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy (bits/byte, 0..8) of ``data``."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


@dataclass
class SectionInfo:
    name: str
    virtual_address: int  # RVA
    virtual_size: int
    raw_size: int
    entropy: float
    executable: bool
    readable: bool
    writable: bool

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + max(
            self.virtual_size, self.raw_size
        )


@dataclass
class BytecodeRegion:
    """A candidate VM bytecode region (high entropy, read-mostly)."""

    section: str
    rva: int
    size: int
    entropy: float


@dataclass
class DetectionResult:
    version: Optional[int]  # 2, 3, or None
    is_themida: bool
    sections: List[SectionInfo] = field(default_factory=list)
    vm_sections: List[str] = field(default_factory=list)
    bytecode_candidates: List[BytecodeRegion] = field(default_factory=list)

    def summary(self) -> str:
        lines = []
        label = f"Themida/WinLicense {self.version}.x" if self.version else "unknown"
        lines.append(f"protection: {label} (is_themida={self.is_themida})")
        lines.append("sections:")
        for s in self.sections:
            flags = "".join(
                [
                    "r" if s.readable else "-",
                    "w" if s.writable else "-",
                    "x" if s.executable else "-",
                ]
            )
            mark = "  <- VM" if s.name in self.vm_sections else ""
            lines.append(
                f"  {s.name:<10} rva=0x{s.virtual_address:08x} "
                f"size=0x{s.virtual_size:06x} {flags} H={s.entropy:.2f}{mark}"
            )
        if self.bytecode_candidates:
            lines.append("bytecode candidates:")
            for r in self.bytecode_candidates:
                lines.append(
                    f"  {r.section} rva=0x{r.rva:08x} size=0x{r.size:x} H={r.entropy:.2f}"
                )
        return "\n".join(lines)


def _section_infos(pe: "lief.PE.Binary") -> List[SectionInfo]:
    infos: List[SectionInfo] = []
    C = lief.PE.Section.CHARACTERISTICS
    for s in pe.sections:
        content = bytes(s.content)
        chars = s.characteristics
        infos.append(
            SectionInfo(
                name=s.name,
                virtual_address=s.virtual_address,
                virtual_size=s.virtual_size or s.size,
                raw_size=s.size,
                entropy=shannon_entropy(content),
                executable=bool(chars & C.MEM_EXECUTE.value),
                readable=bool(chars & C.MEM_READ.value),
                writable=bool(chars & C.MEM_WRITE.value),
            )
        )
    return infos


def detect_version(pe: "lief.PE.Binary", sections: List[SectionInfo]) -> Optional[int]:
    names = {s.name.lower() for s in sections}
    if names & _TH3_SECTIONS:
        return 3

    # 2.x import fingerprint.
    try:
        imported_mods = {imp.name.lower() for imp in pe.imports}
        imported_funcs = {fn.name.lower() for fn in pe.imported_functions if fn.name}
        if (
            len(imported_mods) <= 2
            and imported_mods <= _TH2_MODS
            and imported_funcs & _TH2_FUNCS
        ):
            return 2
    except Exception:
        pass

    # 2.x byte stubs at section starts.
    for s in pe.sections:
        head = bytes(s.content[: max(len(p) for p in _TH2_STUBS)])
        for stub in _TH2_STUBS:
            if head.startswith(stub):
                return 2

    return None


def find_bytecode_regions(
    sections: List[SectionInfo],
    min_entropy: float = 6.5,
) -> List[BytecodeRegion]:
    """Heuristically pick read-mostly, high-entropy sections as bytecode.

    Real VM bytecode is dense/high-entropy and typically lives in a
    non-executable (or read-only) region that the interpreter indexes. We rank
    readable, high-entropy, ideally-non-executable sections.
    """
    regions: List[BytecodeRegion] = []
    for s in sections:
        if not s.readable:
            continue
        if s.entropy < min_entropy:
            continue
        # Prefer data-like regions; still allow exec sections (Themida mixes them).
        regions.append(
            BytecodeRegion(
                section=s.name,
                rva=s.virtual_address,
                size=s.virtual_size,
                entropy=s.entropy,
            )
        )
    # Non-executable regions first, then by entropy.
    exec_names = {s.name for s in sections if s.executable}
    regions.sort(key=lambda r: (r.section in exec_names, -r.entropy))
    return regions


def analyze(pe_path: str) -> DetectionResult:
    """Run all static detectors over a PE file."""
    pe = lief.PE.parse(pe_path)
    if pe is None:
        raise ValueError(f"Failed to parse PE: {pe_path!r}")

    sections = _section_infos(pe)
    version = detect_version(pe, sections)
    vm_sections = [s.name for s in sections if s.name.lower() in _TH3_SECTIONS]
    bytecode = find_bytecode_regions(sections)

    return DetectionResult(
        version=version,
        is_themida=version is not None or bool(vm_sections),
        sections=sections,
        vm_sections=vm_sections,
        bytecode_candidates=bytecode,
    )
