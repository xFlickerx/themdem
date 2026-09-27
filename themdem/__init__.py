"""themdem -- an educational Themida/WinLicense/Code Virtualizer mutation deobfuscator.

The package builds a small, self-contained pipeline on top of Capstone
(disassembly), Keystone (assembly) and Unicorn (semantic validation). It takes
mutation-obfuscated x86 (32-bit) code, strips the junk instructions inserted by
the protector's *mutation* engine, and reassembles semantically-equivalent,
human-readable code.

This is a research/education tool for analysing software you are authorised to
analyse (your own binaries, CTF challenges, malware in a lab, ...).

Public API
----------
``Deobfuscator``
    High-level engine that disassembles a region, runs the simplification
    passes, and hands back the simplified instructions plus stats.
``PEDeobfuscator``
    Wraps ``Deobfuscator`` with LIEF-based PE loading and in-place rewriting.
"""

from .core import Deobfuscator, SimplificationResult

__all__ = ["Deobfuscator", "SimplificationResult", "PEDeobfuscator"]

__version__ = "0.1.0"


def __getattr__(name: str):  # lazy import so `lief` stays optional for raw mode
    if name == "PEDeobfuscator":
        from .pe import PEDeobfuscator

        return PEDeobfuscator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
