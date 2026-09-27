"""Build a minimal, valid PE32 image in memory for tests.

LIEF's newer releases don't expose a ``Binary`` constructor, so we assemble a
bare-bones PE32 (DOS stub + PE headers + a single ``.text`` section) by hand.
The result is just valid enough for LIEF to parse and for us to exercise the
section read/patch paths.
"""

from __future__ import annotations

import struct

IMAGE_BASE = 0x400000
SECTION_RVA = 0x1000
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000


def build_pe32(code: bytes, entry_rva: int = SECTION_RVA) -> bytes:
    """Return the bytes of a minimal PE32 whose ``.text`` holds ``code``."""
    # --- section raw data (file-aligned) ---
    raw = code + b"\x00" * ((-len(code)) % FILE_ALIGN)
    virtual_size = len(code)

    # --- DOS header ---
    e_lfanew = 0x80
    dos = bytearray(b"\x00" * e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    # --- COFF file header ---
    machine = 0x14C  # IMAGE_FILE_MACHINE_I386
    num_sections = 1
    size_opt_hdr = 0xE0
    characteristics = 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE
    coff = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        size_opt_hdr,
        characteristics,
    )

    # --- optional header (PE32) ---
    headers_size = e_lfanew + 4 + len(coff) + size_opt_hdr + 40
    size_of_headers = headers_size + ((-headers_size) % FILE_ALIGN)
    ptr_to_raw = size_of_headers
    size_of_image = SECTION_RVA + (virtual_size + ((-virtual_size) % SECT_ALIGN))

    opt = bytearray(size_opt_hdr)
    struct.pack_into("<H", opt, 0, 0x10B)  # Magic PE32
    struct.pack_into("<I", opt, 16, entry_rva)  # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, SECTION_RVA)  # BaseOfCode
    struct.pack_into("<I", opt, 28, IMAGE_BASE)  # ImageBase
    struct.pack_into("<I", opt, 32, SECT_ALIGN)  # SectionAlignment
    struct.pack_into("<I", opt, 36, FILE_ALIGN)  # FileAlignment
    struct.pack_into("<H", opt, 40, 4)  # MajorOSVersion
    struct.pack_into("<H", opt, 48, 4)  # MajorSubsystemVersion
    struct.pack_into("<I", opt, 56, size_of_image)  # SizeOfImage
    struct.pack_into("<I", opt, 60, size_of_headers)  # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)  # Subsystem = CONSOLE
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes

    # --- section header ---
    sect = bytearray(40)
    sect[0:5] = b".text"
    struct.pack_into("<I", sect, 8, virtual_size)  # VirtualSize
    struct.pack_into("<I", sect, 12, SECTION_RVA)  # VirtualAddress
    struct.pack_into("<I", sect, 16, len(raw))  # SizeOfRawData
    struct.pack_into("<I", sect, 20, ptr_to_raw)  # PointerToRawData
    struct.pack_into("<I", sect, 36, 0x60000020)  # CODE | EXECUTE | READ

    image = bytearray()
    image += dos
    image += b"PE\x00\x00"
    image += coff
    image += opt
    image += sect
    image += b"\x00" * (size_of_headers - len(image))
    image += raw
    return bytes(image)
