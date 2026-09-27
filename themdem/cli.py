"""Command-line interface for themdem."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .core import Deobfuscator


def _parse_int(value: str) -> int:
    return int(value, 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="themdem",
        description="Educational Themida/WinLicense/Code Virtualizer mutation "
        "deobfuscator (x86, 32-bit).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # -- pe ------------------------------------------------------------------
    pe = sub.add_parser(
        "pe",
        help="Deobfuscate mutated functions inside a 32-bit PE and rewrite them.",
    )
    pe.add_argument("binary", help="Path to the protected PE file.")
    pe.add_argument(
        "-a",
        "--addresses",
        nargs="+",
        required=True,
        type=_parse_int,
        metavar="VA",
        help="Virtual addresses of the mutated functions (e.g. 0x401000).",
    )
    pe.add_argument("-o", "--output", help="Where to write the rewritten PE.")
    pe.add_argument(
        "--max-size",
        type=_parse_int,
        default=0x2000,
        help="Max bytes to sweep per function (default: 0x2000).",
    )
    pe.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Only print the simplified listing; do not write a file.",
    )
    pe.add_argument("-v", "--verbose", action="store_true", help="Print pass reduction stats.")

    # -- raw -----------------------------------------------------------------
    raw = sub.add_parser(
        "raw",
        help="Deobfuscate a flat blob of machine code (no PE container).",
    )
    raw.add_argument("blob", help="Path to a file containing raw x86 machine code.")
    raw.add_argument(
        "-b",
        "--base",
        type=_parse_int,
        default=0x0,
        help="Base address the blob is assumed to load at (default: 0).",
    )
    raw.add_argument(
        "-o",
        "--output",
        help="Write the simplified machine code to this file.",
    )
    raw.add_argument(
        "--no-keep-terminator",
        action="store_true",
        help="Also simplify the trailing branch instead of preserving it.",
    )
    raw.add_argument("-v", "--verbose", action="store_true", help="Print pass reduction stats.")

    # -- detect --------------------------------------------------------------
    det = sub.add_parser(
        "detect",
        help="Statically detect Themida/WinLicense protection and VM bytecode "
        "regions in a PE.",
    )
    det.add_argument("binary", help="Path to the PE file.")

    # -- devirt --------------------------------------------------------------
    dv = sub.add_parser(
        "devirt",
        help="Analyse a virtualized function: recover VPC-sensitive CFG, "
        "classify handlers, and (with a VM spec) disassemble + lift it.",
    )
    dv.add_argument("binary", help="Path to the PE file (or use --raw-segment).")
    dv.add_argument(
        "--vm-entry",
        type=_parse_int,
        required=True,
        metavar="VA",
        help="Virtual address where the VM interpreter starts.",
    )
    dv.add_argument(
        "--bytecode",
        required=True,
        metavar="START:SIZE",
        help="VM bytecode region as VA:size, e.g. 0x500000:0x40.",
    )
    dv.add_argument(
        "--reg",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Initial register value, e.g. --reg esi=0x500000 (repeatable).",
    )
    dv.add_argument(
        "--arch",
        choices=["example"],
        help="Named VM architecture spec to disassemble with. Omit for "
        "structure-only recovery (handler classification).",
    )
    dv.add_argument(
        "--max-steps", type=_parse_int, default=200_000, help="Emulation step budget."
    )
    dv.add_argument("--dot", help="Write the recovered CFG to this Graphviz .dot file.")

    return parser


def _run_pe(args: argparse.Namespace) -> int:
    from .pe import PEDeobfuscator  # local import so `raw` works without lief errors

    deob = PEDeobfuscator(args.binary)
    if args.dry_run:
        for va in args.addresses:
            result = deob.simplify_function(va, max_size=args.max_size, profile=args.verbose)
            _print_result(va, result)
        return 0

    reports = deob.rewrite(args.addresses, max_size=args.max_size, profile=args.verbose)
    for report in reports:
        _print_result(report.address, report.result)

    if not args.output:
        print(
            "\n[!] No --output given; simplified code was not written to disk.",
            file=sys.stderr,
        )
        return 0

    deob.save(args.output)
    print(f"\n[+] Rewritten PE written to {args.output}")
    return 0


def _run_raw(args: argparse.Namespace) -> int:
    with open(args.blob, "rb") as fh:
        data = fh.read()

    engine = Deobfuscator()
    result = engine.simplify(
        data,
        args.base,
        keep_terminator=not args.no_keep_terminator,
        profile=args.verbose,
    )
    _print_result(args.base, result)

    if args.output:
        with open(args.output, "wb") as fh:
            fh.write(result.simplified_bytes)
        print(f"\n[+] Simplified machine code written to {args.output}")
    return 0


def _run_detect(args: argparse.Namespace) -> int:
    from .devirt import analyze

    result = analyze(args.binary)
    print(result.summary())
    return 0


def _run_devirt(args: argparse.Namespace) -> int:
    from .devirt import Devirtualizer, Range

    start_str, _, size_str = args.bytecode.partition(":")
    if not size_str:
        raise ValueError("--bytecode must be START:SIZE, e.g. 0x500000:0x40")
    start = int(start_str, 0)
    size = int(size_str, 0)
    bytecode = Range(start, start + size)

    reg_init = {}
    for item in args.reg:
        name, _, value = item.partition("=")
        if not value:
            raise ValueError(f"--reg expects NAME=VALUE, got {item!r}")
        reg_init[name.strip().lower()] = int(value, 0)

    arch = None
    if args.arch == "example":
        from .devirt import STACK_VM_EXAMPLE

        arch = STACK_VM_EXAMPLE

    deob = Devirtualizer.from_pe(args.binary, arch=arch, reg_init=reg_init)
    result = deob.run(args.vm_entry, bytecode, max_steps=args.max_steps)
    print(result.report())

    if args.dot:
        with open(args.dot, "w") as fh:
            fh.write(result.cfg.to_dot())
        print(f"\n[+] CFG written to {args.dot}")
    return 0


def _print_result(va: int, result) -> None:
    print(f"\n=== function 0x{va:08x} ===")
    print("--- before ---")
    print(result.format_listing(simplified=False))
    print("--- after ---")
    print(result.format_listing())
    if result.terminator is not None:
        t = result.terminator
        print(f"(terminator kept: {t.mnemonic} {t.op_str})".rstrip())
    print(
        f"[+] {len(result.original_instructions)} -> "
        f"{len(result.simplified_instructions)} instructions "
        f"({result.reduction} removed)"
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "pe":
            return _run_pe(args)
        if args.command == "raw":
            return _run_raw(args)
        if args.command == "detect":
            return _run_detect(args)
        if args.command == "devirt":
            return _run_devirt(args)
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
