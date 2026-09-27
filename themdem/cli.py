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
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
