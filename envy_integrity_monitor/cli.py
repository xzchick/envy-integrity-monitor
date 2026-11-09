"""Command-line entry point. The Integrity Monitor window is the default.

Checks are read-only; accepting a new state writes a brand-new baseline revision
and never overwrites the previous one.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import __version__
from .core import IntegrityError, accept, check, check_passphrase, create, export, inspect


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="envy-integrity-monitor",
        description="Encrypted file-integrity baselines with change detection. Baseline a folder, then "
                    "check what has been added, removed or modified since. Run with no arguments to open "
                    "the window. Local only: no network, no accounts.")
    root.add_argument("--version", action="version", version=f"envy-integrity-monitor {__version__}")
    commands = root.add_subparsers(dest="command")
    commands.add_parser("gui", help="open the Integrity Monitor window (default)")

    new = commands.add_parser("baseline", help="create an encrypted baseline of a folder")
    new.add_argument("destination", help="a new baseline file; never overwritten")
    new.add_argument("folder", help="the folder to monitor")
    new.add_argument("--title", required=True, help="a name for this monitor")
    new.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                     help="skip paths matching this glob; stored in the baseline and applied to every "
                          "check and accept (repeatable, .gitignore-style)")

    chk = commands.add_parser("check", help="report changes since the baseline (read-only)")
    chk.add_argument("baseline")
    chk.add_argument("--folder", default=None, help="override the stored root folder")
    chk.add_argument("--json", action="store_true", help="emit the full change report as JSON")
    chk.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                     help="skip paths matching this glob (repeatable, .gitignore-style)")

    acc = commands.add_parser("accept", help="record the current state as a new baseline revision")
    acc.add_argument("baseline")
    acc.add_argument("destination", help="a new baseline file; never overwritten")
    acc.add_argument("--folder", default=None)
    acc.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                     help="add a glob to the baseline's stored ignore list (repeatable)")

    insp = commands.add_parser("inspect", help="print the decrypted baseline and journal (read-only)")
    insp.add_argument("baseline")

    exp = commands.add_parser("export", help="write a plaintext HTML or JSON change report")
    exp.add_argument("baseline")
    exp.add_argument("destination", help="a new report file; never overwritten")
    exp.add_argument("--format", default="html", choices=("html", "json", "md"))
    exp.add_argument("--folder", default=None)
    return root


def _passphrase(confirm: bool = False) -> bytes:
    if not sys.stdin.isatty():
        raise IntegrityError("Open this action in a terminal so the passphrase is not echoed")
    value = getpass.getpass("Baseline passphrase: ").encode()
    if confirm and value != getpass.getpass("Repeat passphrase: ").encode():
        raise IntegrityError("Passphrases do not match")
    return check_passphrase(value)


def _run(args) -> int:
    if args.command == "baseline":
        result = create(args.destination, args.title, args.folder, _passphrase(confirm=True), ignore=args.ignore)
        ig = f" (ignoring {len(result['ignore'])} glob(s))" if result["ignore"] else ""
        print(f"baseline: {result['baselined_files']} files → {result['output']} (revision 0){ig}")
        return 0
    if args.command == "check":
        report = check(args.baseline, _passphrase(), args.folder, ignore=args.ignore)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report["clean"] else 1
        print(f"check: +{len(report['added'])} added, -{len(report['removed'])} removed, "
              f"~{len(report['modified'])} modified, {report['unchanged']} unchanged")
        print("CLEAN" if report["clean"] else f"{report['changed']} change(s) since the baseline")
        return 0 if report["clean"] else 1
    if args.command == "accept":
        result = accept(args.baseline, args.destination, _passphrase(), args.folder, ignore=args.ignore)
        print(f"accepted → {result['output']} (revision {result['revision']})")
        return 0
    if args.command == "export":
        result = export(args.baseline, args.destination, _passphrase(), args.format, args.folder)
        print(f"export ({result['format']}): wrote {result['output']}  sha256 {result['sha256']}")
        return 0
    if args.command == "inspect":
        print(json.dumps(inspect(args.baseline, _passphrase()), indent=2, ensure_ascii=False))
        return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in (None, "gui"):
        from .gui import run_app
        return run_app()
    try:
        return _run(args)
    except IntegrityError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
