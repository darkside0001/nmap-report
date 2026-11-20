from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .diff import diff
from .parser import parse_file
from .report import to_html, to_json, to_markdown, to_text
from .rules import SEVERITY_ORDER, assess


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="nmap-report",
        description="Turn nmap XML (-oX) into a readable report, flag risky services and compare scans.")
    p.add_argument("scan", help="nmap XML file")
    p.add_argument("--diff", metavar="OLD_XML", help="compare against an older scan of the same network")
    p.add_argument("-f", "--format", choices=["text", "markdown", "html", "json"], default="text")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low", help="hide risks below this level")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                   help="exit 1 if a risk at this level or above is found, or (with --diff) a new port opened")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    try:
        scan = parse_file(args.scan)
        old = parse_file(args.diff) if args.diff else None
    except FileNotFoundError as e:
        print(f"error: {e.filename}: file not found", file=sys.stderr)
        return 2
    except ValueError as e:  # includes XML ParseError and UnsafeXML
        print(f"error: {e}", file=sys.stderr)
        return 2

    limit = SEVERITY_ORDER[args.min_severity]
    risks = [r for r in assess(scan.hosts) if SEVERITY_ORDER[r.rule.severity] <= limit]
    d = diff(old, scan) if old else None

    if args.format == "text":
        text = to_text(scan, risks, d)
    elif args.format == "markdown":
        text = to_markdown(scan, risks, d)
    elif args.format == "html":
        text = to_html(scan, risks, d)
    else:
        text = to_json(scan, risks, d)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")

    if args.fail_on:
        lvl = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[r.rule.severity] <= lvl for r in risks) or (d and (d.opened or d.new_hosts)):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
