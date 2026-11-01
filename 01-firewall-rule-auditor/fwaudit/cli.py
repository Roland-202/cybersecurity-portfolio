"""Command-line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .models import ParsedConfig, Severity
from .parsers import cisco, iptables
from .report import render_console, render_html, render_json

PARSERS = {"cisco": cisco.parse, "iptables": iptables.parse}


def detect_vendor(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines()]
    if any(ln.startswith(("*filter", "-A ", "-P ", ":INPUT", ":FORWARD")) or ln.startswith("iptables ") for ln in lines):
        return "iptables"
    if any(ln.lower().startswith(("ip access-list", "access-list ")) for ln in lines):
        return "cisco"
    raise ValueError("could not auto-detect vendor; pass --vendor cisco|iptables")


def load(path: str, vendor: str = "auto") -> ParsedConfig:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    vendor = detect_vendor(text) if vendor == "auto" else vendor
    return PARSERS[vendor](text, source=Path(path).name)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fwaudit", description="Audit firewall rule sets for risky misconfigurations.")
    p.add_argument("--version", action="version", version=f"fwaudit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit", help="audit a configuration file")
    a.add_argument("file")
    a.add_argument("--vendor", choices=["auto", *PARSERS], default="auto")
    a.add_argument("-f", "--format", choices=["console", "json", "html"], default="console")
    a.add_argument("-o", "--output", help="write report to this file instead of stdout")
    a.add_argument("--fail-on", choices=[s.name.lower() for s in Severity], default=None,
                   help="exit 1 if any finding at or above this severity exists (for CI gates)")
    a.add_argument("--no-color", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = analyze(load(args.file, args.vendor))
    except (OSError, ValueError) as exc:
        print(f"fwaudit: error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        text = render_json(result)
    elif args.format == "html":
        text = render_html(result)
    else:
        color = not args.no_color and not args.output and sys.stdout.isatty()
        text = render_console(result, color=color)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Report written to {args.output} (score {result.score}/100, grade {result.grade})")
    else:
        try:
            print(text)
            sys.stdout.flush()
        except BrokenPipeError:                  # e.g. `fwaudit audit x | head`
            sys.stderr.close()

    if args.fail_on:
        worst = result.worst()
        if worst is not None and worst >= Severity.parse(args.fail_on):
            return 1
    return 0
