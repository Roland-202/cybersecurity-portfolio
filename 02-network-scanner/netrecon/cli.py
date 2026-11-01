"""Command-line interface."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import __version__
from .engine import run_scan
from .models import Severity
from .ports import parse_ports
from .report import render_console, render_html, render_json
from .targets import ScopeError, expand_targets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netrecon", description="Async TCP service mapper and banner-based vulnerability scanner.")
    p.add_argument("--version", action="version", version=f"netrecon {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan targets")
    s.add_argument("targets", nargs="+", help="IP, CIDR, 10.0.0.5-20, hostname, or @file")
    s.add_argument("-p", "--ports", default="top", help="'top', 'all', or e.g. 22,80,8000-8100 (default: top)")
    s.add_argument("--timeout", type=float, default=1.5, help="connect timeout in seconds")
    s.add_argument("--concurrency", type=int, default=300, help="parallel connections (max 2000)")
    s.add_argument("--max-hosts", type=int, default=256)
    s.add_argument("--no-banner", action="store_true", help="port scan only; skip fingerprinting")
    s.add_argument("--i-have-written-authorization", dest="authorized", action="store_true",
                   help="required to scan publicly routable addresses")
    s.add_argument("-f", "--format", choices=["console", "json", "html"], default="console")
    s.add_argument("-o", "--output")
    s.add_argument("--fail-on", choices=[x.name.lower() for x in Severity])
    s.add_argument("--no-color", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ports = parse_ports(args.ports)
        targets = expand_targets(args.targets, args.max_hosts, args.authorized)
    except ScopeError as exc:
        print(f"netrecon: refused: {exc}", file=sys.stderr)
        return 3
    except (OSError, ValueError) as exc:
        print(f"netrecon: error: {exc}", file=sys.stderr)
        return 2

    print(f"netrecon: scanning {len(targets)} host(s) x {len(ports)} port(s). Only scan systems you are authorised to test.",
          file=sys.stderr)
    progress = lambda done, total: print(f"  ... {done}/{total} probes", file=sys.stderr)  # noqa: E731
    result = asyncio.run(run_scan(targets, ports, timeout=args.timeout, concurrency=min(args.concurrency, 2000),
                                  banners=not args.no_banner, progress=progress))

    if args.format == "json":
        text = render_json(result)
    elif args.format == "html":
        text = render_html(result)
    else:
        text = render_console(result, color=not args.no_color and not args.output and sys.stdout.isatty())
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        try:
            print(text)
            sys.stdout.flush()
        except BrokenPipeError:
            sys.stderr.close()

    worst = result.worst()
    if args.fail_on and worst is not None and worst >= Severity.parse(args.fail_on):
        return 1
    return 0
