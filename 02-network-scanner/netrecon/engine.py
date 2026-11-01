"""Orchestrates scan -> banner grab -> fingerprint -> findings."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Callable

from .banner import grab
from .findings import exposure_findings, vuln_findings
from .fingerprint import Fingerprint
from .models import Finding, HostResult, PortResult, ScanResult
from .ports import SERVICE_BY_PORT
from .scanner import scan_ports
from .targets import Target
from .vulndb import load_db


def _printable(data: bytes, limit: int = 200) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit]).strip(".")


async def run_scan(targets: list[Target], ports: list[int], *, timeout: float = 1.5, concurrency: int = 300,
                   banners: bool = True, db: list[dict] | None = None,
                   progress: Callable[[int, int], None] | None = None) -> ScanResult:
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    db = db if db is not None else load_db()
    states = await scan_ports([t.address for t in targets], ports, timeout, concurrency, progress)

    hosts: dict[str, HostResult] = {}
    for t in targets:
        st = states[t.address]
        hosts[t.address] = HostResult(
            address=t.address, hostname=t.hostname,
            ports=[PortResult(port=p, service=SERVICE_BY_PORT.get(p, "unknown"))
                   for p, s in sorted(st.items()) if s == "open"],
            closed=sum(s == "closed" for s in st.values()),
            filtered=sum(s == "filtered" for s in st.values()))

    sem = asyncio.Semaphore(50)

    async def enrich(host: HostResult, pr: PortResult) -> None:
        async with sem:
            g = await grab(host.address, pr.port, timeout=max(timeout, 1.5), hostname=host.hostname)
        fp: Fingerprint = g["fp"]
        pr.fp, pr.probe, pr.tls, pr.tls_version = fp, g["probe"], g["tls"], g["tls_version"]
        pr.banner = _printable(g["data"])
        if fp.service != "unknown":
            pr.service = fp.service
        pr.product, pr.version = fp.product, fp.version

    if banners:
        await asyncio.gather(*(enrich(h, p) for h in hosts.values() for p in h.ports))

    findings: list[Finding] = []
    for h in hosts.values():
        for pr in h.ports:
            findings += exposure_findings(h.address, pr)
            findings += vuln_findings(h.address, pr, db)
    findings.sort(key=lambda f: (-int(f.severity), f.host, f.port, f.finding_id))
    return ScanResult(hosts=list(hosts.values()), findings=findings,
                      ports_scanned=len(ports) * len(targets), started=started,
                      finished=datetime.now(timezone.utc).isoformat(timespec="seconds"))
