"""Data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .fingerprint import Fingerprint


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class PortResult:
    port: int
    service: str = "unknown"
    product: str = ""
    version: str = ""
    banner: str = ""
    probe: str = ""            # "passive" | "http" | "redis" | ...
    tls: bool = False
    tls_version: str = ""
    fp: Fingerprint = field(default_factory=Fingerprint)

    @property
    def display(self) -> str:
        return f"{self.fp.display} {self.version}".strip()

    def to_dict(self) -> dict:
        return {"port": self.port, "state": "open", "service": self.service, "product": self.product,
                "version": self.version, "tls": self.tls, "tls_version": self.tls_version,
                "probe": self.probe, "banner": self.banner}


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    ports: list[PortResult] = field(default_factory=list)   # open ports only
    closed: int = 0
    filtered: int = 0

    @property
    def up(self) -> bool:
        return bool(self.ports) or self.closed > 0

    def to_dict(self) -> dict:
        return {"address": self.address, "hostname": self.hostname, "up": self.up, "closed": self.closed,
                "filtered": self.filtered, "open_ports": [p.to_dict() for p in self.ports]}


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: Severity
    host: str
    port: int
    description: str
    remediation: str
    confidence: str = "medium"      # high | medium | low
    references: list[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> dict:
        return {"id": self.finding_id, "title": self.title, "severity": self.severity.label, "host": self.host,
                "port": self.port, "confidence": self.confidence, "description": self.description,
                "remediation": self.remediation, "references": self.references, "evidence": self.evidence}


@dataclass
class ScanResult:
    hosts: list[HostResult]
    findings: list[Finding]
    ports_scanned: int
    started: str = ""
    finished: str = ""

    @property
    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)
