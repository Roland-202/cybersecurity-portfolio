"""Core data models shared by parsers, checks and reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

PortRange = tuple[int, int]


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
class Rule:
    """A vendor-neutral firewall rule (one ACE or one iptables rule)."""

    vendor: str
    container: str          # ACL name or iptables chain
    index: int              # 1-based position inside the container
    line_no: int            # line number in the source file
    raw: str
    action: str             # "permit" | "deny"
    protocol: str = "ip"
    src: str = "any"        # "any" or CIDR
    dst: str = "any"
    src_ports: list[PortRange] = field(default_factory=list)   # [] == any
    dst_ports: list[PortRange] = field(default_factory=list)
    direction: str = "unknown"   # "in" | "out" | "unknown"
    log: bool = False
    established: bool = False
    icmp_type: str = ""
    complex: bool = False   # has match conditions we do not model (iface, limit...)

    @property
    def is_permit(self) -> bool:
        return self.action == "permit"

    @property
    def all_protocols(self) -> bool:
        return self.protocol in ("ip", "all", "any")


@dataclass
class ParsedConfig:
    vendor: str
    source: str
    rules: list[Rule] = field(default_factory=list)
    policies: dict[str, str] = field(default_factory=dict)            # chain -> ACCEPT/DROP
    bindings: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # acl -> [(where, dir)]
    logged_containers: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)

    def containers(self) -> dict[str, list[Rule]]:
        grouped: dict[str, list[Rule]] = {}
        for rule in self.rules:
            grouped.setdefault(rule.container, []).append(rule)
        return grouped


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    references: list[str]
    rule: Optional[Rule] = None
    container: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "remediation": self.remediation,
            "references": self.references,
            "container": self.rule.container if self.rule else self.container,
            "line": self.rule.line_no if self.rule else None,
            "rule": self.rule.raw.strip() if self.rule else None,
        }
