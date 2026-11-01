"""Parser for iptables-save output and shell-style `iptables -A ...` scripts (filter table)."""
from __future__ import annotations

import shlex

from ..models import ParsedConfig, PortRange, Rule
from ..netutil import norm_net

SERVICES = {"ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "http": 80, "https": 443,
            "ftp": 21, "snmp": 161, "mysql": 3306, "postgresql": 5432}
KNOWN_MODULES = {"tcp", "udp", "multiport", "state", "conntrack", "comment", "icmp"}
TARGETS = {"ACCEPT": "permit", "DROP": "deny", "REJECT": "deny"}
DIRECTIONS = {"INPUT": "in", "FORWARD": "in", "OUTPUT": "out"}


def _port(tok: str) -> int:
    tok = tok.lower()
    if tok.isdigit():
        return int(tok)
    if tok in SERVICES:
        return SERVICES[tok]
    raise ValueError(f"unknown port {tok!r}")


def _ports(value: str) -> list[PortRange]:
    out: list[PortRange] = []
    for part in value.split(","):
        if ":" in part:
            lo, hi = part.split(":", 1)
            out.append((_port(lo) if lo else 0, _port(hi) if hi else 65535))
        else:
            p = _port(part)
            out.append((p, p))
    return out


def parse(text: str, source: str = "<memory>") -> ParsedConfig:
    cfg = ParsedConfig(vendor="iptables", source=source)
    counters: dict[str, int] = {}
    table: str | None = None

    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            continue
        if line == "COMMIT":
            table = None
            continue
        if line.startswith(":"):
            parts = line[1:].split()
            if table in (None, "filter") and len(parts) >= 2 and parts[1] != "-":
                cfg.policies[parts[0]] = parts[1].upper()
            continue

        try:
            tokens = shlex.split(line, comments=True)
        except ValueError as exc:
            cfg.warnings.append(f"line {n}: unparseable ({exc})")
            continue
        if tokens and tokens[0] in ("iptables", "/sbin/iptables", "/usr/sbin/iptables"):
            tokens = tokens[1:]
            if tokens[:1] == ["-t"]:
                if tokens[1] != "filter":
                    continue
                tokens = tokens[2:]
        elif table not in (None, "filter"):
            continue
        if not tokens:
            continue
        if tokens[0] in ("-P", "--policy") and len(tokens) >= 3:
            cfg.policies[tokens[1]] = tokens[2].upper()
            continue
        if tokens[0] in ("-I", "--insert"):
            cfg.warnings.append(f"line {n}: -I treated as append; rule order may differ")
            tokens = ["-A", *tokens[1:]]
            if len(tokens) > 2 and tokens[2].isdigit():
                del tokens[2]

        try:
            _add_rule(cfg, counters, tokens, n, line)
        except ValueError as exc:
            cfg.warnings.append(f"line {n}: skipped ({exc}): {line}")

    for rule in cfg.rules:
        rule.direction = DIRECTIONS.get(rule.container, "unknown")
    return cfg


def _add_rule(cfg: ParsedConfig, counters: dict[str, int], tokens: list[str], n: int, raw: str) -> None:
    chain = target = None
    proto, src, dst = "all", "any", "any"
    sports: list[PortRange] = []
    dports: list[PortRange] = []
    established = complex_ = False
    icmp = ""
    i = 0
    while i < len(tokens):
        t = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if t in ("-A", "--append"):
            chain, i = nxt, i + 2
        elif t in ("-p", "--protocol"):
            proto, i = nxt.lower(), i + 2
        elif t in ("-s", "--source", "--src"):
            src, i = norm_net(nxt), i + 2
        elif t in ("-d", "--destination", "--dst"):
            dst, i = norm_net(nxt), i + 2
        elif t in ("-i", "--in-interface", "-o", "--out-interface"):
            complex_, i = True, i + 2
        elif t in ("--dport", "--dports", "--destination-port", "--destination-ports"):
            dports, i = _ports(nxt), i + 2
        elif t in ("--sport", "--sports", "--source-port", "--source-ports"):
            sports, i = _ports(nxt), i + 2
        elif t in ("-m", "--match"):
            complex_ = complex_ or nxt not in KNOWN_MODULES
            i += 2
        elif t in ("--state", "--ctstate"):
            u = nxt.upper()
            established = established or ("ESTABLISHED" in u and "NEW" not in u)
            i += 2
        elif t == "--comment":
            i += 2
        elif t in ("-j", "--jump", "-g", "--goto"):
            target, i = nxt, i + 2
        elif t == "--icmp-type":
            icmp, i = nxt, i + 2
        elif t == "!":
            complex_, i = True, i + 1
        elif t.startswith("-"):
            complex_ = True
            i += 2 if nxt and not nxt.startswith("-") else 1
        else:
            i += 1

    if chain is None or target is None:
        return
    if target == "LOG":
        cfg.logged_containers.add(chain)
        return
    if target not in TARGETS:
        return                                   # RETURN, custom chains, NAT targets...
    counters[chain] = counters.get(chain, 0) + 1
    cfg.rules.append(Rule(
        vendor="iptables", container=chain, index=counters[chain], line_no=n, raw=raw,
        action=TARGETS[target], protocol=proto, src=src, dst=dst,
        src_ports=sports, dst_ports=dports, established=established,
        icmp_type=icmp, complex=complex_))
