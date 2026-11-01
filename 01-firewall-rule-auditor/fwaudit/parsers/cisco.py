"""Parser for Cisco IOS / IOS-XE access lists (standard, extended, named, numbered)."""
from __future__ import annotations

import re

from ..models import ParsedConfig, PortRange, Rule
from ..netutil import norm_net, wildcard_to_prefix

PORT_NAMES = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "tacacs": 49,
    "domain": 53, "tftp": 69, "www": 80, "pop3": 110, "sunrpc": 111, "nntp": 119,
    "ntp": 123, "imap4": 143, "snmp": 161, "snmptrap": 162, "bgp": 179, "ldap": 389,
    "https": 443, "exec": 512, "login": 513, "cmd": 514, "syslog": 514, "lpd": 515,
    "ldaps": 636, "pop3s": 995,
}

_ACL_HDR = re.compile(r"^ip\s+access-list\s+(standard|extended)\s+(\S+)", re.I)
_NUM_ACL = re.compile(r"^access-list\s+(\d+)\s+(.*)", re.I)
_IFACE = re.compile(r"^interface\s+(\S+)", re.I)
_ACCESS_GROUP = re.compile(r"^ip\s+access-group\s+(\S+)\s+(in|out)", re.I)
_ACCESS_CLASS = re.compile(r"^access-class\s+(\S+)(?:\s+(in|out))?", re.I)
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_FLAGS = {"log", "log-input", "established", "fragments", "time-range", "reflect", "dscp", "precedence"}


class UnsupportedConstruct(ValueError):
    pass


def _addr(tokens: list[str], i: int) -> tuple[str, int]:
    t = tokens[i].lower()
    if t == "any":
        return "any", i + 1
    if t == "host":
        return norm_net(tokens[i + 1]), i + 2
    if t.startswith("object") or t == "addrgroup":
        raise UnsupportedConstruct(f"object-group reference ({t})")
    if _IPV4.match(t):
        if i + 1 < len(tokens) and _IPV4.match(tokens[i + 1]):
            return wildcard_to_prefix(t, tokens[i + 1]), i + 2
        return norm_net(t), i + 1
    raise ValueError(f"cannot parse address {t!r}")


def _port(tok: str) -> int:
    tok = tok.lower()
    if tok.isdigit():
        return int(tok)
    if tok in PORT_NAMES:
        return PORT_NAMES[tok]
    raise ValueError(f"unknown port {tok!r}")


def _is_port(tok: str) -> bool:
    return tok.isdigit() or tok.lower() in PORT_NAMES


def _ports(tokens: list[str], i: int) -> tuple[list[PortRange], int]:
    if i >= len(tokens) or tokens[i].lower() not in ("eq", "gt", "lt", "neq", "range"):
        return [], i
    op = tokens[i].lower()
    i += 1
    if op == "range":
        return [(_port(tokens[i]), _port(tokens[i + 1]))], i + 2
    vals = []
    while i < len(tokens) and _is_port(tokens[i]):
        vals.append(_port(tokens[i]))
        i += 1
    if not vals:
        raise ValueError(f"missing port after {op}")
    if op == "eq":
        return [(v, v) for v in vals], i
    if op == "gt":
        return [(vals[0] + 1, 65535)], i
    if op == "lt":
        return [(0, vals[0] - 1)], i
    return [], i  # neq: approximated as "any"


def _parse_ace(tokens: list[str], kind: str) -> dict:
    action = tokens[0].lower()
    if kind == "standard":
        src, i = _addr(tokens, 1)
        flags = [t.lower() for t in tokens[i:]]
        return dict(action=action, protocol="ip", src=src, dst="any",
                    log="log" in flags or "log-input" in flags)
    proto = tokens[1].lower()
    i = 2
    src, i = _addr(tokens, i)
    sports: list[PortRange] = []
    dports: list[PortRange] = []
    if proto in ("tcp", "udp"):
        sports, i = _ports(tokens, i)
    dst, i = _addr(tokens, i)
    if proto in ("tcp", "udp"):
        dports, i = _ports(tokens, i)
    rest = [t.lower() for t in tokens[i:]]
    icmp_type = rest[0] if proto == "icmp" and rest and rest[0] not in _FLAGS else ""
    return dict(action=action, protocol=proto, src=src, dst=dst, src_ports=sports,
                dst_ports=dports, log="log" in rest or "log-input" in rest,
                established="established" in rest, icmp_type=icmp_type)


def parse(text: str, source: str = "<memory>") -> ParsedConfig:
    cfg = ParsedConfig(vendor="cisco", source=source)
    counters: dict[str, int] = {}
    ctx: tuple | None = None

    def add_ace(container: str, kind: str, body: str, line_no: int, raw: str) -> None:
        tokens = body.split()
        if tokens and tokens[0].isdigit():       # sequence number
            tokens = tokens[1:]
        if not tokens or tokens[0].lower() not in ("permit", "deny"):
            return
        try:
            fields = _parse_ace(tokens, kind)
        except (ValueError, IndexError) as exc:
            cfg.warnings.append(f"line {line_no}: skipped ({exc}): {raw.strip()}")
            return
        counters[container] = counters.get(container, 0) + 1
        cfg.rules.append(Rule(vendor="cisco", container=container, index=counters[container],
                              line_no=line_no, raw=raw.strip(), **fields))

    for n, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("!"):
            ctx = None
            continue

        if raw[0] not in " \t":                  # top-level statement
            ctx = None
            if m := _ACL_HDR.match(stripped):
                ctx = ("acl", m.group(2), m.group(1).lower())
            elif m := _IFACE.match(stripped):
                ctx = ("iface", m.group(1))
            elif stripped.lower().startswith("line "):
                ctx = ("line", stripped)
            elif m := _NUM_ACL.match(stripped):
                num = int(m.group(1))
                kind = "standard" if (1 <= num <= 99 or 1300 <= num <= 1999) else "extended"
                add_ace(m.group(1), kind, m.group(2), n, raw)
            continue

        if ctx is None:
            continue
        if ctx[0] == "acl":
            add_ace(ctx[1], ctx[2], stripped, n, raw)
        elif ctx[0] == "iface" and (m := _ACCESS_GROUP.match(stripped)):
            cfg.bindings.setdefault(m.group(1), []).append((f"interface {ctx[1]}", m.group(2).lower()))
        elif ctx[0] == "line" and (m := _ACCESS_CLASS.match(stripped)):
            cfg.bindings.setdefault(m.group(1), []).append((ctx[1], (m.group(2) or "in").lower()))

    for rule in cfg.rules:                       # derive direction from bindings
        dirs = {d for _, d in cfg.bindings.get(rule.container, [])}
        rule.direction = "in" if "in" in dirs else ("out" if dirs == {"out"} else "unknown")
    return cfg
