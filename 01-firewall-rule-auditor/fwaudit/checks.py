"""Security checks. Each check inspects a ParsedConfig and yields Findings.

Reference mappings are indicative starting points for audit working papers;
always validate control mappings against your own framework version.
"""
from __future__ import annotations

from typing import Callable, Iterator

from .models import Finding, ParsedConfig, Rule, Severity
from .netutil import net_covers, port_span, ports_cover

S = Severity
NIST_SC7 = "NIST SP 800-53 r5 SC-7 (Boundary Protection)"
NIST_SC7_5 = "NIST SP 800-53 r5 SC-7(5) (Deny by Default, Allow by Exception)"
NIST_CM7 = "NIST SP 800-53 r5 CM-7 (Least Functionality)"
NIST_AU12 = "NIST SP 800-53 r5 AU-12 (Audit Record Generation)"
NIST_CM6 = "NIST SP 800-53 r5 CM-6 (Configuration Settings)"
ISO_NET = "ISO/IEC 27001:2022 A.8.20 (Networks security)"
ISO_LOG = "ISO/IEC 27001:2022 A.8.15 (Logging)"
PCI_1 = "PCI DSS v4.0 Requirement 1 (Network Security Controls)"
CIS_13 = "CIS Controls v8 13.4 (Traffic filtering between network segments)"
CIS_8 = "CIS Controls v8 8.2 (Collect audit logs)"

META: dict[str, dict] = {
    "FW-001": dict(title="Permit any-any rule", severity=S.CRITICAL,
                   remediation="Remove the rule. Permit only the specific sources, destinations and services required, and end the list with an explicit deny.",
                   refs=[NIST_SC7, NIST_CM7, PCI_1, CIS_13]),
    "FW-002": dict(title="Risky service exposed to any source", severity=S.HIGH,
                   remediation="Restrict the source to a management/trusted network or VPN, or remove the rule. Replace cleartext protocols (Telnet, FTP, TFTP, SNMPv1/2c) with encrypted alternatives.",
                   refs=[NIST_SC7, NIST_CM7, ISO_NET, PCI_1]),
    "FW-003": dict(title="Overly broad permit from any source", severity=S.HIGH,
                   remediation="Narrow the rule to the exact destination host and the specific ports/protocols the service needs.",
                   refs=[NIST_CM7, NIST_SC7, CIS_13]),
    "FW-004": dict(title="Default-permit posture / no explicit deny-all", severity=S.HIGH,
                   remediation="Set the default policy to DROP (iptables) or finish the ACL with an explicit 'deny ip any any log' so denied traffic is deliberate and visible.",
                   refs=[NIST_SC7_5, ISO_NET, PCI_1]),
    "FW-005": dict(title="Deny-all rule is not logged", severity=S.LOW,
                   remediation="Add logging (Cisco 'log' keyword, or an iptables LOG rule with rate limiting) before the final deny so blocked traffic is available to the SIEM.",
                   refs=[NIST_AU12, ISO_LOG, CIS_8]),
    "FW-006": dict(title="Shadowed or redundant rule", severity=S.MEDIUM,
                   remediation="Remove the dead rule or reorder the list. If actions conflict, confirm which behaviour was intended.",
                   refs=[NIST_CM6, NIST_SC7]),
    "FW-007": dict(title="ACL defined but not applied", severity=S.LOW,
                   remediation="Apply the ACL to an interface/line, or delete it. Confirm it is not referenced by NAT, route-maps or class-maps before removal.",
                   refs=[NIST_CM6, NIST_CM7]),
    "FW-008": dict(title="ICMP permitted from any source without type restriction", severity=S.LOW,
                   remediation="Limit ICMP to required types (e.g. echo-reply, unreachable, time-exceeded) and rate-limit echo requests on perimeter interfaces.",
                   refs=[NIST_CM7, NIST_SC7]),
}

# port -> (service name, severity when exposed to "any")
RISKY_PORTS: dict[int, tuple[str, Severity]] = {
    21: ("FTP", S.HIGH), 22: ("SSH", S.MEDIUM), 23: ("Telnet", S.CRITICAL), 69: ("TFTP", S.HIGH),
    111: ("rpcbind", S.HIGH), 135: ("MS-RPC", S.HIGH), 137: ("NetBIOS-NS", S.HIGH),
    138: ("NetBIOS-DGM", S.HIGH), 139: ("NetBIOS-SSN", S.HIGH), 161: ("SNMP", S.HIGH),
    445: ("SMB", S.CRITICAL), 512: ("rexec", S.HIGH), 513: ("rlogin", S.HIGH), 514: ("rsh", S.HIGH),
    1433: ("MSSQL", S.HIGH), 1521: ("Oracle DB", S.HIGH), 2375: ("Docker API", S.CRITICAL),
    3306: ("MySQL", S.HIGH), 3389: ("RDP", S.CRITICAL), 5432: ("PostgreSQL", S.HIGH),
    5900: ("VNC", S.HIGH), 6379: ("Redis", S.HIGH), 27017: ("MongoDB", S.HIGH),
}

Check = Callable[[ParsedConfig], Iterator[Finding]]


def _finding(check_id: str, desc: str, rule: Rule | None = None, *, container: str = "",
             severity: Severity | None = None, title: str | None = None) -> Finding:
    m = META[check_id]
    return Finding(check_id=check_id, title=title or m["title"], severity=severity or m["severity"],
                   description=desc, remediation=m["remediation"], references=m["refs"],
                   rule=rule, container=container)


def _inbound_permits(cfg: ParsedConfig) -> Iterator[Rule]:
    for r in cfg.rules:
        if r.is_permit and r.direction != "out" and not r.established:
            yield r


def _is_deny_all(r: Rule) -> bool:
    return (not r.is_permit and r.all_protocols and r.src == "any" and r.dst == "any"
            and not r.complex and not r.established)


def check_any_any(cfg: ParsedConfig) -> Iterator[Finding]:
    for r in _inbound_permits(cfg):
        if r.all_protocols and r.src == "any" and r.dst == "any" and not r.complex:
            yield _finding("FW-001", f"{r.container} #{r.index} permits all protocols from any source to any destination, "
                                     "which effectively disables filtering for this list.", r)


def check_risky_ports(cfg: ParsedConfig) -> Iterator[Finding]:
    for r in _inbound_permits(cfg):
        if r.src != "any" or r.all_protocols or r.protocol not in ("tcp", "udp"):
            continue
        if not r.dst_ports or port_span(r.dst_ports) > 1000:
            continue                              # handled by FW-003
        hits = [(p, *RISKY_PORTS[p]) for p in sorted(RISKY_PORTS)
                if any(lo <= p <= hi for lo, hi in r.dst_ports)]
        if not hits:
            continue
        worst = max(h[2] for h in hits)
        names = ", ".join(f"{name} ({port}/{r.protocol})" for port, name, _ in hits)
        note = " The rule has extra match conditions (interface, rate limit...) that were not evaluated." if r.complex else ""
        yield _finding("FW-002", f"{r.container} #{r.index} exposes {names} to any source address.{note}", r,
                       severity=worst, title=f"Risky service exposed to any source: {hits[0][1]}"
                       + (f" +{len(hits) - 1} more" if len(hits) > 1 else ""))


def check_broad_permits(cfg: ParsedConfig) -> Iterator[Finding]:
    for r in _inbound_permits(cfg):
        if r.src != "any":
            continue
        if r.protocol in ("tcp", "udp") and port_span(r.dst_ports) > 1000:
            span = "all ports" if not r.dst_ports else f"{port_span(r.dst_ports)} ports"
            yield _finding("FW-003", f"{r.container} #{r.index} allows {r.protocol.upper()} from any source on {span}"
                                     + (f" to {r.dst}." if r.dst != "any" else "."), r)
        elif r.all_protocols and r.dst != "any":
            yield _finding("FW-003", f"{r.container} #{r.index} allows every protocol and port from any source to {r.dst}.", r)


def check_default_posture(cfg: ParsedConfig) -> Iterator[Finding]:
    groups = cfg.containers()
    if cfg.vendor == "iptables":
        for chain in ("INPUT", "FORWARD"):
            if cfg.policies.get(chain) == "ACCEPT":
                rules = groups.get(chain, [])
                if not rules or not _is_deny_all(rules[-1]):
                    yield _finding("FW-004", f"Chain {chain} has default policy ACCEPT and no terminal deny-all rule, "
                                             "so any traffic not explicitly blocked is allowed.", container=chain)
    elif cfg.vendor == "cisco":
        for name, rules in groups.items():
            last = rules[-1]
            ends_permit_all = last.is_permit and last.all_protocols and last.src == "any" and last.dst == "any"
            if _is_deny_all(last) or ends_permit_all:   # permit-any-any is reported by FW-001
                continue
            yield _finding("FW-004", f"ACL {name} ends without an explicit 'deny ip any any'. It relies on the implicit "
                                     "deny, which is silent and unlogged.", last, severity=S.LOW,
                           title="No explicit deny-all at end of ACL")


def check_logging(cfg: ParsedConfig) -> Iterator[Finding]:
    groups = cfg.containers()
    if cfg.vendor == "cisco":
        for name, rules in groups.items():
            last = rules[-1]
            if _is_deny_all(last) and not last.log:
                yield _finding("FW-005", f"ACL {name} ends with an explicit deny-all that does not log.", last)
    elif cfg.vendor == "iptables":
        for chain in ("INPUT", "FORWARD"):
            rules = groups.get(chain, [])
            drops = cfg.policies.get(chain) in ("DROP", "REJECT") or (rules and _is_deny_all(rules[-1]))
            if rules and drops and chain not in cfg.logged_containers:
                yield _finding("FW-005", f"Chain {chain} drops traffic by default but has no LOG rule.", container=chain)


def _covers(a: Rule, b: Rule) -> bool:
    """True if every packet matching b is also matched by earlier rule a."""
    if a.complex or (a.established and not b.established):
        return False
    if not (a.all_protocols or a.protocol == b.protocol):
        return False
    if a.icmp_type and a.icmp_type != b.icmp_type:
        return False
    return (net_covers(a.src, b.src) and net_covers(a.dst, b.dst)
            and ports_cover(a.src_ports, b.src_ports) and ports_cover(a.dst_ports, b.dst_ports))


def check_shadowing(cfg: ParsedConfig) -> Iterator[Finding]:
    for name, rules in cfg.containers().items():
        for j, later in enumerate(rules):
            for earlier in rules[:j]:
                if _covers(earlier, later):
                    conflict = earlier.action != later.action
                    kind = "conflicting action - this rule can never take effect" if conflict else "redundant duplicate coverage"
                    yield _finding("FW-006", f"{name} #{later.index} is fully matched by earlier rule #{earlier.index} "
                                             f"(line {earlier.line_no}): {kind}.", later,
                                   severity=S.HIGH if conflict else S.LOW,
                                   title="Shadowed rule with conflicting action" if conflict else "Redundant rule")
                    break


def check_unapplied_acls(cfg: ParsedConfig) -> Iterator[Finding]:
    if cfg.vendor != "cisco":
        return
    for name, rules in cfg.containers().items():
        if name not in cfg.bindings:
            yield _finding("FW-007", f"ACL {name} ({len(rules)} rules) is not applied to any interface or line in this file.",
                           rules[0])


def check_icmp(cfg: ParsedConfig) -> Iterator[Finding]:
    for r in _inbound_permits(cfg):
        if r.protocol == "icmp" and r.src == "any" and not r.icmp_type:
            yield _finding("FW-008", f"{r.container} #{r.index} permits all ICMP types from any source.", r)


ALL_CHECKS: list[Check] = [check_any_any, check_risky_ports, check_broad_permits, check_default_posture,
                           check_logging, check_shadowing, check_unapplied_acls, check_icmp]
