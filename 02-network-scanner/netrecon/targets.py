"""Target expansion and the authorisation scope guard."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from pathlib import Path


class ScopeError(ValueError):
    """Raised when targets fall outside the permitted scope."""


@dataclass(frozen=True)
class Target:
    address: str
    hostname: str = ""


_LAST_OCTET_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")


def _expand_one(spec: str, max_hosts: int) -> list[Target]:
    spec = spec.strip()
    if "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        if net.version != 4:
            raise ValueError("IPv6 targets are not supported yet")
        count = net.num_addresses - (2 if net.prefixlen < 31 else 0)
        if count > max_hosts:
            raise ValueError(f"{spec} expands to {count} hosts (limit {max_hosts}; raise with --max-hosts)")
        hosts = net.hosts() if net.prefixlen < 31 else iter(net)
        return [Target(str(h)) for h in hosts]
    if m := _LAST_OCTET_RANGE.match(spec):
        lo, hi = int(m.group(2)), int(m.group(3))
        if not (0 <= lo <= hi <= 255):
            raise ValueError(f"invalid range {spec!r}")
        return [Target(f"{m.group(1)}{i}") for i in range(lo, hi + 1)]
    try:
        ip = ipaddress.ip_address(spec)
    except ValueError:
        try:
            return [Target(socket.gethostbyname(spec), spec)]
        except socket.gaierror:
            raise ValueError(f"cannot resolve {spec!r}") from None
    if ip.version != 4:
        raise ValueError("IPv6 targets are not supported yet")
    return [Target(str(ip))]


def expand_targets(specs: list[str], max_hosts: int = 256, allow_public: bool = False) -> list[Target]:
    items: list[str] = []
    for spec in specs:
        if spec.startswith("@"):
            lines = Path(spec[1:]).read_text().splitlines()
            items += [ln.split("#")[0].strip() for ln in lines if ln.split("#")[0].strip()]
        else:
            items.append(spec)

    seen: dict[str, Target] = {}
    for item in items:
        for t in _expand_one(item, max_hosts):
            seen.setdefault(t.address, t)
    targets = list(seen.values())
    if len(targets) > max_hosts:
        raise ValueError(f"{len(targets)} targets exceeds limit of {max_hosts} (raise with --max-hosts)")

    public = [t.address for t in targets if ipaddress.ip_address(t.address).is_global]
    if public and not allow_public:
        raise ScopeError(
            f"{len(public)} target(s) are publicly routable (e.g. {public[0]}). Scanning systems you do not own "
            "or lack written permission to test may be illegal. If you are authorised, re-run with "
            "--i-have-written-authorization.")
    return targets
