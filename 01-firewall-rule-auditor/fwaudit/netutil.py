"""Small, dependency-free helpers for address and port-range maths."""
from __future__ import annotations

import ipaddress

from .models import PortRange


def norm_net(value: str) -> str:
    """Normalise an address to "any" or canonical CIDR."""
    if value in ("any", "0.0.0.0/0"):
        return "any"
    if "/" not in value:
        value += "/32"
    net = str(ipaddress.ip_network(value, strict=False))
    return "any" if net == "0.0.0.0/0" else net


def wildcard_to_prefix(addr: str, wildcard: str) -> str:
    """Convert a Cisco wildcard mask (0.0.0.255) into CIDR."""
    wc = int(ipaddress.IPv4Address(wildcard))
    if wc & (wc + 1) != 0:
        raise ValueError(f"non-contiguous wildcard mask {wildcard}")
    return norm_net(f"{addr}/{32 - wc.bit_length()}")


def net_covers(a: str, b: str) -> bool:
    """True if network a fully contains network b."""
    if a == "any":
        return True
    if b == "any":
        return False
    try:
        na, nb = ipaddress.ip_network(a), ipaddress.ip_network(b)
        return na.version == nb.version and nb.subnet_of(na)
    except (ValueError, TypeError):
        return False


def ports_cover(a: list[PortRange], b: list[PortRange]) -> bool:
    """True if port set a covers port set b ([] means any port)."""
    if not a:
        return True
    if not b:
        return any(lo <= 0 and hi >= 65535 for lo, hi in a)
    return all(any(alo <= blo and bhi <= ahi for alo, ahi in a) for blo, bhi in b)


def port_span(ranges: list[PortRange]) -> int:
    """Number of ports matched ([] means all 65536)."""
    if not ranges:
        return 65536
    return sum(hi - lo + 1 for lo, hi in ranges)
