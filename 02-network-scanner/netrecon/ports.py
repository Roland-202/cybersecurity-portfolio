"""Port-spec parsing and well-known service names."""
from __future__ import annotations

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995,
             1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 5985, 6379, 8000, 8008,
             8080, 8081, 8443, 8888, 9090, 9200, 11211, 27017]

SERVICE_BY_PORT = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
                   111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
                   445: "smb", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
                   1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
                   5900: "vnc", 5985: "winrm", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
                   9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}


def parse_ports(spec: str) -> list[int]:
    """'22,80,8000-8100' | 'top' | 'all' -> sorted unique list of ports."""
    spec = spec.strip().lower()
    if spec == "top":
        return list(TOP_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        lo_s, _, hi_s = part.partition("-")
        try:
            lo, hi = int(lo_s), int(hi_s or lo_s)
        except ValueError:
            raise ValueError(f"invalid port spec: {part!r}") from None
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(f"port out of range: {part!r}")
        out.update(range(lo, hi + 1))
    if not out:
        raise ValueError("empty port specification")
    return sorted(out)
