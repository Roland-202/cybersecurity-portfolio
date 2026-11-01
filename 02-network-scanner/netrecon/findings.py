"""Turn fingerprints into findings: version-matched CVEs plus exposure/misconfiguration checks."""
from __future__ import annotations

import re

from .fingerprint import DISPLAY
from .models import Finding, PortResult, Severity
from .vulndb import lookup

S = Severity
DB_PORTS = {1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"}


def vuln_findings(host: str, pr: PortResult, db: list[dict]) -> list[Finding]:
    out = []
    distro = pr.fp.notes.get("distro")
    for product, version in pr.fp.components():
        for e in lookup(product, version, db):
            conf = "low" if distro else "medium"
            caveat = (f" Banner reports a {distro} build; distributions backport fixes without changing the "
                      "version string, so verify the package changelog." if distro else
                      " Detection is based on the advertised version only; confirm the installed version before acting.")
            out.append(Finding(
                finding_id=e["id"], title=e["title"], severity=e["_severity"], host=host, port=pr.port,
                description=f"{e['summary']} Detected {DISPLAY.get(product, product)} {version}.{caveat}",
                remediation=e["remediation"], confidence=conf, references=e["references"],
                evidence=pr.banner[:160]))
    return out


def exposure_findings(host: str, pr: PortResult) -> list[Finding]:
    fp, port, out = pr.fp, pr.port, []

    def add(fid, title, sev, desc, fix, conf="high"):
        out.append(Finding(fid, title, sev, host, port, desc, fix, conf, [], pr.banner[:160]))

    svc = fp.service
    if svc == "telnet" or (svc == "unknown" and port == 23):
        add("NR-001", "Telnet exposed", S.HIGH,
            "Telnet transmits credentials and sessions in cleartext and is trivially intercepted.",
            "Disable telnetd and use SSH with key-based authentication.", "high" if svc == "telnet" else "medium")
    if svc == "ftp":
        add("NR-002", "Cleartext FTP exposed", S.MEDIUM,
            "FTP sends credentials and data unencrypted. Anonymous access was not tested by this tool.",
            "Replace with SFTP/FTPS, or restrict to a trusted management network.")
    if fp.product == "redis" and fp.auth == "none":
        add("NR-003", "Redis responds without authentication", S.CRITICAL,
            "The service answered PING with no credentials. Unauthenticated Redis commonly leads to data theft "
            "and, via CONFIG/SLAVEOF abuse, remote code execution.",
            "Bind to localhost or a private interface, set requirepass/ACLs, and firewall port 6379.")
    elif fp.product == "redis":
        add("NR-004", "Redis exposed to the network", S.LOW,
            "Redis requires authentication but is reachable from the scanner's network position.",
            "Restrict access to application hosts only; Redis should rarely be network-wide reachable.")
    if svc == "memcached":
        add("NR-005", "memcached exposed without authentication", S.HIGH,
            "memcached has no authentication by default; exposed instances leak cached data and can be abused for "
            "UDP amplification attacks.", "Bind to localhost/private interfaces, disable UDP, firewall port 11211.")
    if svc == "vnc":
        add("NR-006", "VNC exposed", S.HIGH,
            "VNC offers remote desktop control with weak or no encryption in many configurations.",
            "Tunnel VNC through SSH/VPN and require strong authentication.")
    if fp.product == "elasticsearch":
        add("NR-007", "Elasticsearch API reachable without authentication", S.HIGH,
            "The cluster metadata endpoint answered an anonymous request.",
            "Enable security features (authentication, TLS) and restrict network access.")
    if fp.product == "docker" and not pr.tls:
        add("NR-008", "Docker Engine API exposed over plain HTTP", S.CRITICAL,
            "An unauthenticated Docker API is equivalent to remote root on the host.",
            "Do not expose the Docker socket over TCP; if needed use mutual TLS on port 2376.")
    if fp.notes.get("ssh1"):
        add("NR-009", "SSH protocol version 1 supported", S.HIGH,
            "SSHv1 has known cryptographic weaknesses.", "Set 'Protocol 2' (or upgrade to a modern OpenSSH).")
    if fp.product in ("mysql", "mariadb") or port in DB_PORTS:
        name = DB_PORTS.get(port, fp.display or "Database")
        add("NR-010", f"Database service reachable ({name})", S.MEDIUM,
            "Database listeners should normally be reachable only from application servers.",
            "Bind to private interfaces and enforce network ACLs between the app and data tiers.",
            "high" if fp.product else "medium")
    if port == 3389:
        add("NR-011", "RDP exposed", S.HIGH, "RDP is a frequent target of credential attacks and ransomware operators.",
            "Place behind a VPN/RD Gateway with MFA and Network Level Authentication.", "medium")
    if port in (445, 139):
        add("NR-012", "SMB/NetBIOS exposed", S.MEDIUM, "SMB should not be reachable outside trusted segments.",
            "Block at the network boundary; disable SMBv1; require signing.", "medium")
    if port == 5985:
        add("NR-013", "WinRM exposed", S.MEDIUM, "Remote management endpoint reachable.",
            "Restrict to admin networks; prefer HTTPS (5986) with certificate auth.", "medium")
    if svc in ("pop3", "imap") and not pr.tls:
        add("NR-014", f"Cleartext {svc.upper()} exposed", S.LOW, "Mail retrieval without TLS exposes credentials.",
            "Enforce STARTTLS or use the TLS variants (995/993).")
    sh = fp.notes.get("server_header", "")
    if re.search(r"/\d", sh) or fp.notes.get("php"):
        add("NR-015", "Web server discloses software version", S.LOW,
            f"Response headers reveal '{sh or 'PHP/' + fp.notes.get('php', '')}', aiding attacker reconnaissance.",
            "Set ServerTokens Prod / server_tokens off / expose_php=Off. Hiding versions is hygiene, not a fix for patching.")
    return out
