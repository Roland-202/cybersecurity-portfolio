"""Turn raw service responses into (service, product, version) fingerprints."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

DISPLAY = {"openssh": "OpenSSH", "dropbear": "Dropbear", "apache": "Apache httpd", "nginx": "nginx",
           "iis": "Microsoft IIS", "lighttpd": "lighttpd", "vsftpd": "vsftpd", "proftpd": "ProFTPD",
           "exim": "Exim", "postfix": "Postfix", "mysql": "MySQL", "mariadb": "MariaDB", "php": "PHP",
           "redis": "Redis", "memcached": "memcached", "elasticsearch": "Elasticsearch",
           "docker": "Docker Engine", "dovecot": "Dovecot"}
_HTTP_PRODUCTS = {"apache": "apache", "nginx": "nginx", "microsoft-iis": "iis", "lighttpd": "lighttpd",
                  "docker": "docker"}
_DISTRO = re.compile(r"(Ubuntu|Debian|Raspbian|FreeBSD|\bel\d|\.el\d|deb\d+u\d+)", re.I)


@dataclass
class Fingerprint:
    service: str = "unknown"
    product: str = ""             # canonical key, e.g. "openssh"
    version: str = ""
    auth: str = ""                # "none" | "required" | "" (unknown)
    notes: dict = field(default_factory=dict)

    @property
    def display(self) -> str:
        return DISPLAY.get(self.product, self.product)

    def components(self) -> list[tuple[str, str]]:
        """(product, version) pairs worth matching against the vulnerability DB."""
        out = [(self.product, self.version)] if self.product and self.version else []
        if self.notes.get("php"):
            out.append(("php", self.notes["php"]))
        return out


def _ssh(text: str) -> Fingerprint:
    line = text.splitlines()[0]
    m = re.match(r"SSH-(\d\.\d+)-(\S+)", line)
    fp = Fingerprint(service="ssh")
    if not m:
        return fp
    proto, software = m.groups()
    if proto.startswith("1.") and proto != "1.99":
        fp.notes["ssh1"] = True
    if d := _DISTRO.search(line):
        fp.notes["distro"] = d.group(1)
    if om := re.match(r"OpenSSH_(\d+\.\d+(?:p\d+)?)", software):
        fp.product, fp.version = "openssh", om.group(1)
    elif dm := re.match(r"dropbear_([\d.]+)", software, re.I):
        fp.product, fp.version = "dropbear", dm.group(1)
    return fp


def _http(text: str, tls: bool) -> Fingerprint:
    head, _, body = text.partition("\r\n\r\n")
    headers = {}
    for ln in head.split("\r\n")[1:]:
        k, _, v = ln.partition(":")
        headers[k.strip().lower()] = v.strip()
    fp = Fingerprint(service="https" if tls else "http")
    server = headers.get("server", "")
    fp.notes["server_header"] = server
    if m := re.match(r"([A-Za-z][\w.\-]*)/(\d[\w.]*)", server):
        key = _HTTP_PRODUCTS.get(m.group(1).lower())
        if key:
            fp.product, fp.version = key, m.group(2)
    if pm := re.search(r"PHP/(\d+\.\d+(?:\.\d+)?)", headers.get("x-powered-by", "")):
        fp.notes["php"] = pm.group(1)
    if '"tagline"' in body and "for Search" in body or '"cluster_name"' in body:
        fp.product = "elasticsearch"
        if vm := re.search(r'"number"\s*:\s*"(\d[\d.]*)"', body):
            fp.version = vm.group(1)
    return fp


def _mail_ftp(text: str) -> Fingerprint | None:
    low = text.lower()
    if text.startswith("220"):
        if "vsftpd" in low:
            m = re.search(r"vsftpd\s+(\d[\d.]*)", text, re.I)
            return Fingerprint("ftp", "vsftpd", m.group(1) if m else "")
        if "proftpd" in low:
            m = re.search(r"proftpd\s+(\d[\w.]*)", text, re.I)
            return Fingerprint("ftp", "proftpd", m.group(1) if m else "")
        if "exim" in low:
            m = re.search(r"exim\s+(\d[\d.]*)", text, re.I)
            return Fingerprint("smtp", "exim", m.group(1) if m else "")
        if "postfix" in low:
            return Fingerprint("smtp", "postfix")
        if "smtp" in low:
            return Fingerprint("smtp")
        if "ftp" in low:
            return Fingerprint("ftp")
    if text.startswith("+OK"):
        return Fingerprint("pop3", "dovecot" if "dovecot" in low else "")
    if text.startswith("* OK"):
        return Fingerprint("imap", "dovecot" if "dovecot" in low else "")
    return None


def _mysql(data: bytes) -> Fingerprint | None:
    if len(data) < 8 or data[4] != 0x0A:
        return None
    ver = data[5:].split(b"\x00")[0].decode("ascii", "replace")
    if not re.match(r"^\d+\.\d+\.\d+", ver):
        return None
    maria = "mariadb" in ver.lower()
    ver = re.sub(r"^5\.5\.5-", "", ver) if maria else ver
    return Fingerprint("mysql", "mariadb" if maria else "mysql", re.match(r"\d+\.\d+\.\d+", ver).group(0))


def identify(data: bytes, tls: bool = False) -> Fingerprint:
    """Classify a response. Returns service='unknown' when nothing matches."""
    if not data:
        return Fingerprint()
    text = data.decode("latin-1")
    if text.startswith("SSH-"):
        return _ssh(text)
    if text.startswith("HTTP/"):
        return _http(text, tls)
    if text.startswith("+PONG"):
        return Fingerprint("redis", "redis", auth="none")
    if text.startswith(("-NOAUTH", "-DENIED")):
        return Fingerprint("redis", "redis", auth="required")
    if text.startswith("VERSION "):
        return Fingerprint("memcached", "memcached", text[8:].split()[0] if text[8:].split() else "")
    if text.startswith("RFB "):
        return Fingerprint("vnc", version=text[4:].strip())
    if data[:1] == b"\xff" and len(data) >= 3:
        return Fingerprint("telnet")
    if (fp := _mysql(data)):
        return fp
    return _mail_ftp(text) or Fingerprint()
