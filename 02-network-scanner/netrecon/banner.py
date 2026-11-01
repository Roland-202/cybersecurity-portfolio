"""Banner grabbing: passive read first, then a small set of safe, read-only probes."""
from __future__ import annotations

import asyncio
import ssl

from .fingerprint import Fingerprint, identify

HTTP_PORTS = {80, 3000, 5000, 8000, 8001, 8008, 8080, 8081, 8888, 9090, 9200, 2375}
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}
PROBES = {
    "http": b"GET / HTTP/1.0\r\nHost: %b\r\nUser-Agent: netrecon/0.1\r\nConnection: close\r\n\r\n",
    "redis": b"PING\r\n",
    "memcached": b"version\r\n",
}


def _probe_order(port: int) -> list[str]:
    if port in HTTP_PORTS or port in (443, 8443, 9443):
        return ["http"]
    if port == 6379:
        return ["redis"]
    if port == 11211:
        return ["memcached"]
    return ["http", "redis"]


async def _exchange(host: str, port: int, payload: bytes, timeout: float, tls: bool):
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE         # we are fingerprinting, not authenticating
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout)
        version = writer.get_extra_info("ssl_object").version() if tls else ""
        if payload:
            writer.write(payload)
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout)
        except (asyncio.TimeoutError, ConnectionError):
            data = b""
        return data, version or ""
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return b"", ""
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass


async def grab(host: str, port: int, timeout: float = 2.0, hostname: str = "") -> dict:
    """Returns {data, probe, tls, tls_version, fp}."""
    tls = port in TLS_PORTS
    data, ver = await _exchange(host, port, b"", min(timeout, 1.0), tls)
    if data:                                        # server-first protocols: SSH, FTP, SMTP, MySQL, Telnet...
        return dict(data=data, probe="passive", tls=tls, tls_version=ver, fp=identify(data, tls))

    last = (b"", "", ver)
    for name in _probe_order(port):
        payload = PROBES[name]
        if name == "http":
            payload = payload % (hostname or host).encode()
        data, ver2 = await _exchange(host, port, payload, timeout, tls)
        if data:
            fp = identify(data, tls)
            last = (data, name, ver2)
            if fp.service != "unknown":
                return dict(data=data, probe=name, tls=tls, tls_version=ver2, fp=fp)
    data, name, ver3 = last
    return dict(data=data, probe=name, tls=tls, tls_version=ver3, fp=identify(data, tls) if data else Fingerprint())
