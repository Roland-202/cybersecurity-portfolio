"""Harmless simulated services for demoing and testing netrecon on localhost.

These servers only *print banners* that look like old, vulnerable software. They contain no real
vulnerable code and bind to 127.0.0.1 only.

    python lab/fake_services.py            # fixed demo ports
    netrecon scan 127.0.0.1 -p 2121,2222,2323,2525,3307,6380,8080
"""
from __future__ import annotations

import asyncio

DEMO_PORTS = {"ssh": 2222, "ftp": 2121, "telnet": 2323, "smtp": 2525, "mysql": 3307, "redis": 6380, "http": 8080}

MYSQL_GREETING = b"\x4a\x00\x00\x00\x0a5.5.20-log\x00" + b"\x01" * 40
HTTP_RESPONSE = (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nX-Powered-By: PHP/5.6.40\r\n"
                 b"Content-Type: text/html\r\nConnection: close\r\n\r\n<html>lab</html>")

SERVER_FIRST = {
    "ssh": b"SSH-2.0-OpenSSH_7.4\r\n",
    "ftp": b"220 (vsFTPd 2.3.4)\r\n",
    "telnet": b"\xff\xfd\x18\xff\xfd\x20login: ",
    "smtp": b"220 mail.lab ESMTP Exim 4.90 ready\r\n",
    "mysql": MYSQL_GREETING,
}


def _banner_handler(payload: bytes):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(payload)
        try:
            await writer.drain()
            await asyncio.wait_for(reader.read(256), 0.5)
        except (asyncio.TimeoutError, ConnectionError):
            pass
        writer.close()
    return handle


async def _redis(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        line = await asyncio.wait_for(reader.readline(), 2)
        writer.write(b"+PONG\r\n" if line.strip().upper() == b"PING" else b"-ERR unknown command\r\n")
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    writer.close()


async def _http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        writer.write(HTTP_RESPONSE)
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
        pass
    writer.close()


async def start_lab(host: str = "127.0.0.1", ports: dict[str, int] | None = None):
    """Start all fake services. Pass port 0 values for ephemeral ports. Returns (servers, {name: port})."""
    ports = ports or DEMO_PORTS
    servers, bound = [], {}
    handlers = {name: _banner_handler(p) for name, p in SERVER_FIRST.items()}
    handlers["redis"], handlers["http"] = _redis, _http
    for name, port in ports.items():
        srv = await asyncio.start_server(handlers[name], host, port)
        servers.append(srv)
        bound[name] = srv.sockets[0].getsockname()[1]
    return servers, bound


async def main() -> None:
    servers, bound = await start_lab()
    print("netrecon lab running on 127.0.0.1 (Ctrl+C to stop)")
    for name, port in bound.items():
        print(f"  {name:<7} tcp/{port}")
    print("\nTry:  netrecon scan 127.0.0.1 -p " + ",".join(str(p) for p in bound.values()))
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
