"""Asynchronous TCP connect scanner.

State semantics (connect scan):
  open      handshake completed
  closed    RST received (host is up, nothing listening)
  filtered  timeout / unreachable (dropped by a firewall or host down)
"""
from __future__ import annotations

import asyncio
import itertools
from typing import Callable


async def probe(host: str, port: int, timeout: float) -> str:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except ConnectionRefusedError:
        return "closed"
    except (asyncio.TimeoutError, OSError):
        return "filtered"
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return "open"


async def scan_ports(hosts: list[str], ports: list[int], timeout: float = 1.5, concurrency: int = 300,
                     on_progress: Callable[[int, int], None] | None = None) -> dict[str, dict[int, str]]:
    results: dict[str, dict[int, str]] = {h: {} for h in hosts}
    total = len(hosts) * len(ports)
    if total == 0:
        return results
    work = itertools.product(hosts, ports)      # shared iterator; next() never yields to the loop
    done = 0

    async def worker() -> None:
        nonlocal done
        for host, port in work:
            results[host][port] = await probe(host, port, timeout)
            done += 1
            if on_progress and done % 500 == 0:
                on_progress(done, total)

    await asyncio.gather(*(worker() for _ in range(min(concurrency, total))))
    return results
