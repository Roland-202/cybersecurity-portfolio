import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "lab"))
from fake_services import start_lab  # noqa: E402

from netrecon.banner import grab  # noqa: E402
from netrecon.cli import main  # noqa: E402
from netrecon.engine import run_scan  # noqa: E402
from netrecon.findings import vuln_findings  # noqa: E402
from netrecon.fingerprint import identify  # noqa: E402
from netrecon.models import PortResult, Severity  # noqa: E402
from netrecon.ports import parse_ports  # noqa: E402
from netrecon.report import render_html  # noqa: E402
from netrecon.scanner import scan_ports  # noqa: E402
from netrecon.targets import ScopeError, Target, expand_targets  # noqa: E402
from netrecon.versions import compare, is_affected, parse  # noqa: E402
from netrecon.vulndb import load_db, lookup  # noqa: E402


# ---------- versions ----------
def test_version_parse_and_compare():
    assert parse("9.7p1") == (9, 7, 1)
    assert compare("9.8", "9.8p1") < 0 and compare("2.4.49", "2.4.49") == 0 and compare("4.91", "4.92") < 0
    assert compare("1.20", "1.2") > 0


def test_openssh_regresshion_boundaries():
    rule = [{"min": "8.5", "max_exclusive": "9.8"}]
    assert is_affected("8.5p1", rule) and is_affected("9.7p1", rule)
    assert not is_affected("8.4p1", rule) and not is_affected("9.8p1", rule) and not is_affected("9.8", rule)


def test_mysql_multi_branch_ranges():
    db = load_db()
    assert any(e["id"] == "CVE-2012-2122" for e in lookup("mysql", "5.5.20", db))
    assert not lookup("mysql", "5.5.62", db) and not lookup("mysql", "8.0.36", db)


# ---------- ports ----------
def test_parse_ports():
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    assert len(parse_ports("all")) == 65535 and 443 in parse_ports("top")
    for bad in ("0", "70000", "abc", "90-80", ""):
        with pytest.raises(ValueError):
            parse_ports(bad)


# ---------- targets / scope guard ----------
def test_cidr_range_and_dedupe():
    assert len(expand_targets(["10.0.0.0/30", "10.0.0.1"])) == 2
    assert [t.address for t in expand_targets(["192.168.1.5-7"])] == ["192.168.1.5", "192.168.1.6", "192.168.1.7"]


def test_cidr_over_limit_rejected():
    with pytest.raises(ValueError):
        expand_targets(["10.0.0.0/16"], max_hosts=256)


def test_public_targets_refused_without_authorization():
    with pytest.raises(ScopeError):
        expand_targets(["8.8.8.8"])
    assert expand_targets(["8.8.8.8"], allow_public=True)[0].address == "8.8.8.8"
    assert expand_targets(["127.0.0.1", "10.1.2.3", "192.168.0.9", "172.16.5.5"])


def test_public_mixed_with_private_still_refused():
    with pytest.raises(ScopeError):
        expand_targets(["10.0.0.1", "1.1.1.1"])


def test_target_file(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# lab\n127.0.0.1\n10.0.0.2  # db\n")
    assert [t.address for t in expand_targets([f"@{f}"])] == ["127.0.0.1", "10.0.0.2"]


# ---------- fingerprinting ----------
def test_ssh_fingerprint_with_distro_marker():
    fp = identify(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    assert (fp.product, fp.version, fp.notes["distro"]) == ("openssh", "8.9p1", "Ubuntu")


def test_ssh_v1_detected():
    assert identify(b"SSH-1.5-Foo\r\n").notes["ssh1"] is True
    assert "ssh1" not in identify(b"SSH-1.99-OpenSSH_3.9\r\n").notes


def test_http_fingerprints():
    fp = identify(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Powered-By: PHP/7.4.3\r\n\r\n")
    assert (fp.product, fp.version, fp.notes["php"]) == ("nginx", "1.18.0", "7.4.3")
    es = identify(b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{"version":{"number":"7.10.2"},"tagline":"You Know, for Search"}')
    assert (es.product, es.version) == ("elasticsearch", "7.10.2")


def test_misc_fingerprints():
    assert identify(b"220 (vsFTPd 2.3.4)\r\n").version == "2.3.4"
    assert identify(b"220 x ESMTP Exim 4.90 ready\r\n").product == "exim"
    assert identify(b"+PONG\r\n").auth == "none" and identify(b"-NOAUTH Authentication required.\r\n").auth == "required"
    assert identify(b"\xff\xfd\x18").service == "telnet" and identify(b"RFB 003.008\n").service == "vnc"
    assert identify(b"J\x00\x00\x00\x0a5.5.5-10.3.27-MariaDB\x00" + b"x" * 20).product == "mariadb"
    assert identify(b"garbage").service == "unknown" and identify(b"").service == "unknown"


# ---------- finding logic ----------
def test_distro_banner_lowers_confidence():
    pr = PortResult(port=22, fp=identify(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"), banner="x")
    f = [x for x in vuln_findings("h", pr, load_db()) if x.finding_id == "CVE-2024-6387"]
    assert f and f[0].confidence == "low" and "backport" in f[0].description


def test_patched_openssh_has_no_regresshion():
    pr = PortResult(port=22, fp=identify(b"SSH-2.0-OpenSSH_9.8p1\r\n"))
    assert vuln_findings("h", pr, load_db()) == []


# ---------- integration against the lab ----------
def _scan_lab(**kw):
    async def go():
        servers, bound = await start_lab(ports={k: 0 for k in ("ssh", "ftp", "telnet", "smtp", "mysql", "redis", "http")})
        try:
            ports = sorted(bound.values()) + [1]       # port 1 should be closed
            res = await run_scan([Target("127.0.0.1")], ports, timeout=1.0, **kw)
            return res, bound
        finally:
            for s in servers:
                s.close()
    return asyncio.run(go())


def test_lab_end_to_end():
    res, bound = _scan_lab()
    host = res.hosts[0]
    assert host.up and len(host.ports) == 7 and host.closed == 1
    ids = {f.finding_id for f in res.findings}
    assert {"CVE-2011-2523", "CVE-2021-42013", "CVE-2019-10149", "NR-001", "NR-003", "EOL-PHP"} <= ids
    by_port = {p.port: p for p in host.ports}
    assert by_port[bound["redis"]].product == "redis" and by_port[bound["mysql"]].version == "5.5.20"
    assert res.worst() == Severity.CRITICAL


def test_no_banner_mode_skips_fingerprinting():
    res, _ = _scan_lab(banners=False)
    assert len(res.hosts[0].ports) == 7 and not any(f.finding_id.startswith("CVE") for f in res.findings)


def test_closed_vs_open_states():
    async def go():
        servers, bound = await start_lab(ports={"ssh": 0})
        try:
            return bound["ssh"], await scan_ports(["127.0.0.1"], [bound["ssh"], 1], timeout=1.0)
        finally:
            for s in servers:
                s.close()
    port, st = asyncio.run(go())
    assert st["127.0.0.1"] == {port: "open", 1: "closed"}


def test_hostile_banner_is_escaped_in_html():
    async def go():
        async def evil(r, w):
            w.write(b"SSH-2.0-<script>alert(1)</script>\r\n")
            await w.drain()
            w.close()
        srv = await asyncio.start_server(evil, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        res = await run_scan([Target("127.0.0.1")], [port], timeout=1.0)
        srv.close()
        return res
    page = render_html(asyncio.run(go()))
    assert "<script>alert(1)" not in page and "&lt;script&gt;" in page


# ---------- CLI ----------
def test_cli_refuses_public_target_without_flag(capsys):
    assert main(["scan", "8.8.8.8", "-p", "53"]) == 3


def test_cli_bad_port_spec_and_json(tmp_path):
    assert main(["scan", "127.0.0.1", "-p", "99999"]) == 2
    out = tmp_path / "r.json"
    assert main(["scan", "127.0.0.1", "-p", "1", "-f", "json", "-o", str(out)]) == 0
    data = json.loads(out.read_text())
    assert data["hosts"][0]["closed"] == 1 and data["findings"] == []
