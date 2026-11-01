import json
from pathlib import Path

import pytest

from fwaudit.analyzer import analyze
from fwaudit.cli import detect_vendor, main
from fwaudit.models import Severity
from fwaudit.netutil import net_covers, port_span, ports_cover, wildcard_to_prefix
from fwaudit.parsers import cisco, iptables

SAMPLES = Path(__file__).parent.parent / "samples"


def ids(text, parser):
    return [f.check_id for f in analyze(parser(text)).findings]


# ---------- helpers ----------
def test_wildcard_conversion():
    assert wildcard_to_prefix("10.1.1.0", "0.0.0.255") == "10.1.1.0/24"
    assert wildcard_to_prefix("10.1.1.5", "0.0.0.0") == "10.1.1.5/32"
    with pytest.raises(ValueError):
        wildcard_to_prefix("10.1.1.0", "0.0.255.1")


def test_coverage_maths():
    assert net_covers("any", "10.0.0.0/8") and net_covers("10.0.0.0/8", "10.1.0.0/16")
    assert not net_covers("10.1.0.0/16", "10.0.0.0/8") and not net_covers("10.0.0.0/8", "any")
    assert ports_cover([], [(22, 22)]) and ports_cover([(1, 1024)], [(22, 22)])
    assert not ports_cover([(22, 22)], [(1, 1024)]) and not ports_cover([(22, 22)], [])
    assert port_span([]) == 65536 and port_span([(80, 80), (443, 443)]) == 2


# ---------- parsers ----------
def test_cisco_parses_names_ranges_and_bindings():
    cfg = cisco.parse("""ip access-list extended A
 10 permit tcp 10.0.0.0 0.0.0.255 any eq www 443
 permit tcp any any range 8000 8100 log
interface Gi0/0
 ip access-group A in
""")
    r1, r2 = cfg.rules
    assert r1.src == "10.0.0.0/24" and r1.dst_ports == [(80, 80), (443, 443)] and r1.direction == "in"
    assert r2.dst_ports == [(8000, 8100)] and r2.log


def test_cisco_numbered_standard_and_object_group_warning():
    cfg = cisco.parse("access-list 10 permit 192.168.1.0 0.0.0.255\n"
                      "ip access-list extended B\n permit tcp object-group USERS any eq 22\n")
    assert cfg.rules[0].src == "192.168.1.0/24" and cfg.rules[0].container == "10"
    assert len(cfg.warnings) == 1 and "object-group" in cfg.warnings[0]


def test_iptables_parses_multiport_policy_and_log():
    cfg = iptables.parse("*filter\n:INPUT DROP [0:0]\n"
                         "-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT\n"
                         "-A INPUT -j LOG\n-A INPUT -j DROP\nCOMMIT\n")
    assert cfg.policies["INPUT"] == "DROP" and "INPUT" in cfg.logged_containers
    assert cfg.rules[0].dst_ports == [(80, 80), (443, 443)] and len(cfg.rules) == 2


def test_iptables_ignores_nat_table():
    cfg = iptables.parse("*nat\n-A PREROUTING -p tcp --dport 80 -j ACCEPT\nCOMMIT\n*filter\n:INPUT DROP [0:0]\nCOMMIT\n")
    assert cfg.rules == []


def test_iptables_script_style():
    cfg = iptables.parse("iptables -P INPUT DROP\niptables -A INPUT -p tcp --dport 22 -j ACCEPT\n")
    assert cfg.policies["INPUT"] == "DROP" and len(cfg.rules) == 1


# ---------- checks ----------
def test_any_any_detected_but_established_and_loopback_are_not():
    assert "FW-001" in ids("ip access-list extended X\n permit ip any any\n", cisco.parse)
    safe = "*filter\n:INPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\nCOMMIT\n"
    assert "FW-001" not in ids(safe, iptables.parse)


def test_risky_port_severity():
    res = analyze(cisco.parse("ip access-list extended X\n permit tcp any any eq telnet\n permit tcp any any eq 22\n"))
    sev = {f.rule.index: f.severity for f in res.findings if f.check_id == "FW-002"}
    assert sev == {1: Severity.CRITICAL, 2: Severity.MEDIUM}


def test_trusted_source_is_not_flagged():
    assert "FW-002" not in ids("ip access-list extended X\n permit tcp 10.0.0.0 0.0.0.255 any eq 22\n deny ip any any log\n", cisco.parse)


def test_shadow_conflict_vs_redundant():
    res = analyze(cisco.parse("ip access-list extended X\n permit tcp any any eq 80\n deny tcp any any eq 80\n permit tcp any any eq 80\n"))
    shadow = [f for f in res.findings if f.check_id == "FW-006"]
    assert [f.severity for f in shadow] == [Severity.HIGH, Severity.LOW]


def test_narrower_earlier_rule_does_not_shadow_broader_later_rule():
    assert "FW-006" not in ids("ip access-list extended X\n permit tcp any host 1.1.1.1 eq 80\n permit tcp any any eq 80\n", cisco.parse)


def test_default_permit_chain_flagged():
    assert "FW-004" in ids("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 80 -j ACCEPT\nCOMMIT\n", iptables.parse)


def test_unapplied_acl_flagged_only_when_unbound():
    base = "ip access-list extended X\n permit tcp any host 1.1.1.1 eq 443\n deny ip any any log\n"
    assert "FW-007" in ids(base, cisco.parse)
    assert "FW-007" not in ids(base + "interface Gi0/0\n ip access-group X in\n", cisco.parse)


# ---------- samples & CLI ----------
def test_hardened_sample_is_clean():
    res = analyze(iptables.parse((SAMPLES / "iptables_hardened.rules").read_text()))
    assert res.findings == [] and res.score == 100 and res.grade == "A"


def test_bad_samples_score_poorly():
    for name, parser in [("cisco_edge_bad.cfg", cisco.parse), ("iptables_bad.rules", iptables.parse)]:
        res = analyze(parser((SAMPLES / name).read_text()))
        assert res.grade == "F" and res.worst() == Severity.CRITICAL


def test_vendor_autodetect():
    assert detect_vendor("*filter\n") == "iptables" and detect_vendor("ip access-list extended A\n") == "cisco"
    with pytest.raises(ValueError):
        detect_vendor("hello world")


def test_cli_exit_codes_and_json(tmp_path, capsys):
    bad, good = str(SAMPLES / "iptables_bad.rules"), str(SAMPLES / "iptables_hardened.rules")
    assert main(["audit", bad, "--fail-on", "high", "--no-color"]) == 1
    assert main(["audit", good, "--fail-on", "low", "--no-color"]) == 0
    assert main(["audit", str(tmp_path / "missing.cfg")]) == 2
    capsys.readouterr()
    out = tmp_path / "r.json"
    main(["audit", bad, "-f", "json", "-o", str(out)])
    data = json.loads(out.read_text())
    assert data["grade"] == "F" and data["findings"][0]["severity"] == "Critical"


def test_html_report_escapes_content(tmp_path):
    cfg = cisco.parse("ip access-list extended <script>alert(1)</script>\n permit ip any any\n")
    from fwaudit.report import render_html
    page = render_html(analyze(cfg))
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
