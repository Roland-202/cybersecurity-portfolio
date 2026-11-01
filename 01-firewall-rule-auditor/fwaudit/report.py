"""Console, JSON and HTML renderers."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from . import __version__
from .analyzer import AuditResult
from .models import Severity

ANSI = {Severity.CRITICAL: "\033[1;97;41m", Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[33m",
        Severity.LOW: "\033[36m", Severity.INFO: "\033[2m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def to_dict(res: AuditResult) -> dict:
    return {
        "tool": "fwaudit", "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": res.config.source, "vendor": res.config.vendor,
        "rules_analyzed": len(res.config.rules), "score": res.score, "grade": res.grade,
        "summary": res.counts, "warnings": res.config.warnings,
        "findings": [f.to_dict() for f in res.findings],
    }


def render_json(res: AuditResult) -> str:
    return json.dumps(to_dict(res), indent=2)


def render_console(res: AuditResult, color: bool = True) -> str:
    c = (lambda code, t: f"{code}{t}{RESET}") if color else (lambda code, t: t)
    out = [c(BOLD, f"fwaudit {__version__}") + f"  {res.config.source} [{res.config.vendor}]",
           f"{len(res.config.rules)} rules analysed | score {c(BOLD, str(res.score))}/100 | grade {c(BOLD, res.grade)}",
           "  ".join(f"{k}: {v}" for k, v in res.counts.items()), ""]
    for f in res.findings:
        where = f"{f.rule.container}#{f.rule.index} (line {f.rule.line_no})" if f.rule else (f.container or "-")
        out.append(f"{c(ANSI[f.severity], f' {f.severity.label.upper():<8}')} {f.check_id}  {f.title}  {c(DIM, '@ ' + where)}")
        out.append(f"           {f.description}")
        if f.rule:
            out.append(c(DIM, f"           > {f.rule.raw}"))
        out.append(f"           Fix: {f.remediation}")
        out.append("")
    if not res.findings:
        out.append("No findings. Nice and tight.")
    for w in res.config.warnings:
        out.append(c(DIM, f"warning: {w}"))
    return "\n".join(out)


_CSS = """
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;--crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#58a6ff;--info:#8b949e;--ok:#3fb950}
@media(prefers-color-scheme:light){:root{--bg:#f6f8fa;--card:#fff;--line:#d0d7de;--fg:#1f2328;--mut:#656d76}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:32px 16px}
.wrap{max-width:1000px;margin:auto}h1{margin:0 0 4px;font-size:24px}.sub{color:var(--mut);margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:28px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card b{display:block;font-size:26px}.card span{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.finding{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:14px 18px;margin-bottom:12px}
.finding h3{margin:0 0 4px;font-size:16px}.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;margin-right:8px;color:#fff;vertical-align:middle}
.Critical{border-left-color:var(--crit)}.Critical .badge{background:var(--crit)}.High{border-left-color:var(--high)}.High .badge{background:var(--high)}
.Medium{border-left-color:var(--med)}.Medium .badge{background:var(--med)}.Low{border-left-color:var(--low)}.Low .badge{background:var(--low)}
.Info{border-left-color:var(--info)}.Info .badge{background:var(--info)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;overflow-x:auto;margin:8px 0}
.meta{color:var(--mut);font-size:13px}.fix{margin-top:6px}.refs{color:var(--mut);font-size:12px;margin-top:6px}
.score{color:var(--ok)}.warn{color:var(--mut);font-size:13px;margin-top:24px}
"""


def render_html(res: AuditResult) -> str:
    e = html.escape
    cards = "".join(f'<div class="card"><b>{v}</b><span>{k}</span></div>' for k, v in res.counts.items())
    items = []
    for f in res.findings:
        where = f"{e(f.rule.container)} #{f.rule.index} &middot; line {f.rule.line_no}" if f.rule else e(f.container or "-")
        rule = f"<pre>{e(f.rule.raw)}</pre>" if f.rule else ""
        items.append(
            f'<div class="finding {f.severity.label}"><h3><span class="badge">{f.severity.label.upper()}</span>'
            f'{e(f.title)}</h3><div class="meta">{e(f.check_id)} &middot; {where}</div><p>{e(f.description)}</p>{rule}'
            f'<div class="fix"><b>Remediation:</b> {e(f.remediation)}</div>'
            f'<div class="refs">{" &middot; ".join(e(r) for r in f.references)}</div></div>')
    warns = "".join(f"<div>{e(w)}</div>" for w in res.config.warnings)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>fwaudit report - {e(res.config.source)}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>Firewall Audit Report</h1>
<div class="sub">{e(res.config.source)} &middot; {e(res.config.vendor)} &middot; {len(res.config.rules)} rules analysed &middot;
generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by fwaudit {__version__}</div>
<div class="grid"><div class="card"><b class="score">{res.score}</b><span>Score / 100</span></div>
<div class="card"><b>{res.grade}</b><span>Grade</span></div>{cards}</div>
{''.join(items) or '<div class="card">No findings.</div>'}
{f'<div class="warn"><b>Parser warnings</b>{warns}</div>' if warns else ''}
</div></body></html>"""
