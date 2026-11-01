"""Console, JSON and HTML output. All scanned-data is treated as hostile and escaped."""
from __future__ import annotations

import html
import json

from . import __version__
from .models import ScanResult, Severity

ANSI = {Severity.CRITICAL: "\033[1;97;41m", Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[33m",
        Severity.LOW: "\033[36m", Severity.INFO: "\033[2m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def render_json(res: ScanResult) -> str:
    return json.dumps({"tool": "netrecon", "version": __version__, "started": res.started, "finished": res.finished,
                       "ports_scanned": res.ports_scanned, "summary": res.counts,
                       "hosts": [h.to_dict() for h in res.hosts],
                       "findings": [f.to_dict() for f in res.findings]}, indent=2)


def render_console(res: ScanResult, color: bool = True) -> str:
    c = (lambda code, t: f"{code}{t}{RESET}") if color else (lambda code, t: t)
    up = [h for h in res.hosts if h.up]
    out = [c(BOLD, f"netrecon {__version__}") + f"  {len(res.hosts)} host(s) scanned, {len(up)} up, "
           f"{sum(len(h.ports) for h in res.hosts)} open port(s)",
           "  ".join(f"{k}: {v}" for k, v in res.counts.items()), ""]
    for h in up:
        name = f"{h.address}" + (f" ({h.hostname})" if h.hostname else "")
        out.append(c(BOLD, name) + c(DIM, f"   closed {h.closed} / filtered {h.filtered}"))
        if h.ports:
            out.append(f"  {'PORT':<10}{'SERVICE':<14}{'VERSION':<26}BANNER")
        for p in h.ports:
            tls = "+tls" if p.tls else ""
            out.append(f"  {str(p.port) + '/tcp':<10}{(p.service + tls):<14}{p.display:<26}{c(DIM, p.banner[:60])}")
        out.append("")
    for f in res.findings:
        out.append(f"{c(ANSI[f.severity], f' {f.severity.label.upper():<8}')} {f.finding_id}  {f.title}  "
                   f"{c(DIM, f'@ {f.host}:{f.port}  confidence={f.confidence}')}")
        out.append(f"           {f.description}")
        out.append(f"           Fix: {f.remediation}")
        for r in f.references:
            out.append(c(DIM, f"           {r}"))
        out.append("")
    if not res.findings:
        out.append("No findings.")
    return "\n".join(out)


_CSS = """:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;--crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#58a6ff}
@media(prefers-color-scheme:light){:root{--bg:#f6f8fa;--card:#fff;--line:#d0d7de;--fg:#1f2328;--mut:#656d76}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;padding:32px 16px}
.wrap{max-width:1000px;margin:auto}h1{margin:0 0 4px}h2{margin:28px 0 10px;font-size:18px}.sub{color:var(--mut);margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px}.card b{display:block;font-size:24px}
.card span{color:var(--mut);font-size:12px;text-transform:uppercase}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:14px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line)}th{color:var(--mut);font-size:12px;text-transform:uppercase}
td.b{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--mut);word-break:break-all}
.scroll{overflow-x:auto}.finding{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:12px 18px;margin-bottom:10px}
.finding h3{margin:0 0 2px;font-size:16px}.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;margin-right:8px;color:#fff}
.Critical{border-left-color:var(--crit)}.Critical .badge{background:var(--crit)}.High{border-left-color:var(--high)}.High .badge{background:var(--high)}
.Medium{border-left-color:var(--med)}.Medium .badge{background:var(--med)}.Low{border-left-color:var(--low)}.Low .badge{background:var(--low)}
.Info{border-left-color:var(--mut)}.Info .badge{background:var(--mut)}.meta{color:var(--mut);font-size:13px}a{color:var(--low)}"""


def render_html(res: ScanResult) -> str:
    e = html.escape
    cards = "".join(f'<div class="card"><b>{v}</b><span>{k}</span></div>' for k, v in res.counts.items())
    sections = []
    for h in (x for x in res.hosts if x.up):
        rows = "".join(f"<tr><td>{p.port}/tcp</td><td>{e(p.service)}{' (TLS)' if p.tls else ''}</td>"
                       f"<td>{e(p.display)}</td><td class='b'>{e(p.banner[:120])}</td></tr>" for p in h.ports)
        table = (f'<div class="scroll"><table><tr><th>Port</th><th>Service</th><th>Version</th><th>Banner</th></tr>'
                 f'{rows}</table></div>') if rows else '<div class="meta">No open ports.</div>'
        sections.append(f"<h2>{e(h.address)} {e('(' + h.hostname + ')') if h.hostname else ''}</h2>{table}")
    items = []
    for f in res.findings:
        refs = " ".join(f'<a href="{e(r)}" rel="noopener noreferrer">{e(r.rsplit("/", 1)[-1])}</a>'
                        for r in f.references if r.startswith("https://"))
        items.append(f'<div class="finding {f.severity.label}"><h3><span class="badge">{f.severity.label.upper()}</span>'
                     f'{e(f.title)}</h3><div class="meta">{e(f.finding_id)} &middot; {e(f.host)}:{f.port} &middot; '
                     f'confidence {e(f.confidence)}</div><p>{e(f.description)}</p>'
                     f'<div><b>Remediation:</b> {e(f.remediation)}</div><div class="meta">{refs}</div></div>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>netrecon report</title><style>{_CSS}</style></head><body><div class="wrap"><h1>Network Scan Report</h1>
<div class="sub">{len(res.hosts)} host(s) &middot; {res.ports_scanned} probes &middot; {e(res.started)} &middot; netrecon {__version__}</div>
<div class="grid">{cards}</div>{''.join(sections)}<h2>Findings</h2>{''.join(items) or '<div class="card">No findings.</div>'}
<p class="meta">Version-based findings are derived from service banners and may be false positives where vendors backport fixes.</p>
</div></body></html>"""
