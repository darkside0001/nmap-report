"""Render scans, risks and diffs as text, Markdown, HTML or JSON.

Banners and script output come from the scanned hosts, so they are treated
as untrusted: everything is HTML-escaped and Markdown table cells are
sanitised, otherwise a device could inject script into the report.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone

from . import __version__
from .diff import ScanDiff
from .parser import Scan
from .rules import Risk

SEV_COLOR = {"critical": "#b42318", "high": "#d9480f", "medium": "#b7791f", "low": "#2b6cb0"}


def _md(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


def _summary(scan: Scan, risks: list[Risk]) -> dict:
    sev = Counter(r.rule.severity for r in risks)
    return {
        "hosts_up": len(scan.hosts),
        "open_ports": sum(len(h.open_ports) for h in scan.hosts),
        "risks": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low")},
        "top_services": Counter(p.service or "unknown" for h in scan.hosts for p in h.open_ports).most_common(8),
    }


# ------------------------------------------------------------------ text

def to_text(scan: Scan, risks: list[Risk], d: ScanDiff | None = None) -> str:
    s = _summary(scan, risks)
    r = s["risks"]
    out = [f"nmap-report  {scan.source}  ({scan.started:%Y-%m-%d %H:%M} UTC)" if scan.started else f"nmap-report  {scan.source}",
           f"Command: {scan.args}" if scan.args else "",
           f"Hosts up: {s['hosts_up']}   Open ports: {s['open_ports']}   "
           f"Risks: {r['critical']} critical, {r['high']} high, {r['medium']} medium, {r['low']} low", ""]
    if risks:
        out.append("RISKS")
        for k in risks:
            out.append(f"  [{k.rule.severity.upper():<8}] {k.host.name:<38} {k.port.key:<10} {k.rule.title}")
            out.append(" " * 13 + k.rule.fix)
        out.append("")
    if d is not None:
        out += [diff_to_text(d), ""]
    out.append("HOSTS")
    for h in scan.hosts:
        out.append(f"  {h.name}" + (f"  [{h.os}]" if h.os else ""))
        for p in h.open_ports:
            out.append(f"     {p.key:<10} {p.service:<16} {p.banner}")
        if not h.open_ports:
            out.append("     no open ports")
    return "\n".join(x for x in out if x is not None) + "\n"


def diff_to_text(d: ScanDiff) -> str:
    out = [f"Changes from {d.old.source} to {d.new.source}"]
    if d.empty:
        return out[0] + "\n  no changes\n"
    for h in d.new_hosts:
        out.append(f"  + host  {h.name}  open: {', '.join(p.key for p in h.open_ports) or 'none'}")
    for h in d.gone_hosts:
        out.append(f"  - host  {h.name}")
    for h, p in d.opened:
        out.append(f"  + port  {h.name:<38} {p.key:<10} {p.service} {p.banner}")
    for h, p in d.closed:
        out.append(f"  - port  {h.name:<38} {p.key:<10} {p.service}")
    for c in d.changed:
        out.append(f"  ~ svc   {c.host:<38} {c.port:<10} {c.before}  ->  {c.after}")
    return "\n".join(out) + "\n"


# -------------------------------------------------------------- markdown

def to_markdown(scan: Scan, risks: list[Risk], d: ScanDiff | None = None) -> str:
    s = _summary(scan, risks)
    r = s["risks"]
    out = [f"# Network scan report: {_md(scan.source)}", ""]
    if scan.started:
        out.append(f"- Scan date: {scan.started:%Y-%m-%d %H:%M} UTC")
    if scan.args:
        out.append(f"- Command: `{scan.args}`")
    out += [f"- Hosts up: **{s['hosts_up']}**, open ports: **{s['open_ports']}**",
            f"- Risks: **{r['critical']} critical**, {r['high']} high, {r['medium']} medium, {r['low']} low", ""]
    if d is not None:
        out += ["## Changes since previous scan", ""]
        if d.empty:
            out.append("No changes.")
        else:
            out += ["| Change | Host | Port | Service |", "|---|---|---|---|"]
            out += [f"| new host | {_md(h.name)} | {', '.join(p.key for p in h.open_ports) or '-'} | |" for h in d.new_hosts]
            out += [f"| host gone | {_md(h.name)} | | |" for h in d.gone_hosts]
            out += [f"| **port opened** | {_md(h.name)} | {p.key} | {_md(p.service)} {_md(p.banner)} |" for h, p in d.opened]
            out += [f"| port closed | {_md(h.name)} | {p.key} | {_md(p.service)} |" for h, p in d.closed]
            out += [f"| service changed | {_md(c.host)} | {c.port} | {_md(c.before)} -> {_md(c.after)} |" for c in d.changed]
        out.append("")
    out += ["## Risks", ""]
    if risks:
        out += ["| Severity | Host | Port | Finding | Why it matters | Fix |", "|---|---|---|---|---|---|"]
        for k in risks:
            out.append(f"| {k.rule.severity} | {_md(k.host.name)} | {k.port.key} | {k.rule.title} | {k.rule.why} | {k.rule.fix} |")
    else:
        out.append("No risky services found.")
    out += ["", "## Hosts", ""]
    for h in scan.hosts:
        out += [f"### {_md(h.name)}", ""]
        if h.os:
            out += [f"OS guess: {_md(h.os)}", ""]
        if h.open_ports:
            out += ["| Port | Service | Version |", "|---|---|---|"]
            out += [f"| {p.key} | {_md(p.service)} | {_md(p.banner)} |" for p in h.open_ports]
        else:
            out.append("No open ports.")
        out.append("")
    return "\n".join(out)


# ------------------------------------------------------------------ html

CSS = """
:root{--bg:#f7f8fa;--card:#fff;--fg:#1a202c;--muted:#5a6473;--line:#e2e6ec;--accent:#0b6e4f}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--fg:#e6e9ee;--muted:#9aa4b2;--line:#2a313b;--accent:#3ccf91}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px}h1{margin:0 0 4px;font-size:26px}h2{margin:32px 0 12px;font-size:19px}
.muted{color:var(--muted)}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}.tile b{display:block;font-size:26px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.sev{display:inline-block;padding:1px 8px;border-radius:99px;color:#fff;font-size:12px;font-weight:600;text-transform:uppercase}
.host{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:10px 0}.host h3{margin:0 0 8px;font-size:16px}
.host table{border:0}.add{color:var(--accent);font-weight:600}.del{color:#d9480f;font-weight:600}
.wrap{overflow-x:auto}footer{margin-top:40px;font-size:13px}
"""


def to_html(scan: Scan, risks: list[Risk], d: ScanDiff | None = None) -> str:
    e = html.escape
    s = _summary(scan, risks)
    r = s["risks"]
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>Scan report: {e(scan.source)}</title><style>{CSS}</style></head><body><main>",
             f"<h1>Network scan report</h1><div class='muted'>{e(scan.source)}"
             + (f" · {scan.started:%Y-%m-%d %H:%M} UTC" if scan.started else "") + "</div>"]
    if scan.args:
        parts.append(f"<p class='muted'><code>{e(scan.args)}</code></p>")
    parts.append("<div class='tiles'>"
                 f"<div class='tile'><b>{s['hosts_up']}</b>hosts up</div>"
                 f"<div class='tile'><b>{s['open_ports']}</b>open ports</div>"
                 + "".join(f"<div class='tile'><b style='color:{SEV_COLOR[k]}'>{r[k]}</b>{k}</div>" for k in ("critical", "high", "medium", "low"))
                 + "</div>")

    if d is not None:
        parts.append(f"<h2>Changes since {e(d.old.source)}</h2>")
        if d.empty:
            parts.append("<p>No changes.</p>")
        else:
            rows = ([f"<tr><td class='add'>new host</td><td>{e(h.name)}</td><td>{e(', '.join(p.key for p in h.open_ports))}</td><td></td></tr>" for h in d.new_hosts]
                    + [f"<tr><td class='del'>host gone</td><td>{e(h.name)}</td><td></td><td></td></tr>" for h in d.gone_hosts]
                    + [f"<tr><td class='add'>port opened</td><td>{e(h.name)}</td><td>{e(p.key)}</td><td>{e(p.service)} {e(p.banner)}</td></tr>" for h, p in d.opened]
                    + [f"<tr><td class='del'>port closed</td><td>{e(h.name)}</td><td>{e(p.key)}</td><td>{e(p.service)}</td></tr>" for h, p in d.closed]
                    + [f"<tr><td>service changed</td><td>{e(c.host)}</td><td>{e(c.port)}</td><td>{e(c.before)} → {e(c.after)}</td></tr>" for c in d.changed])
            parts.append("<div class='wrap'><table><tr><th>Change</th><th>Host</th><th>Port</th><th>Service</th></tr>" + "".join(rows) + "</table></div>")

    parts.append("<h2>Risks</h2>")
    if risks:
        rows = "".join(
            f"<tr><td><span class='sev' style='background:{SEV_COLOR[k.rule.severity]}'>{e(k.rule.severity)}</span></td>"
            f"<td>{e(k.host.name)}</td><td><code>{e(k.port.key)}</code></td><td><b>{e(k.rule.title)}</b><br>"
            f"<span class='muted'>{e(k.rule.why)}</span></td><td>{e(k.rule.fix)}</td></tr>" for k in risks)
        parts.append("<div class='wrap'><table><tr><th>Severity</th><th>Host</th><th>Port</th><th>Finding</th><th>Fix</th></tr>" + rows + "</table></div>")
    else:
        parts.append("<p>No risky services found.</p>")

    parts.append("<h2>Hosts</h2>")
    for h in scan.hosts:
        parts.append(f"<div class='host'><h3>{e(h.name)}</h3>")
        meta = [x for x in (h.os and f"OS: {h.os}", h.vendor and f"Vendor: {h.vendor}") if x]
        if meta:
            parts.append(f"<div class='muted'>{e(' · '.join(meta))}</div>")
        if h.open_ports:
            parts.append("<div class='wrap'><table><tr><th>Port</th><th>Service</th><th>Version</th></tr>"
                         + "".join(f"<tr><td><code>{e(p.key)}</code></td><td>{e(p.service)}</td><td>{e(p.banner)}</td></tr>" for p in h.open_ports)
                         + "</table></div>")
        else:
            parts.append("<p class='muted'>No open ports.</p>")
        parts.append("</div>")
    parts.append(f"<footer class='muted'>Generated by nmap-report {__version__} on "
                 f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC</footer></main></body></html>")
    return "\n".join(parts)


# ------------------------------------------------------------------ json

def to_json(scan: Scan, risks: list[Risk], d: ScanDiff | None = None) -> str:
    s = _summary(scan, risks)
    s["top_services"] = [{"service": k, "count": v} for k, v in s["top_services"]]
    data = {
        "source": scan.source, "args": scan.args,
        "started": scan.started.isoformat() if scan.started else None,
        "summary": s,
        "risks": [k.to_dict() for k in risks],
        "hosts": [{"address": h.address, "hostnames": h.hostnames, "os": h.os, "mac": h.mac, "vendor": h.vendor,
                   "open_ports": [{"port": p.port, "protocol": p.protocol, "service": p.service, "product": p.product,
                                   "version": p.version, "extrainfo": p.extrainfo} for p in h.open_ports]}
                  for h in scan.hosts],
    }
    if d is not None:
        data["diff"] = d.to_dict()
    return json.dumps(data, indent=2)
