"""Report renderers: console, JSON, Markdown, HTML."""

from __future__ import annotations

import html
import json
from collections import Counter
from typing import Dict, List

from .model import SEV_RANK, SEVERITIES, CheckResult

COLOURS = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[36m",
           "PASS": "\033[32m", "ERROR": "\033[35m", "FAIL": "\033[31m"}
RESET = "\033[0m"


def summarise(results: List[CheckResult]) -> Dict:
    sev = Counter(f.severity for r in results for f in r.findings)
    status = Counter(r.status for r in results)
    return {
        "checks": len(results),
        "passed": status["PASS"], "failed": status["FAIL"], "not_assessed": status["ERROR"],
        "findings": sum(sev.values()),
        "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
    }


def _sorted(findings):
    return sorted(findings, key=lambda f: (-SEV_RANK[f.severity], f.resource, f.region))


def to_dict(results: List[CheckResult], meta: Dict) -> Dict:
    return {
        "meta": meta,
        "summary": summarise(results),
        "checks": [{
            "id": r.meta.id, "title": r.meta.title, "service": r.meta.service,
            "status": r.status, "evaluated": r.evaluated,
            "mappings": {"cis_aws_v3": list(r.meta.cis), "iso27001_2022": list(r.meta.iso27001),
                         "nis2": list(r.meta.nis2)},
            "remediation": r.meta.remediation,
            "findings": [f.__dict__ for f in _sorted(r.findings)],
            "errors": r.errors,
        } for r in results],
    }


def to_json(results, meta) -> str:
    return json.dumps(to_dict(results, meta), indent=2)


def to_console(results, meta, colour: bool) -> str:
    def c(key: str, text: str) -> str:
        return f"{COLOURS[key]}{text}{RESET}" if colour else text

    s = summarise(results)
    lines = [f"AWS posture check  account {meta['account']}  {meta['generated']}"
             + ("  [DEMO DATA]" if meta.get("demo") else ""),
             f"Regions: {', '.join(meta['regions'])}", ""]
    for r in results:
        lines.append(f"{c(r.status, f'{r.status:<5}')}  {r.meta.id:<8} {r.meta.title}"
                     f"  ({r.evaluated} evaluated, {len(r.findings)} findings)")
        for f in _sorted(r.findings):
            lines.append(f"        {c(f.severity, f'{f.severity:<8}')} {f.resource} [{f.region}] {f.message}")
        for e in r.errors:
            lines.append(f"        {c('ERROR', 'NOT ASSESSED')} {e}")
    sev = s["by_severity"]
    lines += ["", f"{s['findings']} findings: " + ", ".join(f"{sev[k]} {k.lower()}" for k in SEVERITIES),
              f"Checks: {s['passed']} passed, {s['failed']} failed, {s['not_assessed']} not assessed"]
    return "\n".join(lines)


def to_markdown(results, meta) -> str:
    s = summarise(results)
    sev = s["by_severity"]
    out = ["# AWS cloud security posture report", "",
           f"Account `{meta['account']}` · generated {meta['generated']} · tool v{meta['version']}"
           + (" · **demo data, not a real account**" if meta.get("demo") else ""),
           f"Regions: {', '.join(meta['regions'])}", "",
           "## Summary", "",
           f"{s['findings']} findings ({', '.join(f'{sev[k]} {k.lower()}' for k in SEVERITIES)}). "
           f"{s['passed']} of {s['checks']} checks passed, {s['failed']} failed, "
           f"{s['not_assessed']} could not be assessed.", "",
           "| Check | Status | Findings | Title |", "|---|---|---|---|"]
    for r in results:
        out.append(f"| {r.meta.id} | {r.status} | {len(r.findings)} | {r.meta.title} |")
    for r in results:
        if r.status == "PASS":
            continue
        out += ["", f"## {r.meta.id}: {r.meta.title}", "",
                f"Mappings: CIS AWS v3.0 {', '.join(r.meta.cis) or 'n/a'} · ISO/IEC 27001:2022 "
                f"{', '.join(r.meta.iso27001)} · NIS2 {', '.join(r.meta.nis2)}", ""]
        if r.findings:
            out += ["| Severity | Resource | Region | Finding |", "|---|---|---|---|"]
            for f in _sorted(r.findings):
                msg = f.message.replace("|", "\\|")
                out.append(f"| {f.severity} | `{f.resource}` | {f.region} | {msg} |")
            out += ["", f"**Remediation:** {r.meta.remediation}"]
        for e in r.errors:
            out += ["", f"> Not assessed: {e}"]
    return "\n".join(out) + "\n"


_CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--mut:#6b6a63;--line:#e2dfd6;--card:#fff;--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#0f766e;--ok:#166534;--err:#6d28d9}
@media (prefers-color-scheme:dark){:root{--bg:#141412;--fg:#ecebe6;--mut:#a3a197;--line:#33322d;--card:#1c1c19;--crit:#f87171;--high:#fb923c;--med:#facc15;--low:#5eead4;--ok:#86efac;--err:#c4b5fd}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px}
.mut{color:var(--mut)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}.card b{display:block;font-size:24px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600}
.CRITICAL{color:var(--crit)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}.LOW{color:var(--low)}.PASS{color:var(--ok)}.FAIL{color:var(--crit)}.ERROR{color:var(--err)}
td:first-child{white-space:nowrap}.b{font-weight:700}code{font-size:13px;word-break:break-all}.wrap{overflow-x:auto}
"""


def to_html(results, meta) -> str:
    e = html.escape
    s = summarise(results)
    sev = s["by_severity"]
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>AWS posture report</title><style>{_CSS}</style></head><body><main>",
             "<h1>AWS cloud security posture report</h1>",
             f"<p class='mut'>Account <code>{e(meta['account'])}</code> · {e(meta['generated'])} · "
             f"v{e(meta['version'])} · regions: {e(', '.join(meta['regions']))}"
             + (" · <b>demo data, not a real account</b>" if meta.get("demo") else "") + "</p>",
             "<div class='cards'>"]
    for k in SEVERITIES:
        parts.append(f"<div class='card'><b class='{k}'>{sev[k]}</b><span class='mut'>{k.title()}</span></div>")
    parts.append(f"<div class='card'><b>{s['passed']}/{s['checks']}</b><span class='mut'>Checks passed</span></div></div>")
    parts.append("<h2>Checks</h2><div class='wrap'><table><tr><th>ID</th><th>Status</th><th>Findings</th><th>Check</th>"
                 "<th>CIS</th><th>ISO 27001</th><th>NIS2</th></tr>")
    for r in results:
        parts.append(f"<tr><td>{e(r.meta.id)}</td><td class='b {r.status}'>{r.status}</td><td>{len(r.findings)}</td>"
                     f"<td>{e(r.meta.title)}</td><td>{e(', '.join(r.meta.cis))}</td>"
                     f"<td>{e(', '.join(r.meta.iso27001))}</td><td>{e(', '.join(r.meta.nis2))}</td></tr>")
    parts.append("</table></div>")
    for r in results:
        if r.status == "PASS":
            continue
        parts.append(f"<h2>{e(r.meta.id)}: {e(r.meta.title)}</h2>")
        if r.findings:
            parts.append("<div class='wrap'><table><tr><th>Severity</th><th>Resource</th><th>Region</th><th>Finding</th></tr>")
            for f in _sorted(r.findings):
                parts.append(f"<tr><td class='b {f.severity}'>{f.severity}</td><td><code>{e(f.resource)}</code></td>"
                             f"<td>{e(f.region)}</td><td>{e(f.message)}</td></tr>")
            parts.append(f"</table></div><p><b>Remediation:</b> {e(r.meta.remediation)}</p>")
        for err in r.errors:
            parts.append(f"<p class='ERROR'>Not assessed: {e(err)}</p>")
    parts.append("</main></body></html>")
    return "".join(parts)
