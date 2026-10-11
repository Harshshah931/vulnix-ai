"""Export helpers for JSON, CSV, and standalone HTML reports."""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from typing import Any


def to_json_bytes(result: dict[str, Any]) -> bytes:
    return json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8")


def to_csv_bytes(result: dict[str, Any]) -> bytes:
    def spreadsheet_safe(value: Any) -> str:
        """Reduce CSV formula-injection risk when reports are opened in spreadsheet apps."""
        text = "" if value is None else str(value)
        probe = text.lstrip(" \t\r\n")
        if text.startswith(("\t", "\r", "\n")) or (probe and probe[0] in "=+-@"):
            return "'" + text
        return text

    output = io.StringIO(newline="")
    fields = ["id", "title", "severity", "category", "confidence", "status", "evidence", "impact", "remediation", "reference"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for finding in result.get("findings", []):
        writer.writerow({field: spreadsheet_safe(finding.get(field, "")) for field in fields})
    return output.getvalue().encode("utf-8-sig")


def to_html_bytes(result: dict[str, Any], ai_summary: str = "") -> bytes:
    findings = result.get("findings", [])
    severity_colors = {
        "Critical": "#fecaca", "High": "#fed7aa", "Medium": "#fef08a",
        "Low": "#bfdbfe", "Informational": "#e5e7eb",
    }
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))
    cards = []
    for finding in findings:
        sev = str(finding.get("severity", "Informational"))
        badge = severity_colors.get(sev, "#e5e7eb")
        cards.append(f"""<section class="finding"><div class="finding-head"><h2>{esc(finding.get('title'))}</h2><span class="badge" style="background:{badge}">{esc(sev)}</span></div>
<p class="meta">{esc(finding.get('id'))} · {esc(finding.get('category'))} · Confidence: {esc(finding.get('confidence'))}</p>
<p><strong>Evidence</strong><br>{esc(finding.get('evidence'))}</p><p><strong>Potential impact</strong><br>{esc(finding.get('impact'))}</p>
<p><strong>Recommended remediation</strong><br>{esc(finding.get('remediation'))}</p><p class="meta">Reference: <a href="{esc(finding.get('reference'))}">{esc(finding.get('reference'))}</a></p></section>""")
    summary_block = f"<section class='summary'><h2>Analysis summary</h2><p>{esc(ai_summary).replace(chr(10), '<br>')}</p></section>" if ai_summary else ""
    title = esc(result.get("page_title") or "Website Security Analysis")
    requested = esc(result.get("requested_url", ""))
    final = esc(result.get("final_url", ""))
    warning_html = "".join(f"<li>{esc(value)}</li>" for value in result.get("warnings", []))
    error_html = "".join(f"<li>{esc(value)}</li>" for value in result.get("errors", []))
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vulnix AI Report — {title}</title>
<style>body{{font-family:Inter,Segoe UI,Arial,sans-serif;max-width:980px;margin:40px auto;padding:0 22px;color:#172033;background:#f7f9fc;line-height:1.55}}header{{background:#101d36;color:#fff;border-radius:18px;padding:26px 30px}}header p{{color:#cbd5e1}}h1{{margin:0}}.meta{{color:#667085;font-size:.9rem;overflow-wrap:anywhere}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:12px;margin:18px 0}}.stat,.finding,.summary{{background:#fff;border:1px solid #dfe5ef;border-radius:14px;padding:18px;margin:14px 0;overflow-wrap:anywhere}}.stat strong{{display:block;font-size:1.6rem}}.finding-head{{display:flex;align-items:flex-start;justify-content:space-between;gap:14px}}.finding h2,.summary h2{{font-size:1.13rem;margin:0 0 4px}}.badge{{border-radius:99px;padding:4px 10px;font-size:.82rem;font-weight:700;white-space:nowrap}}a{{color:#1d4ed8}}.notice{{font-size:.9rem;color:#475569}}@media print{{body{{background:#fff;margin:0}}header{{break-inside:avoid}}.finding{{break-inside:avoid}}}}</style></head><body>
<header><p>VULNIX AI · SECURITY ANALYSIS</p><h1>{title}</h1><p>Non-invasive public-page assessment · Generated {esc(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}</p></header>
<div class="grid"><div class="stat"><span>Total findings</span><strong>{len(findings)}</strong></div><div class="stat"><span>High / Critical</span><strong>{sum(1 for f in findings if f.get('severity') in {'High','Critical'})}</strong></div><div class="stat"><span>Medium</span><strong>{sum(1 for f in findings if f.get('severity') == 'Medium')}</strong></div><div class="stat"><span>Low / Informational</span><strong>{sum(1 for f in findings if f.get('severity') in {'Low','Informational'})}</strong></div></div>
<p><strong>Requested URL:</strong> {requested}<br><strong>Final URL:</strong> {final}<br><strong>HTTP status:</strong> {esc(result.get('status_code'))} · <strong>Duration:</strong> {esc(result.get('duration_seconds'))} seconds</p>
<p class="notice">Scope limitation: this report describes a small set of non-invasive checks against the publicly visible response. It is not a penetration test, does not inspect authenticated areas, and cannot certify that the website is secure.</p>
{summary_block}
{('<section class="finding"><h2>Warnings</h2><ul>'+warning_html+'</ul></section>') if warning_html else ''}
{('<section class="finding"><h2>Errors</h2><ul>'+error_html+'</ul></section>') if error_html else ''}
<h2>Findings</h2>{''.join(cards) if cards else '<section class="finding">No findings were recorded by the enabled checks. This does not guarantee security.</section>'}
<footer class="meta">Vulnix AI MVP · For authorised security analysis only.</footer></body></html>"""
    return document.encode("utf-8")
