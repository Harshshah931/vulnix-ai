from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import streamlit as st

from vulnix.ai_assistant import generate_ai_summary, local_summary
from vulnix.demo import sample_report
from vulnix.reporting import to_csv_bytes, to_html_bytes, to_json_bytes
from vulnix.scanner import scan_website
from vulnix.url_safety import URLSafetyError

BASE_DIR = Path(__file__).resolve().parent
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
SEVERITY_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Informational": "⚪"}

st.set_page_config(
    page_title="Vulnix AI — Website Security Analysis",
    page_icon=str(BASE_DIR / "assets" / "vulnix_mark.png"),
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
      :root { --vx-ink:#eaf0ff; --vx-muted:#9aa9c4; --vx-border:rgba(148,163,184,.20); }
      html, body, [class*="css"] { font-family:'DM Sans',sans-serif; }
      .stApp { background: radial-gradient(ellipse at 18% -12%, rgba(43,89,167,.30), transparent 38%), #091121; color:var(--vx-ink); }
      [data-testid="stHeader"] { background:rgba(9,17,33,.75); }
      [data-testid="stSidebar"] { background:linear-gradient(180deg,#101c32 0%,#0b1425 100%); border-right:1px solid var(--vx-border); }
      [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#c5d1e7; }
      .vx-hero { padding:1.2rem 0 .8rem; }
      .vx-kicker { font-family:'Space Grotesk',sans-serif; text-transform:uppercase; color:#8adcf2; letter-spacing:.17em; font-size:.74rem; font-weight:700; }
      .vx-title { font-family:'Space Grotesk',sans-serif; font-size:clamp(2.1rem,4vw,3.2rem); line-height:1.06; letter-spacing:-.055em; font-weight:700; margin:.35rem 0 .65rem; color:#f7faff; }
      .vx-grad { background:linear-gradient(95deg,#7dd3fc,#a5b4fc 65%,#c4b5fd); -webkit-background-clip:text; background-clip:text; color:transparent; }
      .vx-subtitle { max-width:780px; color:#aebbd2; line-height:1.65; font-size:1.02rem; }
      .vx-panel { border:1px solid var(--vx-border); border-radius:18px; padding:1.1rem 1.2rem; background:linear-gradient(145deg,rgba(20,34,59,.88),rgba(12,22,40,.88)); box-shadow:0 16px 36px rgba(0,0,0,.10); }
      .vx-panel-label { font-size:.75rem; text-transform:uppercase; letter-spacing:.12em; color:#93a5c4; font-weight:700; margin-bottom:.45rem; }
      .vx-stat-label { color:#a7b5cd; font-size:.82rem; }
      .vx-stat-value { font-family:'Space Grotesk',sans-serif; font-size:2rem; font-weight:700; line-height:1.3; color:#f4f7ff; }
      .vx-chip { display:inline-block; border:1px solid rgba(125,211,252,.35); background:rgba(14,116,144,.12); color:#a5f3fc; border-radius:999px; padding:.22rem .62rem; font-size:.76rem; font-weight:600; }
      .vx-rule { border:0; border-top:1px solid var(--vx-border); margin:1.2rem 0; }
      .vx-muted { color:#9aa9c4; font-size:.88rem; }
      .vx-section { font-family:'Space Grotesk',sans-serif; font-size:1.28rem; font-weight:600; color:#f4f7ff; margin:.1rem 0 .6rem; }
      .vx-footer { color:#73839f; font-size:.76rem; border-top:1px solid var(--vx-border); padding-top:1rem; margin-top:2rem; }
      div[data-testid="stMetric"] { background:rgba(21,36,62,.75); border:1px solid var(--vx-border); border-radius:15px; padding:1rem; }
      div[data-testid="stMetricLabel"] { color:#9aa9c4; }
      div[data-testid="stMetricValue"] { color:#f4f7ff; font-family:'Space Grotesk',sans-serif; }
      .stButton>button, .stDownloadButton>button { border-radius:10px; border:1px solid rgba(125,211,252,.28); font-weight:650; transition:all .18s ease; }
      .stButton>button[kind="primary"] { background:linear-gradient(95deg,#0891b2,#4f46e5); border:0; color:white; }
      .stButton>button:hover, .stDownloadButton>button:hover { border-color:#67e8f9; transform:translateY(-1px); }
      .stTextInput input { border-radius:10px; }
      div[data-testid="stExpander"] { border:1px solid var(--vx-border); border-radius:12px; background:rgba(15,27,48,.55); }
      .stAlert { border-radius:12px; }
      a { color:#7dd3fc !important; }
    </style>
    """,
    unsafe_allow_html=True,
)


def init_state() -> None:
    defaults = {"scan_result": None, "ai_summary": "", "ai_remote": False, "is_demo": False}
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def severity_counts(findings: list[dict]) -> Counter:
    counts = Counter(item.get("severity", "Informational") for item in findings)
    for severity in SEVERITY_ORDER:
        counts.setdefault(severity, 0)
    return counts


def human_time(value: str) -> str:
    return value.replace("T", " ").replace("+00:00", " UTC") if value else "—"


def render_finding(finding: dict, index: int) -> None:
    severity = finding.get("severity", "Informational")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    with st.expander(f"{emoji}  {finding.get('title', 'Untitled finding')}  ·  {severity}", expanded=(severity in {"Critical", "High"})):
        col_a, col_b = st.columns([1, 2])
        with col_a:
            st.caption(f"{finding.get('id', 'VX-UNKNOWN')} · {finding.get('category', 'General')}")
            st.markdown(f"**Confidence:** {finding.get('confidence', 'Not rated')}")
            st.markdown(f"**Finding type:** {finding.get('status', 'Potential weakness')}")
        with col_b:
            st.markdown("**Observed evidence**")
            st.code(finding.get("evidence", "No evidence was attached."), language="text")
        st.markdown("**Why it matters**")
        st.write(finding.get("impact", "Review this result in context."))
        st.markdown("**Recommended fix**")
        st.write(finding.get("remediation", "Review the configuration and verify the change."))
        reference = finding.get("reference", "")
        if reference.startswith("https://"):
            st.markdown(f"Reference: [{reference}]({reference})")


init_state()

with st.sidebar:
    logo_path = BASE_DIR / "assets" / "vulnix_mark.png"
    if logo_path.exists():
        st.image(str(logo_path), width=66)
    st.markdown("<div style='font-family:Space Grotesk,sans-serif;font-size:1.55rem;font-weight:700;letter-spacing:-.04em'>Vulnix <span style='color:#7dd3fc'>AI</span></div>", unsafe_allow_html=True)
    st.caption("AI-powered website security analysis")
    st.markdown('<hr class="vx-rule">', unsafe_allow_html=True)
    st.markdown("#### Start a scan")
    entered_url = st.text_input("Website URL", placeholder="https://yourdomain.com", help="Only public HTTP/HTTPS hosts on standard ports are accepted.")
    consent = st.checkbox("I own this website or have explicit permission to test it.")
    scan_clicked = st.button("Run security scan", type="primary", width="stretch", disabled=not consent or not entered_url.strip())
    st.markdown('<div class="vx-muted">Non-invasive checks only · No exploit payloads · No login attempts</div>', unsafe_allow_html=True)
    st.markdown('<hr class="vx-rule">', unsafe_allow_html=True)
    st.markdown("#### Optional AI provider")
    env_key = os.getenv("OPENAI_API_KEY", "").strip()
    api_key_input = st.text_input("OpenAI API key", type="password", placeholder="Optional — not saved", help="Use an environment variable for deployment. The key is not included in reports.")
    model_default = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    model_choice = st.text_input("Model", value=model_default, help="Uses the model name available to your API account.")
    if env_key:
        st.caption("An API key is configured in the environment.")
    else:
        st.caption("Without a key, Vulnix uses a clearly labelled local rules-based summary.")
    demo_clicked = st.button("Load sample report", width="stretch")
    st.caption("Sample report is synthetic and does not contact any website.")

st.markdown(
    """
    <div class="vx-hero">
      <div class="vx-kicker">Website defense · Made understandable</div>
      <div class="vx-title">Find weaknesses.<br><span class="vx-grad">Fix them with confidence.</span></div>
      <div class="vx-subtitle">Vulnix AI inspects a public website response for common security-configuration gaps, shows the evidence, and turns each finding into a practical developer action.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="vx-panel"><span class="vx-chip">MVP · Safe scan mode</span><p style="margin:.7rem 0 .15rem;color:#e4ecfb;font-size:.95rem"><strong>Scope matters.</strong> This prototype checks public response headers, TLS certificate information, cookies and visible HTML. It does not exploit vulnerabilities, test authenticated routes, or prove a website is secure.</p></div>',
    unsafe_allow_html=True,
)

if scan_clicked:
    st.session_state.scan_result = None
    st.session_state.ai_summary = ""
    st.session_state.ai_remote = False
    st.session_state.is_demo = False
    try:
        with st.spinner("Checking the destination and inspecting its public response…"):
            result_obj = scan_website(entered_url, authorization_confirmed=consent)
        result = result_obj.to_dict()
        st.session_state.scan_result = result
        st.session_state.ai_summary = local_summary(result.get("findings", []))
        st.success("Scan finished. Review the evidence and verify fixes before marking a finding resolved.")
    except URLSafetyError as exc:
        st.error(str(exc))
    except Exception as exc:
        st.error(f"The scan could not be completed ({type(exc).__name__}). Check the URL and try again.")

if demo_clicked:
    result = sample_report()
    st.session_state.scan_result = result
    st.session_state.ai_summary = local_summary(result.get("findings", []))
    st.session_state.ai_remote = False
    st.session_state.is_demo = True

result = st.session_state.scan_result
if result:
    is_demo = st.session_state.is_demo or str(result.get("scan_mode", "")).startswith("synthetic")
    if is_demo:
        st.warning("SAMPLE DATA ONLY — this is a simulated report. No real website was contacted.")

    st.markdown('<hr class="vx-rule">', unsafe_allow_html=True)
    top_left, top_right = st.columns([2.3, 1])
    with top_left:
        st.markdown('<div class="vx-section">Security report</div>', unsafe_allow_html=True)
        page_title = result.get("page_title") or "Untitled website"
        st.subheader(page_title)
        st.caption(f"Requested: {result.get('requested_url', '—')}  ·  Final: {result.get('final_url', '—')}")
    with top_right:
        status = result.get("status_code")
        if status is not None:
            st.markdown(f"<div class='vx-panel'><div class='vx-panel-label'>HTTP response</div><div class='vx-stat-value'>{status}</div><div class='vx-muted'>{result.get('content_type') or 'Content type unavailable'}</div></div>", unsafe_allow_html=True)
        else:
            st.markdown(f"<div class='vx-panel'><div class='vx-panel-label'>HTTP response</div><div class='vx-stat-value'>N/A</div><div class='vx-muted'>Response not available</div></div>", unsafe_allow_html=True)

    findings = result.get("findings", [])
    counts = severity_counts(findings)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total findings", len(findings))
    c2.metric("Critical / High", counts["Critical"] + counts["High"])
    c3.metric("Medium", counts["Medium"])
    c4.metric("Low", counts["Low"])
    c5.metric("Informational", counts["Informational"])

    st.markdown('<div class="vx-section" style="margin-top:1.4rem">AI-assisted interpretation</div>', unsafe_allow_html=True)
    st.markdown('<div class="vx-muted">Model-generated explanation is optional. When no provider key is configured, the displayed summary is rule-based and clearly identified as such.</div>', unsafe_allow_html=True)
    ai_col, ai_btn_col = st.columns([4, 1.3])
    with ai_btn_col:
        run_ai = st.button("Generate AI insights", width="stretch", disabled=False)
    if run_ai:
        with st.spinner("Preparing a concise, evidence-grounded explanation…"):
            summary, remote_used = generate_ai_summary(
                target_url=result.get("final_url", ""),
                findings=findings,
                api_key=api_key_input.strip() or env_key or None,
                model=model_choice.strip() or model_default,
            )
        st.session_state.ai_summary = summary
        st.session_state.ai_remote = remote_used
    with ai_col:
        if st.session_state.ai_remote:
            st.markdown('<span class="vx-chip">Model-assisted summary</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="vx-chip">Local rules-based summary</span>', unsafe_allow_html=True)
    st.markdown('<div class="vx-panel">' + st.session_state.ai_summary.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>") + '</div>', unsafe_allow_html=True)
    if not st.session_state.ai_remote:
        st.caption("To enable model-generated summaries, configure OPENAI_API_KEY or enter a key in the sidebar. A local fallback remains available without an API key.")

    tab_overview, tab_findings, tab_technical, tab_export = st.tabs(["Overview", "Findings & fixes", "Technical details", "Export report"])
    with tab_overview:
        left, right = st.columns([1.15, 1])
        with left:
            st.markdown("##### Findings by severity")
            severity_rows = [(name, counts[name]) for name in ["Critical", "High", "Medium", "Low", "Informational"]]
            max_count = max([n for _, n in severity_rows] + [1])
            for label, count in severity_rows:
                label_col, bar_col, num_col = st.columns([1.4, 4, .5])
                label_col.write(label)
                bar_col.progress(count / max_count if max_count else 0.0)
                num_col.write(str(count))
            if not findings:
                st.info("No findings were recorded by the enabled checks. This does not establish that the website is secure.")
        with right:
            st.markdown("##### Scan metadata")
            st.write(f"**Started:** {human_time(result.get('started_at', ''))}")
            st.write(f"**Finished:** {human_time(result.get('finished_at', ''))}")
            st.write(f"**Duration:** {result.get('duration_seconds', '—')} seconds")
            st.write(f"**Mode:** {result.get('scan_mode', 'non-invasive public-page analysis')}")
            st.write(f"**HTML truncated:** {'Yes' if result.get('truncated') else 'No'}")
        if result.get("warnings"):
            with st.expander("Warnings and scope notes", expanded=True):
                for warning in result["warnings"]:
                    st.warning(warning)
        if result.get("errors"):
            with st.expander("Errors encountered", expanded=True):
                for error in result["errors"]:
                    st.error(error)

    with tab_findings:
        filter_options = [name for name in ["Critical", "High", "Medium", "Low", "Informational"] if counts[name] > 0]
        selected_severities = st.multiselect("Filter by severity", options=filter_options, default=filter_options)
        visible = [item for item in findings if item.get("severity") in selected_severities]
        visible.sort(key=lambda item: (SEVERITY_ORDER.get(item.get("severity", "Informational"), 9), item.get("title", "").lower()))
        st.caption(f"Showing {len(visible)} of {len(findings)} findings. Severity is a preliminary prioritisation, not proof of exploitability.")
        if visible:
            for index, finding in enumerate(visible):
                render_finding(finding, index)
        else:
            st.info("No findings match the selected severity filters.")

    with tab_technical:
        st.markdown("##### Connection and response")
        meta_left, meta_right = st.columns(2)
        with meta_left:
            st.write(f"**Requested URL:** {result.get('requested_url') or '—'}")
            st.write(f"**Final URL:** {result.get('final_url') or '—'}")
            st.write(f"**HTTP status:** {result.get('status_code') if result.get('status_code') is not None else '—'}")
            st.write(f"**Content type:** {result.get('content_type') or '—'}")
            st.write(f"**Server header:** {result.get('server') or 'Not disclosed / not captured'}")
        with meta_right:
            tls = result.get("tls") or {}
            st.write(f"**TLS checked:** {'Yes' if tls.get('checked') else 'No / not available'}")
            st.write(f"**Certificate verified:** {'Yes' if tls.get('verified') else ('No' if tls.get('verified') is False else 'Unknown')}")
            st.write(f"**TLS version:** {tls.get('tls_version') or '—'}")
            st.write(f"**Certificate expiry:** {tls.get('not_after') or '—'}")
            st.write(f"**Issuer:** {tls.get('issuer') or '—'}")
            if tls.get("verification_error"):
                st.error(tls["verification_error"])
            elif tls.get("error"):
                st.info(tls["error"])
        if result.get("redirect_chain"):
            st.markdown("##### Redirect chain")
            st.dataframe(result["redirect_chain"], width="stretch", hide_index=True)
        st.markdown("##### Scope limitation")
        st.write("The scanner makes a small number of HTTP GET requests, follows same-host redirects only, does not log in, does not submit forms, and does not try attack payloads. It checks only the final inspected public response and visible HTML. Production deployments should enforce outbound network controls at the infrastructure layer as well.")

    with tab_export:
        st.markdown("##### Download this report")
        st.write("Reports contain observations and remediation guidance; they do not contain cookie values or the page's full HTML source.")
        host = urlsplit(result.get("final_url", "") or "").hostname or "website"
        filename_host = "".join(char if char.isalnum() or char in "-._" else "_" for char in host)[:80] or "website"
        e1, e2, e3 = st.columns(3)
        export_result = dict(result)
        export_result["analysis_summary"] = st.session_state.ai_summary
        export_result["analysis_summary_source"] = "model-assisted" if st.session_state.ai_remote else "local-rules-based"
        with e1:
            st.download_button("Download JSON", data=to_json_bytes(export_result), file_name=f"vulnix-report-{filename_host}.json", mime="application/json", width="stretch")
        with e2:
            st.download_button("Download CSV", data=to_csv_bytes(result), file_name=f"vulnix-findings-{filename_host}.csv", mime="text/csv", width="stretch")
        with e3:
            st.download_button("Download HTML report", data=to_html_bytes(result, st.session_state.ai_summary), file_name=f"vulnix-report-{filename_host}.html", mime="text/html", width="stretch")
        st.caption("The HTML report can be opened in a browser and printed or saved as PDF.")

else:
    st.markdown('<hr class="vx-rule">', unsafe_allow_html=True)
    st.markdown('<div class="vx-section">What Vulnix checks</div>', unsafe_allow_html=True)
    feature_cols = st.columns(3)
    feature_data = [
        ("01", "Transport security", "HTTP/HTTPS handling, TLS certificate validation, and certificate expiry."),
        ("02", "Browser protections", "CSP, HSTS, framing protections, content-type and referrer policies."),
        ("03", "Cookies & forms", "Visible cookie attributes and unsafe password form destinations/methods."),
        ("04", "Resource loading", "Potential mixed content and cross-origin scripts without integrity metadata."),
        ("05", "Evidence-first findings", "Each result includes the observation, likely impact, confidence, and suggested fix."),
        ("06", "Shareable reports", "Export findings as JSON, CSV, or a standalone HTML report."),
    ]
    for index, (number, title, copy) in enumerate(feature_data):
        with feature_cols[index % 3]:
            st.markdown(f"<div class='vx-panel' style='min-height:175px;margin-bottom:14px'><div class='vx-panel-label'>{number} / CAPABILITY</div><div style='font-family:Space Grotesk,sans-serif;font-size:1.08rem;font-weight:600;margin:.25rem 0 .55rem;color:#eef5ff'>{title}</div><div class='vx-muted'>{copy}</div></div>", unsafe_allow_html=True)
    st.markdown('<div class="vx-panel"><div class="vx-panel-label">Try it without contacting a real website</div><p style="color:#c7d3e8;margin:.3rem 0">Use <strong>Load sample report</strong> in the sidebar to explore a simulated report with example findings, evidence, recommended fixes, and exports. When you are ready, scan only a website you own or have permission to test.</p></div>', unsafe_allow_html=True)

st.markdown('<div class="vx-footer">Vulnix AI v1.1 · Built for authorised, non-invasive security analysis · Findings are indicative and do not replace a professional security assessment.</div>', unsafe_allow_html=True)
