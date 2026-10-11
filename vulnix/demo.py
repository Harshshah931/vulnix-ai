"""Synthetic demo report. All findings are illustrative, never a live scan."""

from __future__ import annotations

from datetime import datetime, timezone


def sample_report() -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    findings = [
        {
            "id": "VX-HDR-001", "title": "HSTS header not observed", "severity": "Medium", "category": "Security headers", "confidence": "High", "status": "Potential weakness",
            "evidence": "Strict-Transport-Security is absent from the synthetic HTTPS response.",
            "impact": "Browsers are not instructed by this response to remember that the host should only be reached over HTTPS.",
            "remediation": "After confirming HTTPS works across the relevant hosts, configure an appropriate HSTS policy. Add includeSubDomains or preload only after a domain-wide review.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        },
        {
            "id": "VX-HDR-002", "title": "Content Security Policy not observed", "severity": "Medium", "category": "Security headers", "confidence": "High", "status": "Potential weakness",
            "evidence": "Content-Security-Policy is absent from the synthetic response.",
            "impact": "A browser-level defence that can limit script and resource loading is not configured by this response. Its absence alone does not prove XSS.",
            "remediation": "Create and test a CSP based on the resources the application needs. Consider report-only mode before enforcing it.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
        },
        {
            "id": "VX-COOKIE-002", "title": "Session-like cookies missing HttpOnly", "severity": "Medium", "category": "Cookie security", "confidence": "Medium", "status": "Potential weakness",
            "evidence": "Synthetic response cookie name: session_id (cookie value not recorded). HttpOnly was absent.",
            "impact": "If the cookie contains a session credential, JavaScript access can increase the impact of a client-side script injection flaw.",
            "remediation": "Set HttpOnly on session credentials unless client-side JavaScript genuinely needs access; verify the application's design before changing it.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
        },
        {
            "id": "VX-HTML-001", "title": "Potential active mixed content", "severity": "High", "category": "Insecure resource loading", "confidence": "High", "status": "Potential weakness",
            "evidence": "Synthetic HTML references a script with an http:// URL.",
            "impact": "An active resource loaded over HTTP can undermine the security guarantees of an HTTPS page, depending on browser handling.",
            "remediation": "Change active resources to HTTPS, verify their integrity and ownership, and remove obsolete dependencies.",
            "reference": "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
        },
        {
            "id": "VX-INFO-001", "title": "Technology details exposed in response headers", "severity": "Informational", "category": "Information disclosure", "confidence": "High", "status": "Hardening recommendation",
            "evidence": "Synthetic headers: Server: DemoServer/1.2; X-Powered-By: ExampleFramework.",
            "impact": "Technology details can help an attacker profile the stack, but disclosure by itself is not a vulnerability.",
            "remediation": "Remove unnecessary version details from response headers where practical, and prioritise patching and secure configuration.",
            "reference": "https://owasp.org/www-project-web-security-testing-guide/",
        },
    ]
    return {
        "requested_url": "https://demo.vulnix.invalid/", "final_url": "https://demo.vulnix.invalid/",
        "started_at": now, "finished_at": now, "duration_seconds": 1.24, "status_code": 200,
        "content_type": "text/html; charset=utf-8", "page_title": "Sample Storefront — synthetic demonstration",
        "server": "DemoServer/1.2", "tls": {"checked": True, "verified": True, "tls_version": "TLSv1.3", "note": "Synthetic values for demonstration only."},
        "redirect_chain": [], "findings": findings,
        "warnings": ["This is a synthetic sample report. No website was contacted and no real vulnerability was assessed."],
        "errors": [], "truncated": False, "scan_mode": "synthetic demo data; no network activity",
    }
