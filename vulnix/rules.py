"""Evidence-based, non-invasive website security checks."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from html import unescape
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def _finding(
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    confidence: str,
    evidence: str,
    impact: str,
    remediation: str,
    reference: str,
    *,
    status: str = "Potential weakness",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "confidence": confidence,
        "status": status,
        "evidence": evidence[:1200],
        "impact": impact,
        "remediation": remediation,
        "reference": reference,
    }


def _header(headers: dict[str, Any], name: str) -> str:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == wanted:
            return str(value).strip()
    return ""


def _csp_directives(policy: str) -> dict[str, list[str]]:
    """Parse the simple directive/source-token shape needed for conservative checks."""
    parsed: dict[str, list[str]] = {}
    for section in policy.split(";"):
        tokens = section.strip().split()
        if tokens:
            parsed[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    return parsed


def _sanitise_resource_url(value: str) -> str:
    """Remove query strings/fragments before putting page resource URLs in reports."""
    try:
        parsed = urlsplit(value)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    except (TypeError, ValueError):
        return value.split("?", 1)[0].split("#", 1)[0]


def _cookie_details(raw_cookie_headers: list[str]) -> list[dict[str, Any]]:
    """Parse Set-Cookie attributes without retaining cookie values."""
    result: list[dict[str, Any]] = []
    for raw in raw_cookie_headers:
        parts = [part.strip() for part in raw.split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs: dict[str, str | bool] = {}
        for part in parts[1:]:
            key, sep, value = part.partition("=")
            attrs[key.strip().lower()] = value.strip() if sep else True
        result.append({"name": name[:100], "attributes": attrs})
    return result


def analyze_response(
    *,
    requested_url: str,
    final_url: str,
    headers: dict[str, Any] | None,
    html: str = "",
    set_cookie_headers: list[str] | None = None,
    tls_info: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Create findings from observed response headers and visible HTML only.

    This function does not send payloads, mutate data, authenticate, or attempt
    exploitation. Missing recommendations are not proof of exploitability.
    """
    headers = headers or {}
    set_cookie_headers = set_cookie_headers or []
    tls_info = tls_info or {}
    findings: list[dict[str, Any]] = []
    final_scheme = urlsplit(final_url).scheme.lower()

    if final_scheme == "http":
        findings.append(_finding(
            "VX-HTTP-001", "Page is served without HTTPS", "High", "Transport security", "High",
            f"The final page URL uses the {final_scheme.upper()} scheme.",
            "Information sent to or received from this page may be observable or modified in transit, depending on the network and application.",
            "Configure a valid TLS certificate, serve the site over HTTPS, and redirect HTTP requests to HTTPS. Review HSTS after HTTPS is working reliably.",
            "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
        ))

    if final_scheme == "https":
        hsts = _header(headers, "Strict-Transport-Security")
        if not hsts:
            findings.append(_finding(
                "VX-HDR-001", "HSTS header not observed", "Medium", "Security headers", "High",
                "Strict-Transport-Security is absent from the inspected HTTPS response.",
                "Browsers are not instructed by this response to remember that the host should only be reached over HTTPS.",
                "After confirming HTTPS works across the relevant hosts, configure an appropriate Strict-Transport-Security policy. Add includeSubDomains or preload only after careful domain-wide review.",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ))
        else:
            max_age_match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.IGNORECASE)
            max_age_text = max_age_match.group(1) if max_age_match else ""
            # Bound conversion size so an unusually long header cannot trigger an integer
            # conversion exception on newer Python releases.
            effective_max_age = int(max_age_text) if max_age_text and len(max_age_text) <= 12 else 0
            if effective_max_age <= 0:
                findings.append(_finding(
                    "VX-HDR-007", "HSTS policy has no effective positive max-age", "Medium", "Security headers", "High",
                    f"Strict-Transport-Security was present, but a positive max-age directive was not observed. Header value: {hsts[:300]}.",
                    "A missing, malformed, or zero max-age does not provide the intended persistent HTTPS-only instruction in browsers.",
                    "Set a deliberate positive max-age after confirming HTTPS works. Add includeSubDomains or preload only after a domain-wide review.",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                ))

    csp = _header(headers, "Content-Security-Policy")
    if not csp:
        findings.append(_finding(
            "VX-HDR-002", "Content Security Policy not observed", "Medium", "Security headers", "High",
            "Content-Security-Policy is absent from the inspected response.",
            "A browser-level defence that can limit script and resource loading is not configured by this response. Its absence alone does not prove XSS.",
            "Create and test a Content Security Policy based on the resources the application needs. Start with report-only mode if appropriate, then enforce a carefully reviewed policy.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
        ))
    else:
        directives = _csp_directives(csp)
        script_sources = directives.get("script-src", directives.get("default-src", []))
        csp_concerns: list[str] = []
        nonce_or_hash = any(
            token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
            for token in script_sources
        )
        strict_dynamic = "'strict-dynamic'" in script_sources
        if not script_sources:
            csp_concerns.append("neither script-src nor default-src restricts script sources")
        if "*" in script_sources and not strict_dynamic:
            csp_concerns.append("script source list contains a wildcard (*)")
        if "'unsafe-eval'" in script_sources:
            csp_concerns.append("script source list permits 'unsafe-eval'")
        if "'unsafe-inline'" in script_sources and not nonce_or_hash and not strict_dynamic:
            csp_concerns.append("script source list permits 'unsafe-inline' without a nonce/hash source")
        if csp_concerns:
            findings.append(_finding(
                "VX-HDR-008", "Content Security Policy may be overly permissive", "Medium", "Security headers", "Medium",
                "Observed policy concerns: " + "; ".join(csp_concerns) + ".",
                "A present CSP may provide limited protection if script sources are unrestricted or unsafe script execution options are allowed. This is a policy heuristic, not proof of XSS.",
                "Review the full policy against actual application resources. Prefer explicit trusted sources, nonces or hashes where appropriate, remove unsafe directives when feasible, and test in report-only mode before enforcement.",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                status="Policy hardening recommendation",
            ))
    xfo = _header(headers, "X-Frame-Options")
    csp_directives = _csp_directives(csp)
    has_frame_ancestors = "frame-ancestors" in csp_directives
    effective_xfo = xfo.strip().lower() in {"deny", "sameorigin"}
    if not effective_xfo and not has_frame_ancestors:
        framing_evidence = "Neither a recognised X-Frame-Options value (DENY or SAMEORIGIN) nor a CSP frame-ancestors directive was observed."
        if xfo:
            framing_evidence += f" Observed X-Frame-Options value: {xfo[:160]}."
        findings.append(_finding(
            "VX-HDR-003", "Framing protection not observed", "Medium", "Security headers", "High",
            framing_evidence,
            "Sensitive pages may be more exposed to clickjacking if the application can be framed by an untrusted site.",
            "Set Content-Security-Policy with an appropriate frame-ancestors directive. Use X-Frame-Options where legacy browser support is needed.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        ))

    xcto = _header(headers, "X-Content-Type-Options")
    if xcto.lower() != "nosniff":
        findings.append(_finding(
            "VX-HDR-004", "X-Content-Type-Options nosniff not observed", "Low", "Security headers", "High",
            f"Observed value: {xcto if xcto else '[header absent]'}.",
            "Some browsers may perform content-type sniffing in contexts where it is undesirable.",
            "Configure X-Content-Type-Options: nosniff and ensure every response uses an accurate Content-Type.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        ))

    referrer_policy = _header(headers, "Referrer-Policy")
    if not referrer_policy:
        findings.append(_finding(
            "VX-HDR-005", "Referrer-Policy not observed", "Low", "Privacy and browser policy", "High",
            "Referrer-Policy is absent from the inspected response.",
            "The browser's default referrer behaviour may disclose more referring URL information than the site intends in some contexts.",
            "Choose and set a Referrer-Policy that matches the site's privacy requirements; strict-origin-when-cross-origin is a common baseline.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        ))

    permissions_policy = _header(headers, "Permissions-Policy")
    if not permissions_policy:
        findings.append(_finding(
            "VX-HDR-006", "Permissions-Policy not observed", "Informational", "Privacy and browser policy", "High",
            "Permissions-Policy is absent from the inspected response.",
            "The site has not used this header to further restrict selected browser features. The header is optional and not required on every site.",
            "Consider an explicit Permissions-Policy for capabilities such as camera, microphone, and geolocation, based on the features the site needs.",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        ))

    server = _header(headers, "Server")
    powered_by = _header(headers, "X-Powered-By")
    disclosed = []
    if server and re.search(r"\d+\.\d+(?:\.\d+)?", server):
        disclosed.append(f"Server: {server[:180]}")
    if powered_by:
        disclosed.append(f"X-Powered-By: {powered_by[:180]}")
    if disclosed:
        findings.append(_finding(
            "VX-INFO-001", "Technology details exposed in response headers", "Informational", "Information disclosure", "High",
            "; ".join(disclosed),
            "Technology/version details can help an attacker profile the stack, but disclosure by itself is not a vulnerability.",
            "Remove unnecessary version details from response headers where practical, and prioritise patching and secure configuration over header concealment.",
            "https://owasp.org/www-project-web-security-testing-guide/",
            status="Hardening recommendation",
        ))

    cookies = _cookie_details(set_cookie_headers)
    if cookies:
        insecure_names: list[str] = []
        session_cookie_missing_httponly: list[str] = []
        missing_samesite: list[str] = []
        for cookie in cookies:
            name = cookie["name"]
            lower_name = name.lower()
            attrs = cookie["attributes"]
            session_like = any(token in lower_name for token in ("session", "sess", "auth", "token", "jwt", "sid"))
            if final_scheme == "https" and "secure" not in attrs:
                insecure_names.append(name)
            if session_like and "httponly" not in attrs:
                session_cookie_missing_httponly.append(name)
            if "samesite" not in attrs:
                missing_samesite.append(name)
        if insecure_names:
            sample = ", ".join(sorted(set(insecure_names))[:8])
            findings.append(_finding(
                "VX-COOKIE-001", "Cookies missing Secure attribute", "Medium", "Cookie security", "High",
                f"Cookie names without Secure on an HTTPS response: {sample}. Cookie values were not retained.",
                "Those cookies may be sent over an unencrypted HTTP request if the site also permits HTTP access or another insecure path.",
                "Set Secure on cookies intended only for HTTPS and review all cookie issuance points, including application and reverse-proxy configuration.",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
            ))
        if session_cookie_missing_httponly:
            sample = ", ".join(sorted(set(session_cookie_missing_httponly))[:8])
            findings.append(_finding(
                "VX-COOKIE-002", "Session-like cookies missing HttpOnly", "Medium", "Cookie security", "Medium",
                f"Session/auth-like cookie names without HttpOnly: {sample}. Cookie values were not retained.",
                "If these cookies contain session credentials, JavaScript access can increase the impact of a client-side script injection flaw.",
                "Set HttpOnly on session credentials unless client-side JavaScript genuinely needs access; verify the application's design before changing it.",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
            ))
        if missing_samesite:
            sample = ", ".join(sorted(set(missing_samesite))[:8])
            findings.append(_finding(
                "VX-COOKIE-003", "Cookies missing SameSite attribute", "Low", "Cookie security", "Medium",
                f"Cookie names without SameSite: {sample}. Cookie values were not retained.",
                "Cross-site cookie behaviour may be broader than intended, which can affect CSRF exposure depending on the application and browser context.",
                "Set an intentional SameSite value (Lax, Strict, or None with Secure) based on whether cross-site cookie use is required.",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
            ))

    if html:
        soup = BeautifulSoup(html, "html.parser")
        mixed_active: list[str] = []
        mixed_passive: list[str] = []
        if final_scheme == "https":
            for tag in soup.find_all(["script", "iframe", "link", "img", "audio", "video", "source", "object"]):
                attr = "data" if tag.name == "object" else ("href" if tag.name == "link" else "src")
                value = str(tag.get(attr, "")).strip()
                if value.lower().startswith("http://"):
                    safe_value = _sanitise_resource_url(value)
                    summary = f"<{tag.name} {attr}=\"{safe_value[:160]}\">"
                    if tag.name in {"script", "iframe", "object"} or (tag.name == "link" and "stylesheet" in [str(x).lower() for x in tag.get("rel", [])]):
                        mixed_active.append(summary)
                    else:
                        mixed_passive.append(summary)
            if mixed_active:
                findings.append(_finding(
                    "VX-HTML-001", "Potential active mixed content", "High", "Insecure resource loading", "High",
                    "Insecure HTTP resource references: " + "; ".join(mixed_active[:6]),
                    "An active resource loaded over HTTP can undermine the security guarantees of an HTTPS page, depending on browser handling and whether the resource loads.",
                    "Change active resources to HTTPS, verify their integrity and ownership, and remove obsolete dependencies.",
                    "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                ))
            if mixed_passive:
                findings.append(_finding(
                    "VX-HTML-002", "Potential passive mixed content", "Medium", "Insecure resource loading", "High",
                    "Insecure HTTP resource references: " + "; ".join(mixed_passive[:6]),
                    "Images or other passive resources requested over HTTP may be exposed to modification or inconsistent browser handling.",
                    "Serve these resources via HTTPS and verify that the referenced hosts are trusted.",
                    "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                ))

        insecure_password_forms: list[str] = []
        get_password_forms: list[str] = []
        for idx, form in enumerate(soup.find_all("form"), 1):
            inputs = form.find_all("input")
            has_password = any(str(item.get("type", "text")).lower() == "password" for item in inputs)
            if not has_password:
                continue
            method = str(form.get("method", "get")).lower()
            action = str(form.get("action", "")).strip()
            resolved_action = urljoin(final_url, action) if action else final_url
            action_scheme = urlsplit(resolved_action).scheme.lower()
            if action_scheme == "http":
                insecure_password_forms.append(f"password form #{idx} submits to an HTTP URL")
            if method == "get":
                get_password_forms.append(f"password form #{idx} uses GET (or omits method, defaulting to GET)")
        if insecure_password_forms:
            findings.append(_finding(
                "VX-FORM-001", "Password form submits over HTTP", "High", "Form security", "High",
                "; ".join(insecure_password_forms[:8]),
                "Credentials submitted over HTTP may be exposed or altered in transit.",
                "Change the form destination to HTTPS and enforce secure transport on the receiving endpoint. Verify redirects do not send credentials to an insecure destination.",
                "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
            ))
        if get_password_forms:
            findings.append(_finding(
                "VX-FORM-002", "Password form appears to use GET", "High", "Form security", "High",
                "; ".join(get_password_forms[:8]),
                "GET parameters can appear in browser history, server logs, analytics, and referrer URLs. This can expose submitted credentials.",
                "Use POST for credential submission, protect the endpoint with HTTPS, and ensure credentials are not written to URLs or logs.",
                "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/form",
            ))

        missing_sri: list[str] = []
        target_host = urlsplit(final_url).hostname or ""
        for script in soup.find_all("script", src=True):
            src = str(script.get("src", "")).strip()
            absolute = urljoin(final_url, src)
            parsed_src = urlsplit(absolute)
            if parsed_src.scheme in {"http", "https"} and parsed_src.hostname and parsed_src.hostname.lower() != target_host.lower() and not script.get("integrity"):
                missing_sri.append(absolute.split("?", 1)[0][:180])
        if missing_sri:
            findings.append(_finding(
                "VX-HTML-003", "Cross-origin scripts without Subresource Integrity", "Low", "Third-party resources", "Medium",
                "Examples: " + "; ".join(missing_sri[:6]),
                "If a third-party script provider or delivery path is compromised, the page may load altered code. SRI is not suitable or necessary for every dynamic resource.",
                "Where compatible with the resource lifecycle, pin static third-party scripts with Subresource Integrity and crossorigin attributes, or self-host/reduce third-party code.",
                "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                status="Hardening recommendation",
            ))

        visible_text = unescape(soup.get_text(" ", strip=True))[:250_000]
        debug_patterns = [
            r"Traceback \(most recent call last\):",
            r"SQLSTATE\[[A-Z0-9]+\]",
            r"Fatal error:\s*Uncaught",
            r"Unhandled Exception",
            r"Exception in thread \"main\"",
        ]
        matched = [pattern for pattern in debug_patterns if re.search(pattern, visible_text, re.IGNORECASE)]
        if matched:
            findings.append(_finding(
                "VX-INFO-002", "Possible debug or stack-trace output", "Medium", "Information disclosure", "Medium",
                "The visible page text matches a common error/debug pattern: " + ", ".join(matched),
                "Debug output can expose file paths, internal implementation details, or database errors. The exact sensitivity depends on the full response and deployment context.",
                "Disable verbose error pages in production, return generic client-facing errors, and retain diagnostic details in access-controlled server logs.",
                "https://owasp.org/www-project-web-security-testing-guide/",
            ))

    if tls_info.get("verification_error"):
        findings.append(_finding(
            "VX-TLS-001", "TLS certificate validation failed", "High", "Transport security", "High",
            str(tls_info.get("verification_error"))[:500],
            "Browsers or clients that validate TLS may reject the connection or warn users, leaving them uncertain whether the site is authentic.",
            "Use a currently valid certificate whose names match the host, serve the full certificate chain, and renew/reconfigure it with a trusted certificate authority.",
            "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
            status="Observed TLS validation error",
        ))
    else:
        not_after = tls_info.get("not_after")
        if not_after:
            try:
                expiry = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                days_remaining = (expiry - datetime.now(timezone.utc)).total_seconds() / 86400
                if days_remaining < 0:
                    findings.append(_finding(
                        "VX-TLS-002", "TLS certificate appears expired", "High", "Transport security", "High",
                        f"Certificate notAfter: {not_after}.",
                        "Clients that validate TLS should reject an expired certificate, and visitors may see security warnings.",
                        "Renew the TLS certificate and verify the deployed certificate chain after replacement.",
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
                        status="Observed certificate expiry",
                    ))
                elif days_remaining <= 14:
                    findings.append(_finding(
                        "VX-TLS-003", "TLS certificate expires soon", "Medium", "Transport security", "High",
                        f"Certificate expires in approximately {max(0, int(days_remaining))} day(s): {not_after}.",
                        "An overlooked renewal could cause availability and trust warnings when the certificate expires.",
                        "Renew the certificate before expiry and confirm that automatic renewal and monitoring are working.",
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
                    ))
            except (ValueError, TypeError):
                pass

    # One finding per rule. Stable sorting makes reports easy to compare.
    unique: dict[str, dict[str, Any]] = {}
    for item in findings:
        unique[item["id"]] = item
    return sorted(unique.values(), key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["title"].lower()))
