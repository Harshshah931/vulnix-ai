"""Low-impact, public website scanner for the Vulnix AI MVP.

Network connections are made to a previously validated public IP address while
preserving the hostname for HTTP Host and TLS SNI/certificate verification. This
helps prevent DNS-rebinding based SSRF in the prototype; production still needs
a network egress policy as a second layer of defence.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

from bs4 import BeautifulSoup

from .rules import analyze_response
from .url_safety import URLSafetyError, host_of, resolve_public_host, safe_display_url, same_site_host, validate_public_url

USER_AGENT = "VulnixAI/1.0 (+non-invasive security configuration analysis; authorised testing only)"
MAX_HTML_BYTES = 1_500_000
CONNECT_TIMEOUT_SECONDS = 4
READ_TIMEOUT_SECONDS = 10
MAX_REDIRECTS = 4
MAX_ADDRESSES_PER_HOST = 4


@dataclass
class ScanResult:
    requested_url: str
    final_url: str
    started_at: str
    finished_at: str
    duration_seconds: float
    status_code: int | None = None
    content_type: str = ""
    page_title: str = ""
    server: str = ""
    tls: dict[str, Any] = field(default_factory=dict)
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False
    scan_mode: str = "non-invasive public-page analysis"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FetchError(RuntimeError):
    """A bounded HTTP request failed before a usable response was received."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _header_dict(pairs: list[tuple[str, str]]) -> tuple[dict[str, str], list[str]]:
    """Normalise response headers while preserving separate Set-Cookie values."""
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for name, value in pairs:
        key = str(name).strip().lower()
        val = str(value).strip()
        if key == "set-cookie":
            cookies.append(val)
        elif key in headers:
            headers[key] = headers[key] + ", " + val
        else:
            headers[key] = val
    return headers, cookies


def _parse_tls_metadata(tls_socket: ssl.SSLSocket, hostname: str) -> dict[str, Any]:
    details: dict[str, Any] = {
        "checked": True,
        "verified": True,
        "hostname": hostname,
        "tls_version": tls_socket.version(),
        "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
    }
    cert = tls_socket.getpeercert() or {}
    details["subject"] = ", ".join("=".join(x) for group in cert.get("subject", []) for x in group)
    details["issuer"] = ", ".join("=".join(x) for group in cert.get("issuer", []) for x in group)
    details["not_before"] = cert.get("notBefore")
    details["not_after"] = cert.get("notAfter")
    if cert.get("notAfter"):
        try:
            details["not_after"] = datetime.fromtimestamp(
                ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc
            ).isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    details["sans"] = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"][:20]
    return details


def _certificate_details(hostname: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    """Inspect TLS without ever resolving to a non-public address for the socket."""
    details: dict[str, Any] = {"checked": False, "hostname": hostname}
    try:
        addresses = resolve_public_host(hostname, port)[:MAX_ADDRESSES_PER_HOST]
    except URLSafetyError as exc:
        details["checked"] = True
        details["verified"] = False
        details["error"] = str(exc)
        return details

    context = ssl.create_default_context()
    last_error: Exception | None = None
    for address in addresses:
        raw_sock: socket.socket | None = None
        tls_sock: ssl.SSLSocket | None = None
        try:
            raw_sock = socket.create_connection((address, port), timeout=timeout)
            raw_sock.settimeout(timeout)
            tls_sock = context.wrap_socket(raw_sock, server_hostname=hostname)
            raw_sock = None  # The wrapped socket now owns the file descriptor.
            details.update(_parse_tls_metadata(tls_sock, hostname))
            return details
        except ssl.SSLCertVerificationError as exc:
            details["checked"] = True
            details["verified"] = False
            details["verification_error"] = f"Certificate verification error: {exc.verify_message or str(exc)}"
            return details
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            last_error = exc
        finally:
            if tls_sock is not None:
                try:
                    tls_sock.close()
                except OSError:
                    pass
            if raw_sock is not None:
                try:
                    raw_sock.close()
                except OSError:
                    pass
    details["checked"] = True
    details["verified"] = False
    details["error"] = f"TLS inspection could not complete: {type(last_error).__name__ if last_error else 'ConnectionError'}"
    return details


def _request_target(url: str) -> tuple[str, str, int, str, str]:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host_header = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port is not None:
        host_header = f"{host_header}:{parsed.port}"
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~%")
    if parsed.query:
        path += "?" + quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~%[]")
    return parsed.scheme.lower(), hostname, port, host_header, path


def _fetch_once(url: str) -> dict[str, Any]:
    """Make one GET request over a socket connected to a validated public IP."""
    normalized = validate_public_url(url)
    scheme, hostname, port, host_header, path = _request_target(normalized)
    addresses = resolve_public_host(hostname, port)[:MAX_ADDRESSES_PER_HOST]
    if not addresses:
        raise FetchError("The hostname did not resolve to a public address.")

    context = ssl.create_default_context() if scheme == "https" else None
    last_error: Exception | None = None
    for address in addresses:
        raw_sock: socket.socket | None = None
        connection_sock: socket.socket | ssl.SSLSocket | None = None
        response: http.client.HTTPResponse | None = None
        try:
            raw_sock = socket.create_connection((address, port), timeout=CONNECT_TIMEOUT_SECONDS)
            raw_sock.settimeout(READ_TIMEOUT_SECONDS)
            if scheme == "https":
                assert context is not None
                connection_sock = context.wrap_socket(raw_sock, server_hostname=hostname)
                raw_sock = None  # Wrapped socket now owns the file descriptor.
            else:
                connection_sock = raw_sock
                raw_sock = None

            request_bytes = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                "Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.2\r\n"
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii", errors="strict")
            connection_sock.sendall(request_bytes)
            response = http.client.HTTPResponse(connection_sock)
            response.begin()
            headers, cookies = _header_dict(response.getheaders())
            body = ""
            truncated = False
            content_type = headers.get("content-type", "")
            body_read_error = ""
            if "text/html" in content_type.lower() or "application/xhtml+xml" in content_type.lower():
                try:
                    raw_body = response.read(MAX_HTML_BYTES + 1)
                except (OSError, http.client.HTTPException) as exc:
                    raw_body = b""
                    body_read_error = type(exc).__name__
                if len(raw_body) > MAX_HTML_BYTES:
                    raw_body = raw_body[:MAX_HTML_BYTES]
                    truncated = True
                charset = "utf-8"
                for part in content_type.split(";")[1:]:
                    key, sep, value = part.strip().partition("=")
                    if sep and key.lower() == "charset":
                        charset = value.strip().strip("\"'")[:40] or "utf-8"
                        break
                try:
                    body = raw_body.decode(charset, errors="replace")
                except LookupError:
                    body = raw_body.decode("utf-8", errors="replace")
            tls_details = _parse_tls_metadata(connection_sock, hostname) if scheme == "https" and isinstance(connection_sock, ssl.SSLSocket) else {}
            return {
                "status_code": int(response.status),
                "reason": str(response.reason or "")[:120],
                "headers": headers,
                "set_cookie_headers": cookies,
                "html": body,
                "truncated": truncated,
                "body_read_error": body_read_error,
                "content_type": content_type[:200],
                "tls": tls_details,
            }
        except ssl.SSLCertVerificationError:
            # Do not retry verification failures against a different backend; report them.
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError, UnicodeEncodeError) as exc:
            last_error = exc
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            if connection_sock is not None:
                try:
                    connection_sock.close()
                except OSError:
                    pass
            if raw_sock is not None:
                try:
                    raw_sock.close()
                except OSError:
                    pass

    raise FetchError(f"Connection failed: {type(last_error).__name__ if last_error else 'ConnectionError'}")


def scan_website(raw_url: str, *, authorization_confirmed: bool = False) -> ScanResult:
    """Scan one public HTTP(S) page using GET only and conservative controls."""
    if not authorization_confirmed:
        raise URLSafetyError("Confirm that you own this website or have explicit permission to test it.")

    normalized = validate_public_url(raw_url)
    start_epoch = time.monotonic()
    started_at = _utc_now()
    result = ScanResult(
        requested_url=safe_display_url(normalized),
        final_url=safe_display_url(normalized),
        started_at=started_at,
        finished_at=started_at,
        duration_seconds=0.0,
    )

    current_url = normalized
    response_data: dict[str, Any] | None = None
    cross_host_redirect = False

    for hop in range(MAX_REDIRECTS + 1):
        try:
            current_url = validate_public_url(current_url)
            response_data = _fetch_once(current_url)
        except ssl.SSLCertVerificationError as exc:
            host = urlsplit(current_url).hostname or ""
            port = urlsplit(current_url).port or 443
            result.final_url = safe_display_url(current_url)
            result.tls = _certificate_details(host, port)
            result.tls.setdefault("checked", True)
            result.tls.setdefault("verified", False)
            result.tls.setdefault("verification_error", f"TLS validation failed: {exc.verify_message or str(exc)}")
            result.findings = [{
                "id": "VX-TLS-001",
                "title": "TLS certificate validation failed",
                "severity": "High",
                "category": "Transport security",
                "confidence": "High",
                "status": "Observed TLS validation error",
                "evidence": str(result.tls.get("verification_error", "TLS certificate validation failed"))[:500],
                "impact": "Clients that validate TLS may reject the connection or warn users, leaving them uncertain whether the site is authentic.",
                "remediation": "Use a currently valid certificate whose names match the host, serve the full certificate chain, and renew/reconfigure it with a trusted certificate authority.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
            }]
            result.errors.append("The HTTPS connection failed certificate/TLS validation. See the TLS finding for details.")
            break
        except (URLSafetyError, FetchError) as exc:
            result.errors.append(str(exc))
            break

        status = int(response_data["status_code"])
        location = response_data["headers"].get("location", "")
        if status in {301, 302, 303, 307, 308} and location:
            next_url = urljoin(current_url, location)
            try:
                parsed_next = validate_public_url(next_url)
            except URLSafetyError as exc:
                result.warnings.append(f"Redirect not followed because its destination was blocked: {exc}")
                break
            from_host = host_of(current_url)
            to_host = host_of(parsed_next)
            result.redirect_chain.append({
                "status_code": status,
                "from": safe_display_url(current_url),
                "to": safe_display_url(parsed_next),
            })
            if not same_site_host(from_host, to_host):
                cross_host_redirect = True
                result.warnings.append(
                    "A redirect points to a different hostname. Vulnix AI did not follow it because cross-host destinations are outside the default scan scope."
                )
                break
            if hop >= MAX_REDIRECTS:
                result.warnings.append("The redirect limit was reached; the scanner stopped following redirects.")
                break
            current_url = parsed_next
            response_data = None
            continue
        break

    if response_data is not None:
        result.status_code = response_data["status_code"]
        result.final_url = safe_display_url(current_url)
        result.content_type = response_data.get("content_type", "")
        result.server = response_data.get("headers", {}).get("server", "")[:200]
        result.truncated = bool(response_data.get("truncated"))
        page_html = response_data.get("html", "")
        if result.truncated:
            result.warnings.append("The HTML response exceeded the configured size limit; analysis used only the first 1.5 MB.")
        if response_data.get("body_read_error"):
            result.warnings.append(f"The HTML body could not be fully read ({response_data['body_read_error']}); checks used the response headers only.")
        if not page_html and "text/html" not in result.content_type.lower() and "application/xhtml+xml" not in result.content_type.lower():
            result.warnings.append("The final response was not recognised as HTML; checks were limited to available headers and TLS metadata.")
        if page_html:
            soup = BeautifulSoup(page_html, "html.parser")
            title_tag = soup.find("title")
            if title_tag:
                result.page_title = " ".join(title_tag.get_text(" ", strip=True).split())[:240]
        result.tls = response_data.get("tls", {}) or result.tls
        result.findings = analyze_response(
            requested_url=normalized,
            final_url=current_url,
            headers=response_data.get("headers", {}),
            html=page_html,
            set_cookie_headers=response_data.get("set_cookie_headers", []),
            tls_info=result.tls,
        )

    if cross_host_redirect:
        result.warnings.append("Findings describe the redirect response on the original host, not the destination website.")
    if not result.findings and not result.errors:
        result.warnings.append("No findings were produced by the available checks. This does not prove the website is secure.")
    result.finished_at = _utc_now()
    result.duration_seconds = round(time.monotonic() - start_epoch, 2)
    return result
