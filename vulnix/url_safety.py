"""URL parsing and SSRF guardrails for non-invasive public-site scanning.

This MVP intentionally supports only HTTP(S) on standard ports and public IPs.
Production deployments should also enforce outbound network restrictions at the
infrastructure level because DNS can change between validation and connection.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class URLSafetyError(ValueError):
    """Raised when a URL is outside the scanner's permitted scope."""


def normalize_url(raw_url: str) -> str:
    """Normalize URL syntax without resolving the hostname.

    A scheme-less hostname is interpreted as HTTPS for user convenience.
    Only HTTP and HTTPS on their conventional ports are accepted.
    """
    if not isinstance(raw_url, str):
        raise URLSafetyError("Enter a valid website URL.")
    value = raw_url.strip()
    if not value:
        raise URLSafetyError("Enter a website URL first.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise URLSafetyError("The URL contains invalid control characters.")
    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise URLSafetyError("The URL or port number is malformed.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise URLSafetyError("Only HTTP and HTTPS websites are supported.")
    if not parsed.hostname:
        raise URLSafetyError("The URL must include a hostname, such as https://example.com.")
    if parsed.username is not None or parsed.password is not None:
        raise URLSafetyError("URLs containing embedded usernames or passwords are not accepted.")

    expected_port = 443 if scheme == "https" else 80
    if port is not None and port != expected_port:
        raise URLSafetyError("For safety, only standard HTTP (80) and HTTPS (443) ports are supported.")

    hostname = parsed.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise URLSafetyError("The hostname is not valid.") from exc
    if not hostname or hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        raise URLSafetyError("Localhost and local-network hostnames are blocked.")

    # Rebuild netloc with IPv6 brackets when needed. Preserve non-default path/query,
    # but intentionally drop fragments because they are never sent to a server.
    try:
        ipaddress.ip_address(hostname)
        host_for_url = f"[{hostname}]" if ":" in hostname else hostname
    except ValueError:
        host_for_url = hostname
    netloc = host_for_url if port is None else f"{host_for_url}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def resolve_public_host(hostname: str, port: int) -> list[str]:
    """Resolve hostname and reject any non-public IP address."""
    try:
        literal_ip = ipaddress.ip_address(hostname)
        addresses = [str(literal_ip)]
    except ValueError:
        try:
            records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise URLSafetyError("The hostname could not be resolved. Check the URL and try again.") from exc
        addresses = sorted({record[4][0].split("%", 1)[0] for record in records})

    if not addresses:
        raise URLSafetyError("The hostname did not resolve to an IP address.")

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise URLSafetyError("The hostname returned an unsupported address.") from exc
        if not ip.is_global:
            raise URLSafetyError(
                "The destination resolves to a private, local, reserved, or otherwise non-public IP address. "
                "Vulnix AI only scans public destinations."
            )
    return addresses


def validate_public_url(raw_url: str) -> str:
    """Normalize a URL and verify that its destination is public."""
    normalized = normalize_url(raw_url)
    parsed = urlsplit(normalized)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolve_public_host(parsed.hostname or "", port)
    return normalized


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def same_site_host(host_a: str, host_b: str) -> bool:
    """Permit redirects only between a hostname and its www counterpart.

    This is a conservative redirect policy, not a public-suffix-domain parser.
    Cross-host redirects are reported and are not followed automatically.
    """
    a = host_a.lower().rstrip(".")
    b = host_b.lower().rstrip(".")
    return a == b or a.removeprefix("www.") == b.removeprefix("www.")


def safe_display_url(url: str) -> str:
    """Remove query strings/fragments from report URLs to reduce data leakage."""
    try:
        parsed = urlsplit(url)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    except Exception:
        return "[URL hidden]"
