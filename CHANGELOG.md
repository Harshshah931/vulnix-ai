# Changelog

## 1.1.0 — scanner quality and report safety

- Added a conservative check for HSTS headers with absent, malformed, or non-positive `max-age` values.
- Added a CSP hardening heuristic for unrestricted script sources, `unsafe-eval`, and `unsafe-inline` without a nonce/hash source.
- Framing protection now recognises only the effective `X-Frame-Options` values `DENY` and `SAMEORIGIN`, or an enforced CSP `frame-ancestors` directive.
- Redacted query strings and fragments from mixed-content resource evidence.
- Reduced spreadsheet formula-injection risk in CSV exports.
- Changed the Windows launcher to bind to `127.0.0.1` by default.
- Added automated tests covering the new behaviour.
