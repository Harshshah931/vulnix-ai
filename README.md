# Vulnix AI — AI-Powered Website Security Analysis System

**Version:** 1.1.0 MVP  
**Stack:** Python, Streamlit 1.48+, standard-library HTTP/TLS sockets, Beautiful Soup, optional OpenAI API  
**Purpose:** Demonstrate an evidence-first, non-invasive website security analysis workflow for authorised public websites.

## What's included

- Modern, responsive Streamlit dashboard with Vulnix AI branding.
- Permission confirmation before live scans.
- URL parsing and public-destination checks; rejects private/local/reserved destinations and non-standard ports.
- Conservative redirect policy: only same-host and `www` counterpart redirects are followed automatically.
- Low-impact HTTP `GET` requests only; no exploit payloads, login attempts, form submission, directory brute forcing, or mutation.
- Bounded HTML response reading, request timeouts, no ambient proxy configuration, and no cookie values stored in findings.
- Rule engine for TLS validity/expiry, HTTP without HTTPS, HSTS, CSP presence and common permissive script directives, framing protections, content-type options, Referrer-Policy, Permissions-Policy, cookie attributes, mixed content, insecure password forms, third-party scripts without SRI, server/version disclosures, and common visible debug output.
- Findings include a stable ID, severity, confidence, observed evidence, impact, remediation and reference.
- Optional OpenAI Responses API explanation layer. If no key is configured, the app explicitly labels its local deterministic summary rather than pretending a remote model was used.
- Synthetic sample report that does **not** contact a website.
- JSON, CSV, and standalone HTML report downloads.
- Unit tests for URL safety helpers and detection rules.

## Requirements

- Python 3.10 or newer (Python 3.12 recommended).
- Internet access from the machine running the scanner for authorised public-host checks.
- Optional OpenAI API key only if you want model-generated executive summaries. The core scanner works without it.

## Run on Windows 11 (easiest option)

1. Extract the ZIP.
2. Double-click `setup_vulnix.bat` once. It creates a virtual environment and installs dependencies.
3. Double-click `run_vulnix.bat` whenever you want to launch the app. To run the tests, double-click `test_vulnix.bat`.

## Run on Windows 11 (PowerShell)

1. Extract the ZIP and open PowerShell inside the `vulnix_ai` folder.
2. Create a virtual environment:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. Start the application:

   ```powershell
   streamlit run app.py
   ```

4. Open the local address Streamlit prints (typically `http://127.0.0.1:8501`). The Windows launcher binds to loopback by default, reducing the chance that the development UI is exposed to other devices on the network.
5. First click **Load sample report** to explore the interface without contacting a live site. For a real scan, enter a website you own or are explicitly authorised to test, tick the consent checkbox, and click **Run security scan**.

If PowerShell blocks virtual-environment activation, use Command Prompt or launch `.venv\Scripts\python.exe -m streamlit run app.py` directly.

## Enable optional model-generated summaries

**Option A — session-only key:** enter your API key in the sidebar's password input. It is not added to the downloaded report or written to source files.

**Option B — environment variable (recommended):** in PowerShell, set the key before starting Streamlit:

```powershell
$env:OPENAI_API_KEY = "YOUR_API_KEY"
$env:OPENAI_MODEL = "gpt-4.1-mini"
streamlit run app.py
```

Use a model name available to your API account. API use may incur charges. Never commit a real API key to GitHub. Without a key, a local rules-based summary is provided and clearly labelled.

## Run tests

From the project root:

```powershell
python -m unittest discover -s tests -v
```

The tests do not contact external websites.

## Deploy

### Streamlit Community Cloud

1. Push the project folder to a new GitHub repository (do not upload `.env` or API keys).
2. Create a Streamlit app pointing to `app.py`.
3. Set `OPENAI_API_KEY` and optionally `OPENAI_MODEL` in the platform's Secrets settings if model-generated summaries are needed.
4. Keep access limited while the product is experimental. Do not expose an unrestricted public URL scanner.

### Docker

```bash
docker build -t vulnix-ai .
docker run --rm -p 8501:8501 vulnix-ai
```

Open `http://127.0.0.1:8501` in your browser.

## Checks implemented (and interpretation)

| Check | What the scanner observes | Important limitation |
|---|---|---|
| HTTP vs HTTPS | Whether the final observed page uses HTTP or HTTPS | Does not inspect every route or subdomain |
| TLS certificate | Trusted TLS handshake and certificate metadata/expiry | Network errors can prevent full certificate inspection |
| HSTS | `Strict-Transport-Security` on an HTTPS response | A missing header is a hardening gap, not proof of compromise |
| CSP | Presence of `Content-Security-Policy`; basic heuristic for absent or permissive script source directives | Presence alone does not mean the policy is strong; heuristic warnings need manual review |
| Clickjacking protection | CSP `frame-ancestors` or recognised `X-Frame-Options` values (`DENY`, `SAMEORIGIN`) | Some pages intentionally allow framing; unsupported or invalid values do not count as effective protection |
| `nosniff` | `X-Content-Type-Options` value | Context matters |
| Referrer/Permissions policies | Header presence | These are recommendations, not always mandatory |
| Cookie attributes | `Secure`, `HttpOnly`, `SameSite` on cookies from the inspected response | Logged-in and post-interaction cookies are not covered; values are never included |
| Mixed content | `http://` references in visible HTML | Does not execute scripts or verify whether the resource loads |
| Password forms | Visible password forms with HTTP destinations or GET method | Only the returned HTML is inspected; no form is submitted |
| Third-party SRI | Cross-origin script tags lacking integrity metadata | SRI is not appropriate for every dynamic script |
| Server/version details | Public response headers | Concealment alone is not a fix for unpatched software |
| Debug output | A small set of visible error/stack-trace patterns | Heuristic and may produce false positives/negatives |

## Safety and privacy notes

- Use only for websites you own or have explicit written authorisation to test.
- Publicly reachable does not mean authorised to test.
- The scanner limits checks to one public page, HTTP `GET`, standard ports, and a small redirect count. It does not perform exploitation or authenticated testing.
- Private, local, reserved and non-public IP targets are rejected. Every followed redirect is revalidated; cross-host redirects are not followed automatically.
- The scanner uses direct pinned sockets rather than inherited proxy settings, verifies TLS certificates, applies timeouts and bounds HTML to 1.5 MB.
- Cookie values are not stored in finding evidence. Query strings/fragments are removed from displayed URLs.
- Connections are pinned to a validated public IP, reducing DNS-rebinding SSRF risk. This application-level control is not a substitute for production network isolation. Before offering a public hosted scanner, enforce egress firewall rules or a controlled outbound proxy, request quotas, authentication, abuse monitoring and server-side network policy. Consider domain-ownership verification and explicit scope registration.
- Do not send raw HTML or cookie values to the AI provider. Only sanitised finding fields are sent for the optional summary.
- CSV exports prefix spreadsheet-formula-like values with an apostrophe to reduce formula-injection risk when findings are opened in spreadsheet applications. Resource evidence omits query strings and fragments to reduce accidental disclosure of tokens.
- Scanner results are indicative, not a guarantee of security or a replacement for a professional penetration test.

## Architecture

```text
Streamlit UI
    ↓
URL syntax / public IP validation + explicit authorisation
    ↓
Bounded GET over a socket pinned to a validated public IP
    ↓
Same-host redirect handling
    ↓
HTTP headers + TLS metadata + visible HTML
    ↓
Rule-based findings (severity, confidence, evidence, impact, remediation)
    ↓
Optional model-generated summary (local summary otherwise)
    ↓
Interactive results + JSON / CSV / HTML exports
```

## Suggested college demo (3–5 minutes)

1. Click **Load sample report** and explain that the report is synthetic.
2. Open one finding and point to the evidence, impact and recommended fix.
3. Explain that the detection engine applies deterministic rules and the optional AI layer explains findings; it does not invent findings from a URL alone.
4. Show the technical details and report exports.
5. Explain the limitations: no authentication testing, no injection testing, no full penetration test, and no security guarantee.

## Viva-ready explanation

“Vulnix AI is a Python-based website security analysis prototype. It safely inspects the publicly visible HTTP response, TLS certificate metadata, security headers, cookie attributes and visible HTML. A rule engine identifies potential weaknesses with evidence and predefined severity. An optional AI model converts structured findings into plain-language explanations and remediation steps. The application supports downloadable JSON, CSV and HTML reports. It is intentionally non-invasive and requires authorisation; deeper testing such as authenticated access-control checks or injection tests is outside this MVP.”

## Project layout

```text
vulnix_ai/
├── app.py
├── setup_vulnix.bat
├── run_vulnix.bat
├── test_vulnix.bat
├── vulnix/
│   ├── ai_assistant.py
│   ├── demo.py
│   ├── reporting.py
│   ├── rules.py
│   ├── scanner.py
│   └── url_safety.py
├── tests/test_rules.py
├── assets/vulnix_mark.svg
├── assets/vulnix_mark.png
├── .streamlit/config.toml
├── requirements.txt
├── .env.example
├── .gitignore
├── Dockerfile
├── LICENSE
└── README.md
```
