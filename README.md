# GREVORA Recon

**Scope-limited, non-invasive HTTP security posture checks for authorized assets.**

GREVORA Recon is an early-stage open-source project from **GREVORA-Labs**. It checks explicitly supplied hostnames within a declared domain scope and creates JSON and HTML reports.

> **Authorization required:** Use only on systems you own or have explicit permission to assess. The scope file is a safety control, not proof of authorization. This tool does not exploit vulnerabilities, enumerate unknown subdomains, brute-force paths, or follow redirects.

## Features

- Explicit authorized-domain allowlist (`scope.json`)
- Correct root/subdomain boundary matching
- HTTP/HTTPS only; rejects IP literals, localhost, URL credentials, and out-of-scope hosts
- DNS guard blocks loopback, private, link-local, reserved, and other non-global IP answers
- One `HEAD` request per target, with minimal range `GET` fallback if `HEAD` is unsupported
- Redirects are not followed
- Checks HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`
- Notes `Server` and `X-Powered-By` disclosure headers
- JSON and self-contained HTML reports; report output escapes untrusted text
- Python standard library only; no API keys or telemetry

## Requirements

Python 3.10+, network access, and permission to assess every target.

## Quick start

Clone or download this repository, then enter its directory:

```bash
git clone https://github.com/GREVORA-Labs/grevora-recon.git
cd grevora-recon
```

Copy the examples and edit them:

```bash
cp examples/scope.example.json scope.json
cp examples/targets.example.txt targets.txt
```

Change `scope.json` to list only domains you are authorized to assess:

```json
{
  "authorized_domains": ["your-authorized-domain.example"]
}
```

Change `targets.txt` to list only hosts inside that scope, one per line:

```text
https://your-authorized-domain.example/
https://www.your-authorized-domain.example/
```

Do not run the example domain unless it is genuinely in your authorized scope.

Run from source:

```bash
python -m grevora_recon.cli --scope scope.json --targets targets.txt --output reports
```

Reports are written to `reports/report.json` and `reports/report.html`.

Optional limits:

```bash
python -m grevora_recon.cli --scope scope.json --targets targets.txt --timeout 5 --delay 2 --output reports
```

Timeout is 1–20 seconds; delay is 0–30 seconds. Defaults are 8 seconds and one second between targets. A maximum of 100 input targets is accepted.

### Optional virtual environment install

```bash
python -m venv .venv
```

Activate on Windows PowerShell with `.venv\Scripts\Activate.ps1`, or on macOS/Linux with `source .venv/bin/activate`. Then:

```bash
python -m pip install .
grevora-recon --scope scope.json --targets targets.txt --output reports
```

## Interpreting findings

A missing header is a review suggestion, **not proof of a vulnerability**. Requirements depend on the application and threat model. Validate findings manually.

This tool does not exploit or verify vulnerabilities, crawl pages, discover hidden paths or subdomains, follow redirects, scan ports, authenticate, submit forms, change server state, or guarantee protection against DNS rebinding.

## Tests and validation

```bash
python -m unittest discover -s tests -v
python -m compileall -q grevora_recon tests
```

Unit tests require no internet access.

## Project layout

```text
grevora-recon/
├── grevora_recon/ (__init__.py, checks.py, cli.py, report.py, scope.py)
├── tests/ (test_checks.py, test_reports.py, test_scope.py)
├── examples/ (scope.example.json, targets.example.txt)
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
└── pyproject.toml
```

## Roadmap

- [x] Domain scope validation
- [x] Basic HTTP security-header checks
- [x] JSON and HTML reporting
- [x] Unit tests for scope, DNS guard, and HTML escaping
- [ ] CI workflow
- [ ] Optional CSV report
- [ ] Versioned releases after broader review

Unchecked items are planned, not implemented.

See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under MIT; see [LICENSE](LICENSE).

**GREVORA-Labs** — *INTELLIGENCE. SECURITY. FUTURE.*
