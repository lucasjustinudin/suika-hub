# suika-hub

Async, modular web security scanning toolkit for authorized security research.

`suika-hub` is a Python CLI/library that coordinates focused scanner modules (recon, IDOR, API fuzzing, auth bypass, file upload, SSRF, GraphQL, JWT) and writes JSON/Markdown reports. It is **beta**: useful as a framework and portfolio project, not a replacement for nuclei, nmap, or Burp Suite.

## Status

- Package: beta (`2.1.0`)
- Python: 3.10+ (CI covers 3.10-3.13)
- Scope: authorized testing only
- Output: JSON and Markdown reports
- AI analysis: optional; disabled unless configured with an API key

## Features

- **Async HTTP client** with per-host token-bucket rate limiting, bounded concurrency, and explicit `Retry-After` handling
- **Retry policy** with exponential backoff and full jitter, capped by attempts, delay ceiling, and total budget
- **Proxy rotation** with round-robin/random strategies and automatic cooldown of proxies that keep failing
- **WAF detection** across Cloudflare, Akamai, Imperva, DataDome, AWS WAF, Sucuri, F5, and Azure Front Door
- **Coherent browser fingerprint** -- UA and `sec-ch-ua` client hints are derived together, so the header set is internally consistent
- **Modular scanner registry** with aliases and a plugin template
- **Differential findings** -- checks that mutate a request compare against a control request instead of pattern-matching a string
- Report generation in JSON and Markdown, including HTTP/retry/proxy statistics
- Optional OpenAI-compatible AI analyzer
- 387-test suite plus GitHub Actions CI (lint, format, types, tests, import check, build)

## Install

```bash
git clone https://github.com/lucasjustinudin/suika-hub.git
cd suika-hub
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
```

## Usage

List modules:

```bash
suika-hub modules
```

Run a scan:

```bash
suika-hub scan --target https://example.com --module recon,idor,api --delay 1.5 --concurrency 5 --output reports
```

Authenticated scan with cookies and a rate limit:

```bash
suika-hub scan -t https://example.com -m idor,auth --cookie 'session=abc; csrf=xyz' --rate-limit 3
```

Rotate through proxies:

```bash
suika-hub scan -t https://example.com -m recon --proxies 'http://p1:8080,http://p2:8080,socks5://p3:1080'
```

GraphQL and JWT checks:

```bash
suika-hub scan -t https://example.com -m graphql --graphql-endpoint https://example.com/graphql
suika-hub scan -t https://example.com -m jwt --jwt 'eyJhbGciOi...'
```

Recommend a module set for a target profile (the profile describes a stack
shape, not a specific host):

```bash
suika-hub recommend --target spa      # nodejs, python, php, java, spa
```

Import a HAR file to reuse a browser session:

```bash
suika-hub import-har ./session.har --domain example.com
```

## Modules

| Alias | Module | Purpose |
|---|---|---|
| `recon` | `recon_scanner` | endpoint and technology discovery |
| `idor` | `idor_scanner` | IDOR pattern checks with baseline comparison |
| `api` | `api_fuzzer` | API payload and boundary fuzzing |
| `auth` | `auth_bypass` | auth bypass, privilege escalation, mass assignment |
| `upload` | `upload_scanner` | file upload validation bypass |
| `ssrf` | `ssrf_scanner` | SSRF, cloud metadata, protocol smuggling |
| `graphql` | `graphql_scanner` | introspection, alias batching, complexity limits |
| `jwt` | `jwt_scanner` | `alg:none`, weak HMAC secret, claim tampering |

### How the GraphQL and JWT modules avoid false positives

Both modules send a **control request** first and only report a finding when a mutated request is accepted *and* the control was accepted. A JWT finding additionally requires the response shape to overlap with the control's, so a generic `200` shell page cannot be mistaken for a signature bypass. If the control is rejected, the module says so and reports nothing.

## Configuration

`ScanConfig` loads from JSON or YAML via `ScanConfig.from_file()`. Module-specific values go in `extra` and are merged into the dict modules receive:

```yaml
target: https://example.com
modules: [graphql, jwt]
rate_limit: 3
proxies:
  - http://127.0.0.1:8080
extra:
  jwt: "eyJhbGciOi..."
  graphql_endpoints:
    - https://example.com/graphql
```

## Optional AI analysis

The AI analyzer uses an OpenAI-compatible `/chat/completions` endpoint. It is disabled unless an API key is configured.

```bash
export AI_BASE_URL='https://api.openai.com/v1'
export AI_API_KEY='...'
export AI_MODEL='gpt-4o-mini'
```

Do not send sensitive target data to third-party AI services unless your engagement scope permits it.

## Development

```bash
pip install -e '.[dev]'

ruff check suika_hub/ tests/
ruff format --check suika_hub/ tests/
mypy suika_hub/ --ignore-missing-imports
pytest -v
python scripts/verify_imports.py
```

All five gates run in CI on every push and pull request.

## Design notes

- **Per-host limits, not one global delay.** A single global sleep makes a scan with one slow host as slow as a scan with fifty. `RateLimiter` keys a token bucket per hostname and reserves tokens so concurrent callers wake at staggered times rather than all firing at once.
- **Retries honour `Retry-After`.** A `429` retried on the scanner's own schedule is how an IP gets banned. The retry policy reads the header (both delta-seconds and HTTP-date forms) and caps it at `max_delay`.
- **Only transient failures are retried.** 4xx responses other than `429` are deterministic rejections; retrying them wastes budget and looks like an attack.
- **Recommendations are profile-based, not target-based.** `recommend --target`
  takes a stack shape (`nodejs`, `python`, `php`, `java`, `spa`) and scores the
  shipped modules against it. A module that directly matches detected technology
  (GraphQL scanner on a GraphQL API, JWT scanner on JWT auth) gets a relevance
  floor before its multiplier, because the stack-derived vulnerability priority
  list often shares no key with that module's effectiveness table -- without the
  floor the multiplier applies to zero and the most relevant module ranks last.
- **A WAF block is not a finding.** It is returned as `error="waf_blocked"` with the identified vendor, so modules skip rather than reporting the block page as a vulnerability.

## Safety

Only run this tool against systems where you have explicit authorization. The project is designed for responsible security research and defensive testing.

## License

MIT
