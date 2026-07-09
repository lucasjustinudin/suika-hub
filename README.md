# suika-hub

Async, modular web security scanning toolkit for authorized security research.

`suika-hub` is a Python CLI/library that coordinates focused scanner modules (recon, IDOR, API fuzzing, auth bypass checks, file-upload checks, SSRF checks) and writes JSON/Markdown reports. It is currently **beta**: useful as a base framework and portfolio project, but not a replacement for mature scanners like nuclei, nmap, or Burp Suite.

## Status

- Package: beta (`2.0.0`)
- Python: 3.10+
- Scope: authorized testing only
- Output: JSON and Markdown reports
- AI analysis: optional; disabled unless configured with an API key

## Features

- Async HTTP client with concurrency and delay controls
- Modular scanner registry
- CLI commands for scanning, listing modules, HAR import, and recommendations
- Authentication support through cookies, headers, session JSON, or HAR files
- Report generation in JSON and Markdown
- Optional OpenAI-compatible AI analyzer
- Test suite and GitHub Actions CI

## Install

From source:

```bash
git clone https://github.com/lucasjustinudin/suika-hub.git
cd suika-hub
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Usage

List modules:

```bash
suika-hub modules
```

Run a scan:

```bash
suika-hub scan   --target https://example.com   --module recon,idor,api   --delay 1.5   --concurrency 5   --output reports
```

Use cookies:

```bash
suika-hub scan   -t https://example.com   -m idor,auth   --cookie 'session=abc; csrf=xyz'
```

Import a HAR file:

```bash
suika-hub import-har ./session.har --domain example.com
```

## Modules

| Alias | Module | Purpose |
|---|---|---|
| `recon` | `recon_scanner` | endpoint and technology discovery |
| `idor` | `idor_scanner` | generic IDOR pattern checks |
| `api` | `api_fuzzer` | API payload and boundary fuzzing |
| `auth` | `auth_bypass` | auth bypass and privilege checks |
| `upload` | `upload_scanner` | file upload validation checks |
| `ssrf` | `ssrf_scanner` | SSRF payload checks |
| `redstorm` | `redstorm_scanner` | RedStorm-specific helper checks |

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
ruff check suika_hub tests
ruff format suika_hub tests
mypy suika_hub --ignore-missing-imports
pytest -v
```

## Safety

Only run this tool against systems where you have explicit authorization. The project is designed for responsible security research and defensive testing.

## License

MIT
