# Contributing to suika-hub

Thanks for your interest in contributing.

## Getting started

```bash
git clone https://github.com/lucasjustinudin/suika-hub.git
cd suika-hub

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Editable install with the development tools
pip install -e ".[dev]"
```

There is no pre-commit hook configured; run the checks below manually or wire
them into your editor.

## Development workflow

1. Branch from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```

2. Make your change, with tests.

3. Run the full gate set — all five must pass:
   ```bash
   pytest
   ruff check suika_hub/ tests/
   ruff format --check suika_hub/ tests/
   mypy suika_hub/ --ignore-missing-imports
   python scripts/verify_imports.py
   ```

4. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `perf:`, `ci:`, `chore:`

5. Push and open a pull request.

## Project structure

```
suika-hub/
├── suika_hub/
│   ├── _version.py         # single source of truth for the version
│   ├── cli.py              # Typer CLI: scan, modules, recommend, server, import-har
│   ├── server.py           # aiohttp capture server for the browser extension
│   ├── core/
│   │   ├── config.py       # ScanConfig / AuthConfig
│   │   ├── engine.py       # SuikaEngine: registry + orchestration
│   │   ├── http.py         # AsyncClient: retries, rate limit, proxy pool, WAF detection
│   │   ├── module.py       # BaseModule + Finding
│   │   ├── plugins.py      # plugin discovery (entry points + local paths)
│   │   ├── ratelimit.py    # token-bucket limiter + proxy pool
│   │   ├── retry.py        # retry policy with backoff, jitter, Retry-After
│   │   ├── decision_engine.py  # profile-based module recommendation
│   │   ├── reporter.py     # JSON + Markdown report output
│   │   ├── har_parser.py   # HAR session import
│   │   ├── browser.py      # optional Playwright session capture
│   │   └── ai_analyzer.py  # optional OpenAI-compatible finding analysis
│   └── modules/            # scanner modules, one file each
├── extension/              # Chrome MV3 companion extension
├── plugins/templates/      # plugin template
├── scripts/verify_imports.py
├── configs/example.json    # example scan config
└── tests/
```

## Writing a scanner module

Modules are async. Subclass `BaseModule`, set a unique `name`, and implement
`execute`:

```python
# suika_hub/modules/my_scanner.py
from suika_hub.core.http import AsyncClient
from suika_hub.core.module import BaseModule, Finding


class MyScanner(BaseModule):
    name = "my_scanner"           # alias becomes "my" (the _scanner suffix is stripped)
    description = "What this checks for"

    async def execute(self, target: str, client: AsyncClient, config: dict) -> list[Finding]:
        self.reset()

        url = f"{target.rstrip('/')}/some/endpoint"
        response = await client.get(url)

        # client.get() returns a dict and does NOT raise on HTTP error statuses.
        # Network failures come back as status 0 with an "error" string.
        if response.get("error") is None and response.get("status") == 200:
            self.add_finding(
                severity="HIGH",             # CRITICAL | HIGH | MEDIUM | LOW | INFO
                title="Short, specific title",
                url=url,
                description="What is wrong and why it matters.",
                evidence="The actual bytes that prove it.",
                impact="What an attacker gains.",
                remediation="How to fix it.",
            )

        return self.findings
```

Then register it in `suika_hub/modules/__init__.py` and add it to `build_engine()`
in `cli.py`, plus `MODULE_EFFECTIVENESS` / `MODULE_TIME_ESTIMATE` in
`core/decision_engine.py` — a module missing from those tables can never be
recommended, and `tests/test_plugin.py` asserts the two sets match.

### Finding quality bar

Every finding needs `evidence`. A finding that says "possible issue" without the
bytes that prove it is noise and will be treated as a bug in the module.

If a check is "did this behave differently from normal", send a control request
first and compare against it. Do not report on string-matching a response body
alone — that is how false positives get shipped.

## Writing plugins

Plugins are scanners that live outside the package. Two discovery paths:

**Ad-hoc** — pass a file or directory:

```bash
suika-hub scan -t https://target -m my_plugin --plugin ./my_plugin.py
suika-hub scan -t https://target -m my_plugin --plugin ./my_plugin_dir/
```

**Installed** — declare an entry point in the `suika.plugins` group:

```toml
[project.entry-points."suika.plugins"]
my_plugin = "my_package.scanner:MyScanner"
```

Start from `plugins/templates/`. A plugin must subclass `BaseModule` and expose
`get_module()` returning the class. Malformed plugins are reported and skipped
rather than aborting discovery — one broken third-party plugin must not make the
tool unusable.

## Writing tests

Tests live in `tests/`, with module tests under `tests/test_modules/`.

```python
import pytest

from suika_hub.modules.my_scanner import MyScanner


async def test_detects_the_issue(mock_client_factory):
    # Map a URL substring to the response the scanner should see.
    client = mock_client_factory(
        responses={"/some/endpoint": {"url": "x", "status": 200, "body": {"leak": 1}, "headers": {}, "error": None}}
    )
    scanner = MyScanner()
    findings = await scanner.execute("https://example.com", client, {})
    assert any(f["severity"] == "HIGH" for f in findings)
```

`asyncio_mode = "auto"` is set, so `async def test_*` needs no marker. Shared
fixtures live in `tests/conftest.py` (`mock_client`, `mock_client_factory`,
`make_response`, `sample_finding`).

Two things worth doing that the existing suite does:

- **Assert on the outgoing request, not just the response.** A mock that ignores
  request headers cannot catch a malformed request; the JWT module once sent
  every probe without its `Bearer` prefix and the tests still passed.
- **Prove a regression test fails.** Re-introduce the bug and confirm the test
  goes red before you call it a regression test.

## Code style

- Python 3.10+ (`requires-python = ">=3.10"`), type hints on public functions.
- Ruff for lint and format, line length 120.
- mypy is configured but **not** in strict mode (`disallow_untyped_defs = false`).
- Docstrings explain *why* a check exists, not what the next line does.

## Reporting issues

Open a GitHub issue with reproduction steps, the command you ran, and the output
you got. `suika-hub --help` output helps when the issue is CLI-related.

## Security

Found a vulnerability in suika-hub itself? Open a private security advisory on
GitHub rather than a public issue.

## Scope

This is a tool for **authorized** security testing. Do not contribute checks
that are destructive, that exfiltrate data, or that are hardcoded to a specific
target — target-specific logic belongs in a private plugin, not here.

## License

By contributing you agree your contributions are licensed under the MIT License.
