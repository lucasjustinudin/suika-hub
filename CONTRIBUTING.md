# Contributing to suika-hub

Thank you for your interest in contributing to suika-hub! 🍉

## Getting Started

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/suika-hub.git
cd suika-hub

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Development Workflow

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make your changes** and add tests

3. **Run the test suite**:
   ```bash
   pytest tests/ -v --cov=suika_hub
   ```

4. **Run linting**:
   ```bash
   ruff check .
   ruff format .
   mypy suika_hub/
   ```

5. **Commit** with a clear message:
   ```bash
   git commit -m "feat: add GraphQL introspection scanner"
   ```

6. **Push** and open a Pull Request

## Project Structure

```
suika-hub/
├── suika_hub/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py       # Scan orchestration engine
│   │   ├── base.py         # BaseScanner, Finding, Report abstractions
│   │   ├── config.py       # Configuration management
│   │   └── state.py        # SQLite state persistence
│   ├── modules/
│   │   ├── recon/          # Reconnaissance modules
│   │   ├── vuln/           # Vulnerability scanning modules
│   │   ├── ai/             # OpenAI integration
│   │   └── report/         # Report generation
│   ├── plugins/            # Plugin loader and registry
│   ├── chrome_extension/   # Chrome companion extension
│   └── utils/              # Shared utilities
├── tests/
├── docs/
├── pyproject.toml
└── README.md
```

## Writing a New Module

```python
# suika_hub/modules/vuln/my_scanner.py
from suika_hub.core.base import BaseScanner, Finding, Severity

class MyScanner(BaseScanner):
    name = "my-scanner"
    description = "What it checks for"
    category = "vuln"

    def scan(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        # ... your logic ...
        findings.append(Finding(
            title="Found something",
            severity=Severity.HIGH,
            target=target,
            description="Detailed description",
            remediation="How to fix it",
            references=["https://cwe.mitre.org/data/definitions/XXX.html"],
        ))
        return findings
```

Register it in `suika_hub/modules/vuln/__init__.py`:
```python
from .my_scanner import MyScanner
__all__ = [..., "MyScanner"]
```

## Writing Tests

```python
# tests/test_my_scanner.py
import pytest
from suika_hub.modules.vuln.my_scanner import MyScanner

@pytest.fixture
def scanner():
    return MyScanner()

def test_scanner_detects_issue(scanner, mock_target):
    findings = scanner.scan(mock_target)
    assert any(f.severity == "high" for f in findings)

def test_scanner_clean_target(scanner, mock_clean_target):
    findings = scanner.scan(mock_clean_target)
    assert len(findings) == 0
```

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation
- `test:` — Tests
- `refactor:` — Code refactoring
- `perf:` — Performance improvement
- `ci:` — CI/CD changes
- `chore:` — Maintenance

## Code Style

- **Python 3.9+** with type hints
- **Ruff** for linting and formatting
- **mypy** for type checking (strict mode)
- Maximum line length: 100 characters
- Docstrings: Google style

## Reporting Issues

- Use GitHub Issues
- Include reproduction steps
- Include `suika --version` output
- Include relevant logs (use `--debug` flag)

## Security

Found a security issue in suika-hub itself? **Do not open a public issue.** Email security@suika-hub.dev with details. We'll respond within 48 hours.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Questions?** Open a Discussion on GitHub or join our Discord. We're happy to help new contributors!
