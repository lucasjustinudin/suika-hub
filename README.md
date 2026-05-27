<div align="center">

# suika-hub

Modular vulnerability scanning hub — async engine, AI analysis, browser capture.

[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)]()
[![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)]()

</div>

---

## Architecture

```
suika.py (CLI)
    |
    +-- core/
    |   |-- engine.py        Async scan orchestrator
    |   |-- config.py        Pydantic-based config
    |   |-- http.py          Async HTTP client
    |   |-- module.py        Base module interface
    |   |-- reporter.py      Finding output
    |
    +-- modules/
    |   |-- RedStorm         RedStorm-style analysis
    |   |-- IDOR             IDOR detection
    |   |-- Recon            Reconnaissance
    |   |-- APIFuzzer        API endpoint fuzzing
    |   |-- AuthBypass       Auth bypass detection
    |   |-- FileUpload       Upload vulnerability scanner
    |   |-- SSRF             SSRF detection
    |
    +-- extension/
    |   |-- Chrome extension for session capture
    |
    +-- server.py            Local capture server (aiohttp)
```

## Modules

| Module | Purpose |
|--------|---------|
| RedStorm | RedStorm-style analysis patterns |
| IDOR | Insecure direct object reference detection |
| Recon | Target reconnaissance and discovery |
| APIFuzzer | API endpoint fuzzing |
| AuthBypass | Authentication bypass detection |
| FileUpload | File upload vulnerability scanner |
| SSRF | Server-side request forgery detection |

## Usage

```bash
# Scan a target
python suika.py --target https://example.com --modules recon,ssrf

# Start capture server (for browser extension)
python server.py

# View all options
python suika.py --help
```

## Setup

```bash
pip install -r requirements.txt
python test_imports.py    # Verify installation
```

## License

Private — all rights reserved.
