# Suika Hunter v2

Next-generation bug bounty hunting framework — async, modular, AI-powered vulnerability scanner.

## Architecture

```
suika.py (CLI entry)
    |
    +-- core/
    |   |-- config.py      Scan configuration
    |   |-- engine.py      Async scan orchestrator
    |
    +-- modules/
    |   |-- RedStorm       RedStorm-style analysis
    |   |-- IDOR           IDOR detection
    |   |-- [more scanners]
    |
    +-- extension/
    |   |-- browser        Chrome extension for capture
    |
    +-- server.py          Local capture server (aiohttp)
    |   |-- Receives session data from browser extension
    |   |-- Bridge between extension and scanner
    |
    +-- configs/           Scan profiles and templates
```

## Features

- **Async Engine** — fast, concurrent target analysis
- **Browser Extension** — capture and replay sessions
- **Modular Scanners** — add custom modules easily
- **AI Analysis** — intelligent vulnerability detection

## Usage

```bash
python suika.py --help
python server.py          # Start capture server
```

## Setup

```bash
pip install -r requirements.txt
python test_imports.py    # Verify installation
```

## License

Private — all rights reserved.
