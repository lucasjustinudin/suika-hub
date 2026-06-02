#!/usr/bin/env python3
"""Verify all suika_hub imports work correctly."""
import sys

print("Testing suika_hub imports...")

import suika_hub
print(f"  suika_hub OK (version: {suika_hub.__version__})")

from suika_hub.core.config import ScanConfig, AuthConfig
print("  suika_hub.core.config OK")

from suika_hub.core.engine import SuikaEngine
print("  suika_hub.core.engine OK")

from suika_hub.core.http import AsyncClient
print("  suika_hub.core.http OK")

from suika_hub.core.module import BaseModule, Finding
print("  suika_hub.core.module OK")

from suika_hub.core.reporter import Reporter
print("  suika_hub.core.reporter OK")

from suika_hub.core.har_parser import HARParser
print("  suika_hub.core.har_parser OK")

from suika_hub.core.decision_engine import DecisionEngine
print("  suika_hub.core.decision_engine OK")

from suika_hub.modules import (
    RedStormScanner, IDORScanner, ReconScanner,
    APIFuzzer, AuthBypassScanner, FileUploadScanner, SSRFScanner,
)
print("  suika_hub.modules OK")

# Test engine registration
engine = SuikaEngine()
engine.register(RedStormScanner)
engine.register(IDORScanner)
engine.register(ReconScanner)
engine.register(APIFuzzer)
engine.register(AuthBypassScanner)
engine.register(FileUploadScanner)
engine.register(SSRFScanner)

print(f"\nRegistered {len(engine.modules)} modules:")
for alias, name in sorted(engine.aliases.items()):
    if alias != name:
        print(f"  {alias} -> {name}")

# Test config creation
config = ScanConfig(target="https://example.com", modules=["recon"])
print(f"\nConfig test: target={config.target}, modules={config.modules}")

print("\nAll checks passed!")
