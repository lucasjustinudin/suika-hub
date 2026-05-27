#!/usr/bin/env python3
"""Quick sanity check - verify all imports work"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

print("Testing imports...")

from core.config import ScanConfig, AuthConfig
print("  core.config OK")

from core.engine import SuikaEngine
print("  core.engine OK")

from core.http import AsyncClient
print("  core.http OK")

from core.har_parser import HARParser
print("  core.har_parser OK")

from core.ai_analyzer import AIAnalyzer
print("  core.ai_analyzer OK")

from core.module import BaseModule, Finding
print("  core.module OK")

from core.reporter import Reporter
print("  core.reporter OK")

from modules import RedStormScanner, IDORScanner, ReconScanner, APIFuzzer, AuthBypassScanner
print("  modules OK")

# Test engine registration
engine = SuikaEngine()
engine.register(RedStormScanner)
engine.register(IDORScanner)
engine.register(ReconScanner)
engine.register(APIFuzzer)
engine.register(AuthBypassScanner)

print(f"\nRegistered {len(engine.modules)} modules:")
for alias, name in sorted(engine.aliases.items()):
    if alias != name:
        print(f"  {alias} -> {name}")

print("\nAll checks passed!")
