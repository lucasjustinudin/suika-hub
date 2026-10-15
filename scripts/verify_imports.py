#!/usr/bin/env python3
"""Verify all suika_hub imports work correctly.

Run in CI and locally after adding a module: a module that fails to import is
invisible to the test suite if no test touches it, so this script exercises the
package surface explicitly.
"""

import sys

print("Testing suika_hub imports...")

import suika_hub

print(f"  suika_hub OK (version: {suika_hub.__version__})")

from suika_hub.core.config import AuthConfig, ScanConfig

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

from suika_hub.core.ratelimit import ProxyPool, RateLimiter

print("  suika_hub.core.ratelimit OK")

from suika_hub.core.retry import RetryPolicy, parse_retry_after

print("  suika_hub.core.retry OK")

from suika_hub.modules import (
    APIFuzzer,
    AuthBypassScanner,
    FileUploadScanner,
    GraphQLScanner,
    IDORScanner,
    JWTScanner,
    ReconScanner,
    SSRFScanner,
)

print("  suika_hub.modules OK")

# Register every module and confirm aliases resolve.
ENGINE_MODULES = [
    IDORScanner,
    ReconScanner,
    APIFuzzer,
    AuthBypassScanner,
    FileUploadScanner,
    SSRFScanner,
    GraphQLScanner,
    JWTScanner,
]

engine = SuikaEngine()
for module_class in ENGINE_MODULES:
    engine.register(module_class)

print(f"\nRegistered {len(engine.modules)} modules:")
for alias, name in sorted(engine.aliases.items()):
    if alias != name:
        print(f"  {alias} -> {name}")

# Every alias must resolve to an instantiated module.
unresolved = [alias for alias in engine.aliases if engine.resolve(alias) is None]
if unresolved:
    print(f"\nERROR: aliases did not resolve: {unresolved}")
    sys.exit(1)

# Config creation, including the module passthrough used by graphql/jwt.
config = ScanConfig(target="https://example.com", modules=["recon"], extra={"jwt": "a.b.c"})
merged = config.module_config()
if merged.get("jwt") != "a.b.c":
    print("\nERROR: module_config() did not merge extra keys")
    sys.exit(1)

print(f"\nConfig test: target={config.target}, modules={config.modules}, extra merged OK")
print("\nAll checks passed!")
