"""Suika Hunter v2 Modules"""
from suika_hub.modules.api_fuzzer import APIFuzzer
from suika_hub.modules.auth_bypass import AuthBypassScanner
from suika_hub.modules.idor import IDORScanner
from suika_hub.modules.recon import ReconScanner
from suika_hub.modules.redstorm import RedStormScanner
from suika_hub.modules.ssrf_scanner import SSRFScanner
from suika_hub.modules.upload_scanner import FileUploadScanner

__all__ = [
    "RedStormScanner",
    "IDORScanner",
    "ReconScanner",
    "APIFuzzer",
    "AuthBypassScanner",
    "FileUploadScanner",
    "SSRFScanner",
]
