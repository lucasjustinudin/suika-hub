"""Suika Hunter v2 Modules"""
from modules.redstorm import RedStormScanner
from modules.idor import IDORScanner
from modules.recon import ReconScanner
from modules.api_fuzzer import APIFuzzer
from modules.auth_bypass import AuthBypassScanner
from modules.upload_scanner import FileUploadScanner
from modules.ssrf_scanner import SSRFScanner

__all__ = [
    "RedStormScanner",
    "IDORScanner",
    "ReconScanner",
    "APIFuzzer",
    "AuthBypassScanner",
    "FileUploadScanner",
    "SSRFScanner",
]
