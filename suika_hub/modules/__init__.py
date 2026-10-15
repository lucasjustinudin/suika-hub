"""Suika Hub scanner modules."""

from suika_hub.modules.api_fuzzer import APIFuzzer
from suika_hub.modules.auth_bypass import AuthBypassScanner
from suika_hub.modules.graphql_scanner import GraphQLScanner
from suika_hub.modules.idor import IDORScanner
from suika_hub.modules.jwt_scanner import JWTScanner
from suika_hub.modules.recon import ReconScanner
from suika_hub.modules.ssrf_scanner import SSRFScanner
from suika_hub.modules.upload_scanner import FileUploadScanner

__all__ = [
    "IDORScanner",
    "ReconScanner",
    "APIFuzzer",
    "AuthBypassScanner",
    "FileUploadScanner",
    "SSRFScanner",
    "GraphQLScanner",
    "JWTScanner",
]
