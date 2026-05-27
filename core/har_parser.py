"""HAR file parser - import browser sessions"""
import json
from typing import Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse


class HARParser:
    """Parse HAR files to extract auth, endpoints, and patterns"""

    def __init__(self, har_path: str):
        self.path = Path(har_path)
        self.data = self._load()
        self.entries = self.data.get("log", {}).get("entries", [])

    def _load(self) -> Dict:
        """Load HAR file"""
        content = self.path.read_text(encoding="utf-8")
        return json.loads(content)

    def extract_cookies(self, domain: Optional[str] = None) -> Dict[str, str]:
        """Extract cookies from HAR entries"""
        cookies = {}
        for entry in self.entries:
            req = entry.get("request", {})
            url = req.get("url", "")

            if domain and domain not in url:
                continue

            for cookie in req.get("cookies", []):
                cookies[cookie["name"]] = cookie["value"]

        return cookies

    def extract_headers(self, domain: Optional[str] = None) -> Dict[str, str]:
        """Extract auth headers (Authorization, X-Token, etc.)"""
        headers = {}
        auth_keys = ["authorization", "x-token", "x-api-key", "x-csrf-token", "x-session"]

        for entry in self.entries:
            req = entry.get("request", {})
            url = req.get("url", "")

            if domain and domain not in url:
                continue

            for header in req.get("headers", []):
                name = header["name"].lower()
                if name in auth_keys:
                    headers[header["name"]] = header["value"]

        return headers

    def extract_endpoints(self, domain: Optional[str] = None) -> List[Dict]:
        """Extract all API endpoints with methods and params"""
        endpoints = []
        seen = set()

        for entry in self.entries:
            req = entry.get("request", {})
            resp = entry.get("response", {})
            url = req.get("url", "")
            method = req.get("method", "GET")

            if domain and domain not in url:
                continue

            # Parse URL
            parsed = urlparse(url)
            path = parsed.path

            # Skip static assets
            if any(path.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico"]):
                continue

            key = f"{method}:{path}"
            if key in seen:
                continue
            seen.add(key)

            # Extract query params
            params = {}
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        k, v = param.split("=", 1)
                        params[k] = v

            # Extract request body
            body = None
            post_data = req.get("postData", {})
            if post_data:
                body = post_data.get("text")

            endpoints.append({
                "method": method,
                "path": path,
                "url": url,
                "params": params,
                "body": body,
                "status": resp.get("status", 0),
                "content_type": resp.get("content", {}).get("mimeType", ""),
            })

        return endpoints

    def extract_api_patterns(self, domain: Optional[str] = None) -> Dict:
        """Analyze API patterns (base paths, ID formats, auth scheme)"""
        endpoints = self.extract_endpoints(domain)

        # Find base API paths
        api_paths = set()
        id_patterns = []

        for ep in endpoints:
            path = ep["path"]
            parts = path.split("/")

            # Detect API base
            for i, part in enumerate(parts):
                if part in ("api", "v1", "v2", "v3"):
                    api_paths.add("/".join(parts[:i+1]))

            # Detect ID patterns in path
            for part in parts:
                if len(part) == 24 and all(c in "0123456789abcdef" for c in part):
                    id_patterns.append({"type": "mongodb_objectid", "example": part})
                elif part.isdigit():
                    id_patterns.append({"type": "numeric", "example": part})

        return {
            "total_endpoints": len(endpoints),
            "api_bases": list(api_paths),
            "id_patterns": id_patterns[:10],
            "methods": list(set(ep["method"] for ep in endpoints)),
            "endpoints": endpoints,
        }

    def get_session_info(self, domain: Optional[str] = None) -> Dict:
        """Get complete session info for scanner"""
        return {
            "cookies": self.extract_cookies(domain),
            "headers": self.extract_headers(domain),
            "endpoints": self.extract_endpoints(domain),
            "patterns": self.extract_api_patterns(domain),
        }
