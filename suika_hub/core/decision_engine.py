"""Intelligent Decision Engine - inspired by HexStrike.

Scores targets and recommends an optimal attack strategy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetProfile:
    """Profile of a target based on recon"""

    domain: str
    stack: list[str] = field(default_factory=list)  # nodejs, python, php, etc
    frameworks: list[str] = field(default_factory=list)  # express, django, laravel
    database: str = ""  # mongodb, postgresql, mysql
    auth_type: str = ""  # session, jwt, oauth
    waf: str = ""  # cloudflare, akamai, etc
    api_style: str = ""  # rest, graphql, soap
    endpoints_count: int = 0
    has_upload: bool = False
    has_websocket: bool = False


# Vulnerability priority by target stack
VULN_PRIORITY = {
    "nodejs": ["nosql_injection", "ssrf", "idor", "prototype_pollution", "xss"],
    "python": ["ssti", "ssrf", "idor", "deserialization", "path_traversal"],
    "php": ["sqli", "file_upload", "lfi", "xss", "deserialization"],
    "java": ["deserialization", "xxe", "ssrf", "sqli", "path_traversal"],
    "ruby": ["ssti", "deserialization", "ssrf", "idor", "mass_assignment"],
    "default": ["idor", "sqli", "xss", "ssrf", "auth_bypass"],
}

# Module effectiveness per vulnerability type
MODULE_EFFECTIVENESS = {
    "idor_scanner": {"idor": 0.95, "auth_bypass": 0.6, "info_disclosure": 0.7},
    "api_fuzzer": {"sqli": 0.9, "nosql_injection": 0.85, "xss": 0.8, "boundary": 0.7},
    "auth_bypass": {"auth_bypass": 0.95, "privilege_escalation": 0.9, "idor": 0.5},
    "ssrf_scanner": {"ssrf": 0.95, "cloud_metadata": 0.9, "internal_access": 0.85},
    "upload_scanner": {"file_upload": 0.95, "rce": 0.8, "xss": 0.3},
    "recon_scanner": {"info_disclosure": 0.9, "subdomain": 0.95, "tech_detection": 0.9},
    "graphql_scanner": {"info_disclosure": 0.85, "auth_bypass": 0.5, "boundary": 0.7},
    "jwt_scanner": {"auth_bypass": 0.95, "privilege_escalation": 0.9, "idor": 0.4},
}

# Time estimates per module (seconds)
MODULE_TIME_ESTIMATE = {
    "recon_scanner": 30,
    "idor_scanner": 60,
    "api_fuzzer": 90,
    "auth_bypass": 45,
    "ssrf_scanner": 60,
    "upload_scanner": 45,
    "graphql_scanner": 30,
    "jwt_scanner": 20,
}


# Named target profiles: a stack shape, reusable across engagements.
PROFILES: dict[str, TargetProfile] = {
    "nodejs": TargetProfile(
        domain="example.com",
        stack=["nodejs"],
        frameworks=["express"],
        database="mongodb",
        auth_type="session",
        api_style="rest",
        has_websocket=True,
    ),
    "python": TargetProfile(
        domain="example.com",
        stack=["python"],
        frameworks=["django"],
        database="postgresql",
        auth_type="session",
        api_style="rest",
    ),
    "php": TargetProfile(
        domain="example.com",
        stack=["php"],
        frameworks=["laravel"],
        database="mysql",
        auth_type="session",
        api_style="rest",
        has_upload=True,
    ),
    "java": TargetProfile(
        domain="example.com",
        stack=["java"],
        frameworks=["spring"],
        database="postgresql",
        auth_type="jwt",
        api_style="rest",
    ),
    "spa": TargetProfile(
        domain="example.com",
        stack=["nodejs"],
        frameworks=["nextjs"],
        database="postgresql",
        auth_type="jwt",
        api_style="graphql",
    ),
}

# Per-module guidance derived from the target profile. Keyed by module name so
# guidance stays generic: any profile that matches a condition gets the note.
PROFILE_NOTES: dict[str, Any] = {
    "api_fuzzer": lambda p: (
        "NoSQL injection likely (MongoDB backend), test $ne/$gt operators"
        if p.database == "mongodb"
        else f"{'SQL' if p.database else 'SQL/NoSQL'} injection testing for {p.database or 'unknown DB'}"
    ),
    "auth_bypass": lambda p: (
        f"Auth type is {p.auth_type}: test token/claim tampering and role escalation"
        if p.auth_type
        else "Test authentication boundaries and privilege escalation"
    ),
    "jwt_scanner": lambda p: (
        "Primary module - auth uses JWTs: test alg confusion, none-alg, claim tampering"
        if p.auth_type == "jwt"
        else "No JWT auth detected; run only if tokens are observed in traffic"
    ),
    "graphql_scanner": lambda p: (
        "Primary module - GraphQL API detected: test introspection, alias batching, complexity"
        if p.api_style == "graphql"
        else "API is not GraphQL; run only if a /graphql route is found"
    ),
    "ssrf_scanner": lambda p: f"SSRF testing for {p.api_style or 'unknown'} API",
    "upload_scanner": lambda p: "File upload bypass" + (" (upload detected)" if p.has_upload else " (speculative)"),
    "idor_scanner": lambda p: "Object reference testing with baseline comparison",
    "recon_scanner": lambda p: "Subdomain and endpoint discovery",
}

# Default time budget per named profile (seconds).
PROFILE_BUDGET: dict[str, int] = {
    "nodejs": 600,
    "python": 480,
    "php": 480,
    "java": 540,
    "spa": 540,
}


class DecisionEngine:
    """Recommend optimal scan strategy based on target profile"""

    def recommend_modules(self, profile: TargetProfile, time_budget: int = 300) -> list[dict[str, Any]]:
        """Recommend modules ordered by expected value"""
        # Get priority vulns for this stack
        stack = profile.stack[0] if profile.stack else "default"
        priority_vulns = VULN_PRIORITY.get(stack, VULN_PRIORITY["default"])

        # Score each module
        scored_modules: list[dict[str, Any]] = []
        for module_name, effectiveness in MODULE_EFFECTIVENESS.items():
            score: float = 0.0
            for vuln_type in priority_vulns[:5]:
                weight = 1.0 - (priority_vulns.index(vuln_type) * 0.15)
                score += effectiveness.get(vuln_type, 0) * weight

            # Bonus for specific conditions
            if module_name == "upload_scanner" and profile.has_upload:
                score *= 1.5
            if module_name == "ssrf_scanner" and profile.api_style == "rest":
                score *= 1.2
            if module_name == "api_fuzzer" and profile.database == "mongodb":
                score *= 1.3  # NoSQL injection more likely
            # Profile-matched modules need a relevance floor, not just a
            # multiplier: the vuln-priority list is stack-derived and often
            # shares no key with the module's effectiveness table, so a
            # multiplier would be applied to a zero score and the module that
            # directly targets the detected technology would rank last.
            if module_name == "graphql_scanner" and profile.api_style == "graphql":
                score = max(score, 0.5) * 2.0
            if module_name == "jwt_scanner" and profile.auth_type == "jwt":
                score = max(score, 0.5) * 2.0

            time_est: int = MODULE_TIME_ESTIMATE.get(module_name, 60)

            scored_modules.append(
                {
                    "module": module_name,
                    "score": round(score, 3),
                    "time_estimate": time_est,
                    "reason": self._get_reason(module_name, profile, priority_vulns),
                }
            )

        # Sort by score descending
        scored_modules.sort(key=lambda x: float(str(x["score"])), reverse=True)

        # Filter by time budget
        selected: list[dict[str, Any]] = []
        remaining_time = time_budget
        for mod in scored_modules:
            cost = int(str(mod["time_estimate"]))
            if remaining_time >= cost:
                selected.append(mod)
                remaining_time -= cost

        return selected

    def recommend_for_profile(self, profile_name: str) -> list[dict]:
        """Recommend modules for a named target profile.

        Profiles describe a *class* of target (a stack shape), not a specific
        host: the point is to encode "this looks like a Node/Mongo REST API, so
        NoSQL injection is likely" and reuse it across engagements.
        """
        profile = PROFILES.get(profile_name.lower())
        if profile is None:
            return []
        budget = PROFILE_BUDGET.get(profile_name.lower(), 300)
        recommendations = self.recommend_modules(profile, time_budget=budget)

        # Attach guidance derived from the profile, so recommendations explain
        # *why* a module matters for this stack shape.
        for rec in recommendations:
            note = PROFILE_NOTES.get(rec["module"])
            if note:
                rec["notes"] = note(profile)
        return recommendations

    def _get_reason(self, module: str, profile: TargetProfile, priority_vulns: list[str]) -> str:
        """Generate human-readable reason for recommendation"""
        reasons = {
            "idor_scanner": f"IDOR is #{priority_vulns.index('idor') + 1 if 'idor' in priority_vulns else '?'} priority for {profile.stack}",
            "api_fuzzer": f"{'NoSQL' if profile.database == 'mongodb' else 'SQL'} injection testing for {profile.database or 'unknown DB'}",
            "auth_bypass": "Test authentication boundaries and privilege escalation",
            "ssrf_scanner": f"SSRF testing for {profile.api_style} API",
            "upload_scanner": "File upload bypass" + (" (upload detected)" if profile.has_upload else " (speculative)"),
            "recon_scanner": "Subdomain and endpoint discovery",
        }
        return reasons.get(module, "General security testing")

    def analyze_findings(self, findings: list[dict]) -> dict:
        """Analyze findings and suggest next steps"""
        if not findings:
            return {"next_steps": ["Verify cookies are valid", "Try browser mode for Cloudflare bypass"]}

        severity_count: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_count[sev] = severity_count.get(sev, 0) + 1

        next_steps = []

        if severity_count.get("CRITICAL", 0) > 0:
            next_steps.append("Write PoC for CRITICAL findings immediately")
            next_steps.append("Document reproduction steps with screenshots")

        if severity_count.get("HIGH", 0) > 0:
            next_steps.append("Verify HIGH findings manually in browser")
            next_steps.append("Check if findings can be chained for higher impact")

        if severity_count.get("MEDIUM", 0) > 0:
            next_steps.append("Investigate MEDIUM findings for escalation potential")

        # Chain detection
        has_idor = any("IDOR" in f.get("title", "") for f in findings)
        has_info_disclosure = any("enumeration" in f.get("title", "").lower() for f in findings)

        if has_idor and has_info_disclosure:
            next_steps.append("CHAIN: Info disclosure + IDOR = mass data access (escalate severity)")

        return {
            "severity_breakdown": severity_count,
            "total_findings": len(findings),
            "next_steps": next_steps,
            "chain_potential": has_idor and has_info_disclosure,
        }
