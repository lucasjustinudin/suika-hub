"""Intelligent Decision Engine - inspired by HexStrike
Scores targets and recommends optimal attack strategy"""

from typing import Dict, List, Tuple
from dataclasses import dataclass, field


@dataclass
class TargetProfile:
    """Profile of a target based on recon"""
    domain: str
    stack: List[str] = field(default_factory=list)  # nodejs, python, php, etc
    frameworks: List[str] = field(default_factory=list)  # express, django, laravel
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
    "redstorm_scanner": {"idor": 0.9, "info_disclosure": 0.85, "auth_bypass": 0.7},
}

# Time estimates per module (seconds)
MODULE_TIME_ESTIMATE = {
    "recon_scanner": 30,
    "idor_scanner": 60,
    "api_fuzzer": 90,
    "auth_bypass": 45,
    "ssrf_scanner": 60,
    "upload_scanner": 45,
    "redstorm_scanner": 40,
}


class DecisionEngine:
    """Recommend optimal scan strategy based on target profile"""

    def recommend_modules(self, profile: TargetProfile, time_budget: int = 300) -> List[Dict]:
        """Recommend modules ordered by expected value"""
        # Get priority vulns for this stack
        stack = profile.stack[0] if profile.stack else "default"
        priority_vulns = VULN_PRIORITY.get(stack, VULN_PRIORITY["default"])

        # Score each module
        scored_modules = []
        for module_name, effectiveness in MODULE_EFFECTIVENESS.items():
            score = 0
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

            time_est = MODULE_TIME_ESTIMATE.get(module_name, 60)

            scored_modules.append({
                "module": module_name,
                "score": round(score, 3),
                "time_estimate": time_est,
                "reason": self._get_reason(module_name, profile, priority_vulns),
            })

        # Sort by score descending
        scored_modules.sort(key=lambda x: x["score"], reverse=True)

        # Filter by time budget
        selected = []
        remaining_time = time_budget
        for mod in scored_modules:
            if remaining_time >= mod["time_estimate"]:
                selected.append(mod)
                remaining_time -= mod["time_estimate"]

        return selected

    def recommend_for_redstorm(self) -> List[Dict]:
        """Specific recommendations for RedStorm platform"""
        profile = TargetProfile(
            domain="www.redstorm.io",
            stack=["nodejs"],
            frameworks=["express"],
            database="mongodb",
            auth_type="session",
            waf="cloudflare",
            api_style="rest",
            endpoints_count=22,
            has_upload=False,
            has_websocket=True,  # Socket.io detected
        )

        recommendations = self.recommend_modules(profile, time_budget=600)

        # Add RedStorm-specific notes
        for rec in recommendations:
            if rec["module"] == "redstorm_scanner":
                rec["notes"] = "Primary module - IDOR via leaderboard usernames, program enumeration"
            elif rec["module"] == "api_fuzzer":
                rec["notes"] = "NoSQL injection likely (MongoDB backend), test $ne/$gt operators"
            elif rec["module"] == "auth_bypass":
                rec["notes"] = "Test researcher->admin escalation, mass assignment on profile"

        return recommendations

    def _get_reason(self, module: str, profile: TargetProfile, priority_vulns: List[str]) -> str:
        """Generate human-readable reason for recommendation"""
        reasons = {
            "idor_scanner": f"IDOR is #{priority_vulns.index('idor')+1 if 'idor' in priority_vulns else '?'} priority for {profile.stack}",
            "api_fuzzer": f"{'NoSQL' if profile.database == 'mongodb' else 'SQL'} injection testing for {profile.database or 'unknown DB'}",
            "auth_bypass": "Test authentication boundaries and privilege escalation",
            "ssrf_scanner": f"SSRF testing for {profile.api_style} API",
            "upload_scanner": "File upload bypass" + (" (upload detected)" if profile.has_upload else " (speculative)"),
            "recon_scanner": "Subdomain and endpoint discovery",
            "redstorm_scanner": "Platform-specific IDOR and enumeration",
        }
        return reasons.get(module, "General security testing")

    def analyze_findings(self, findings: List[Dict]) -> Dict:
        """Analyze findings and suggest next steps"""
        if not findings:
            return {"next_steps": ["Verify cookies are valid", "Try browser mode for Cloudflare bypass"]}

        severity_count = {}
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
