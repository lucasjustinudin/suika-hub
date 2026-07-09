"""Optional AI-powered vulnerability analysis via OpenAI-compatible APIs."""

from __future__ import annotations

import json
import os
from typing import Any

import httpx


class AIAnalyzer:
    """Use an OpenAI-compatible LLM API to analyze findings.

    AI is intentionally opt-in. Configure ``AI_API_KEY`` and optionally
    ``AI_BASE_URL``/``AI_MODEL`` before calling methods that query the API.
    """

    def __init__(self, base_url: str | None = None, api_key: str | None = None, model: str | None = None):
        self.base_url = (base_url or os.getenv("AI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key or os.getenv("AI_API_KEY")
        self.model = model or os.getenv("AI_MODEL", "gpt-4o-mini")

    @property
    def enabled(self) -> bool:
        """Return True when AI requests can be made."""
        return bool(self.api_key)

    async def analyze_response(self, endpoint: str, response: dict) -> dict:
        """Analyze an API response for potential security issues."""
        prompt = f"""Analyze this API response for security vulnerabilities:

Endpoint: {endpoint}
Status: {response.get('status')}
Headers: {json.dumps(response.get('headers', {}), indent=2)[:500]}
Body: {json.dumps(response.get('body', ''), indent=2)[:1000]}

Look for information disclosure, IDOR indicators, sensitive headers, and implementation leaks.
Return JSON with: severity, finding, evidence, next_steps."""
        return await self._query(prompt)

    async def suggest_attack_vectors(self, target_info: dict) -> list[dict] | dict:
        """Suggest attack vectors based on target reconnaissance."""
        prompt = f"""Based on this target reconnaissance, suggest authorized test vectors:

Target: {target_info.get('target')}
Stack: {target_info.get('stack', 'unknown')}
Endpoints found: {len(target_info.get('endpoints', []))}
API patterns: {json.dumps(target_info.get('patterns', {}), indent=2)[:500]}

Return a JSON array with vector_name, priority, description, specific_endpoints_to_test, payloads_to_try."""
        return await self._query(prompt)

    async def generate_poc(self, finding: dict) -> str:
        """Generate a reproduction-oriented proof of concept for a finding."""
        prompt = f"""Generate an authorized-testing proof-of-concept for this vulnerability finding:

Title: {finding.get('title')}
Severity: {finding.get('severity')}
Endpoint: {finding.get('url')}
Description: {finding.get('description')}
Evidence: {finding.get('evidence', '')}

Include reproduction steps, curl command, impact statement, and suggested fix. Format as markdown."""
        result = await self._query(prompt)
        return result.get("content", "") if isinstance(result, dict) else str(result)

    async def classify_severity(self, findings: list[dict]) -> list[dict] | dict:
        """Re-classify findings with AI-powered severity assessment."""
        prompt = f"""Classify these findings by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO):

{json.dumps(findings[:10], indent=2)}

Assess exploitability, data sensitivity, business impact, and false-positive likelihood.
Return JSON array with original finding + ai_severity + ai_confidence + reasoning."""
        return await self._query(prompt)

    async def _query(self, prompt: str) -> Any:
        """Query configured LLM API and return parsed JSON when possible."""
        if not self.enabled:
            return {"error": "AI_API_KEY is not configured; AI analysis is disabled"}

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": "You are a security researcher analyzing authorized web application test results. Return structured JSON when asked."},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.3,
                    },
                )
                if response.status_code != 200:
                    return {"error": f"API error: {response.status_code}", "body": response.text[:500]}

                content = response.json()["choices"][0]["message"]["content"]
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    return {"content": content}
        except Exception as exc:  # pragma: no cover - defensive API boundary
            return {"error": str(exc)}
