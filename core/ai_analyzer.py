"""AI-powered vulnerability analysis via LLM"""
import json
import os
from typing import Dict, List, Optional
import httpx


class AIAnalyzer:
    """Use LLM to analyze findings and suggest next steps"""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None, model: str = "auto"):
        self.base_url = base_url or os.getenv("AI_BASE_URL", "https://hdnsbr-salapanruter.hf.space/v1")
        self.api_key = api_key or os.getenv("AI_API_KEY", "dummy")
        self.model = model

    async def analyze_response(self, endpoint: str, response: Dict) -> Dict:
        """Analyze an API response for vulnerabilities"""
        prompt = f"""Analyze this API response for security vulnerabilities:

Endpoint: {endpoint}
Status: {response.get('status')}
Headers: {json.dumps(response.get('headers', {}), indent=2)[:500]}
Body: {json.dumps(response.get('body', ''), indent=2)[:1000]}

Look for:
1. Information disclosure (emails, tokens, internal IDs)
2. IDOR indicators (user-specific data accessible without auth)
3. Sensitive headers (server version, debug info)
4. Error messages that leak implementation details

Return JSON with: severity, finding, evidence, next_steps"""

        return await self._query(prompt)

    async def suggest_attack_vectors(self, target_info: Dict) -> List[Dict]:
        """Suggest attack vectors based on target reconnaissance"""
        prompt = f"""Based on this target reconnaissance, suggest attack vectors:

Target: {target_info.get('target')}
Stack: {target_info.get('stack', 'unknown')}
Endpoints found: {len(target_info.get('endpoints', []))}
API patterns: {json.dumps(target_info.get('patterns', {}), indent=2)[:500]}

Suggest top 5 attack vectors with:
- vector_name
- priority (1-5)
- description
- specific_endpoints_to_test
- payloads_to_try

Return as JSON array."""

        return await self._query(prompt)

    async def generate_poc(self, finding: Dict) -> str:
        """Generate proof-of-concept for a finding"""
        prompt = f"""Generate a proof-of-concept (PoC) for this vulnerability finding:

Title: {finding.get('title')}
Severity: {finding.get('severity')}
Endpoint: {finding.get('url')}
Description: {finding.get('description')}
Evidence: {finding.get('evidence', '')}

Generate:
1. Step-by-step reproduction
2. curl command to reproduce
3. Impact statement
4. Suggested fix

Format as markdown."""

        result = await self._query(prompt)
        return result.get("content", "") if isinstance(result, dict) else str(result)

    async def classify_severity(self, findings: List[Dict]) -> List[Dict]:
        """Re-classify findings with AI-powered severity assessment"""
        prompt = f"""Classify these security findings by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO):

{json.dumps(findings[:10], indent=2)}

For each finding, assess:
- Real-world exploitability
- Data sensitivity
- Business impact
- Whether it's a true positive or false positive

Return JSON array with original finding + ai_severity + ai_confidence + reasoning"""

        return await self._query(prompt)

    async def _query(self, prompt: str) -> any:
        """Query LLM API"""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": "You are a security researcher analyzing web application vulnerabilities. Return structured JSON when asked."},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.3,
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    content = data["choices"][0]["message"]["content"]
                    # Try to parse as JSON
                    try:
                        return json.loads(content)
                    except json.JSONDecodeError:
                        return {"content": content}
                else:
                    return {"error": f"API error: {response.status_code}"}

        except Exception as e:
            return {"error": str(e)}
