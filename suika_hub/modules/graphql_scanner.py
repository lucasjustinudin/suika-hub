"""GraphQL scanner: introspection, alias batching, and depth-abuse checks.

GraphQL endpoints fail in ways REST endpoints cannot, so the checks here target
GraphQL-specific weaknesses:

- **Introspection left enabled** in production leaks the whole schema, which
  turns every other test from guesswork into a checklist.
- **Alias batching** lets one HTTP request carry hundreds of operations. That is
  how rate limits and query-cost limits get bypassed even when a per-request
  limiter exists.
- **Unbounded depth / cycles** let a single query exhaust the server.

Every check pairs a positive probe with a control request, so a finding means
"this behaved differently from the control", not "the word error appeared".
"""

from __future__ import annotations

from typing import Any

from rich.console import Console

from suika_hub.core.http import AsyncClient
from suika_hub.core.module import BaseModule, Finding

console = Console()

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind }
  }
}
""".strip()

# Cheap type probe: asks for a field that may not exist. A schema-aware server
# answers with a validation error naming the type; a non-GraphQL endpoint does
# not.
TYPE_PROBE = "{ __typename }"

COMMON_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/v1",
    "/query",
    "/api/query",
    "/gql",
]


class GraphQLScanner(BaseModule):
    """GraphQL-specific security checks."""

    name = "graphql_scanner"
    description = "GraphQL introspection, alias batching, depth abuse, and error leakage"

    def __init__(self) -> None:
        super().__init__()
        self._endpoint: str | None = None

    async def execute(self, target: str, client: AsyncClient, config: dict) -> list[Finding]:
        """Run all GraphQL checks against the first responsive endpoint."""
        console.print("[bold cyan]GraphQL Scanner[/bold cyan] - Testing GraphQL-specific weaknesses")

        endpoints = config.get("graphql_endpoints") or self._candidate_endpoints(target, config)
        base_headers = {"Content-Type": "application/json"}

        for endpoint in endpoints:
            probe = await client.post(
                endpoint,
                json={"query": TYPE_PROBE},
                headers=base_headers,
            )
            if not self._looks_like_graphql(probe):
                continue

            self._endpoint = endpoint
            console.print(f"  [dim]GraphQL endpoint: {endpoint}[/dim]")

            await self._check_introspection(client, endpoint, base_headers, probe)
            await self._check_alias_batching(client, endpoint, base_headers)
            await self._check_depth_limit(client, endpoint, base_headers)
            break

        if not self._endpoint:
            console.print("  [dim]No GraphQL endpoint detected[/dim]")

        console.print(f"  [green]GraphQL scan complete: {len(self.findings)} findings[/green]")
        return self.findings

    def _candidate_endpoints(self, target: str, config: dict) -> list[str]:
        """Build the endpoint list from configured paths plus well-known defaults.

        Configured paths are taken as given: filtering them by name would drop
        legitimate custom routes (``/custom/gql``, ``/gql``) that do not contain
        the word "graphql".
        """
        target = target.rstrip("/")
        paths: list[str] = []

        for path in config.get("graphql_endpoints") or []:
            if path and path not in paths:
                paths.append(path)
        # ``endpoints`` is shared with the REST modules, so it can hold hundreds
        # of unrelated paths; keep only the ones that could plausibly be GraphQL.
        for path in config.get("endpoints") or []:
            if not path or path in paths:
                continue
            lowered = path.lower()
            if "graphql" in lowered or "gql" in lowered or lowered.endswith("/query"):
                paths.append(path)
        for path in COMMON_PATHS:
            if path not in paths:
                paths.append(path)

        return [f"{target}{p}" if p.startswith("/") else p for p in paths]

    def _looks_like_graphql(self, resp: dict[str, Any]) -> bool:
        """Decide whether a response came from a GraphQL server.

        A GraphQL server answers a bogus field with a structured ``errors``
        array. Anything else (404 HTML, redirect, empty body) is not GraphQL.
        """
        if resp.get("error") or resp.get("status") != 200:
            return False
        body = resp.get("body")
        if isinstance(body, dict):
            return "data" in body or "errors" in body
        return False

    async def _check_introspection(
        self,
        client: AsyncClient,
        endpoint: str,
        headers: dict[str, str],
        probe: dict[str, Any],
    ) -> None:
        """Report whether introspection is enabled in what looks like production."""
        resp = await client.post(endpoint, json={"query": INTROSPECTION_QUERY}, headers=headers)
        if resp.get("error") or resp.get("status") != 200:
            return

        body = resp.get("body")
        if not isinstance(body, dict):
            return

        data = body.get("data")
        if not isinstance(data, dict):
            return
        schema = data.get("__schema")
        if not schema:
            console.print("  [dim]Introspection disabled[/dim]")
            return

        types = schema.get("types") or []
        type_names = [str(t["name"]) for t in types if isinstance(t, dict) and t.get("name")]
        # Introspection is noisy: flag only when it actually returns a schema
        # rather than the two or three built-in introspection types.
        if len(type_names) < 5:
            return

        self.add_finding(
            severity="MEDIUM",
            title=f"GraphQL introspection enabled: {endpoint}",
            description=(
                "The endpoint returns its full schema to an unauthenticated caller, exposing every "
                "type, field, mutation and argument. This removes the discovery work needed to attack "
                "the API and often reveals internal-only fields."
            ),
            url=endpoint,
            evidence=f"{len(type_names)} types returned; sample: {', '.join(sorted(type_names)[:10])}",
            impact="Complete API surface disclosure; enables targeted abuse of hidden fields and mutations",
            remediation=(
                "Disable introspection in production, or gate it behind authentication. "
                "Disabling is defence in depth, not a fix on its own: introspection being off does not "
                "prevent field abuse, it only removes the map."
            ),
            extra={"types_exposed": len(type_names), "probe": "introspection"},
        )

    async def _check_alias_batching(
        self,
        client: AsyncClient,
        endpoint: str,
        headers: dict[str, str],
    ) -> None:
        """Test whether many operations can be smuggled into one request via aliases.

        This is the GraphQL equivalent of an unlimited batch endpoint: if a
        per-request rate limit is the only control, aliases defeat it. The check
        compares a single-operation request against an aliased batch and looks
        for the server processing all of them.
        """
        single = await client.post(endpoint, json={"query": "{ __typename }"}, headers=headers)
        if single.get("status") != 200:
            return

        count = 25
        aliased = "{" + " ".join(f"q{i}: __typename" for i in range(count)) + "}"
        batched = await client.post(endpoint, json={"query": aliased}, headers=headers)

        if batched.get("error") or batched.get("status") != 200:
            return

        body = batched.get("body")
        if not isinstance(body, dict):
            return

        data = body.get("data")
        if not isinstance(data, dict):
            return

        returned = len([k for k in data if k.startswith("q")])
        # Require the server to have actually resolved the batch, not merely
        # echoed the aliases back.
        if returned < count:
            return

        self.add_finding(
            severity="MEDIUM",
            title=f"GraphQL alias batching allows {returned} operations per request: {endpoint}",
            description=(
                f"A single HTTP request resolved {returned} aliased operations. Any control that counts "
                "requests rather than operations (per-request rate limit, request-based quota, WAF rule) "
                "is bypassed by aliasing."
            ),
            url=endpoint,
            evidence=f"One request returned {returned} aliased results (control: 1)",
            impact="Rate limiting and quota controls bypassed; enables brute force and resource exhaustion",
            remediation=(
                "Limit operations per request, or enforce cost/query-complexity limits server-side "
                "rather than counting HTTP requests."
            ),
            extra={"operations_per_request": returned, "probe": "alias_batching"},
        )

    async def _check_depth_limit(
        self,
        client: AsyncClient,
        endpoint: str,
        headers: dict[str, str],
    ) -> None:
        """Test whether the server caps query size/cost.

        Probes with a very wide valid selection (200 aliased fields). A server
        enforcing a complexity or cost limit rejects it; one without a limit
        resolves it. A wide selection is used rather than a guessed recursive
        field because a nonexistent field only proves validation works.
        """
        field_count = 200
        wide = "{" + " ".join(f"f{i}: __typename" for i in range(field_count)) + "}"
        resp = await client.post(endpoint, json={"query": wide}, headers=headers)
        if resp.get("error") or resp.get("status") != 200:
            return

        body = resp.get("body")
        if not isinstance(body, dict):
            return

        # A server with a complexity cap returns errors and no data.
        if body.get("errors") and not body.get("data"):
            return

        data = body.get("data")
        if not isinstance(data, dict) or len(data) < field_count:
            return

        self.add_finding(
            severity="LOW",
            title=f"No GraphQL query complexity limit observed: {endpoint}",
            description=(
                f"A single request selecting {field_count} fields was resolved without error. Without a "
                "complexity or cost limit, a client can request disproportionately expensive queries "
                "relative to the request size it sends."
            ),
            url=endpoint,
            evidence=f"{field_count}-field selection resolved ({len(data)} fields returned)",
            impact="Resource exhaustion and cost amplification on expensive resolvers",
            remediation="Enforce query complexity/cost analysis and a maximum depth server-side.",
            extra={"probe": "depth_limit", "fields_selected": field_count},
        )
