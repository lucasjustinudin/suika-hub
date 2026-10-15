"""Tests for suika_hub.modules.graphql_scanner -- GraphQL-specific checks."""

import pytest

from suika_hub.modules.graphql_scanner import COMMON_PATHS, INTROSPECTION_QUERY, GraphQLScanner


def gql_response(body, status=200):
    """Build a response dict shaped like a GraphQL reply."""
    return {"url": "x", "status": status, "body": body, "headers": {}, "error": None}


def make_schema(type_count: int):
    """Build an introspection payload with ``type_count`` types."""
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [{"name": f"Type{i}", "kind": "OBJECT"} for i in range(type_count)],
            }
        }
    }


class TestEndpointCandidates:
    def test_includes_common_paths(self):
        scanner = GraphQLScanner()
        urls = scanner._candidate_endpoints("https://example.com", {})
        assert "https://example.com/graphql" in urls

    def test_uses_configured_graphql_paths_first(self):
        scanner = GraphQLScanner()
        urls = scanner._candidate_endpoints("https://example.com", {"endpoints": ["/custom/gql"]})
        assert urls[0] == "https://example.com/custom/gql"

    def test_ignores_non_graphql_configured_paths(self):
        scanner = GraphQLScanner()
        urls = scanner._candidate_endpoints("https://example.com", {"endpoints": ["/api/users"]})
        assert "https://example.com/api/users" not in urls

    def test_strips_trailing_slash(self):
        scanner = GraphQLScanner()
        urls = scanner._candidate_endpoints("https://example.com/", {})
        assert not any("//graphql" in u for u in urls)

    def test_all_common_paths_present(self):
        scanner = GraphQLScanner()
        urls = scanner._candidate_endpoints("https://example.com", {})
        for path in COMMON_PATHS:
            assert f"https://example.com{path}" in urls


class TestLooksLikeGraphql:
    def test_data_key_means_graphql(self):
        assert GraphQLScanner()._looks_like_graphql(gql_response({"data": {"__typename": "Query"}})) is True

    def test_errors_key_means_graphql(self):
        assert GraphQLScanner()._looks_like_graphql(gql_response({"errors": [{"message": "bad"}]})) is True

    def test_html_body_is_not_graphql(self):
        assert GraphQLScanner()._looks_like_graphql(gql_response("<html>404</html>")) is False

    def test_404_is_not_graphql(self):
        assert GraphQLScanner()._looks_like_graphql(gql_response({"data": {}}, status=404)) is False

    def test_error_dict_is_not_graphql(self):
        assert GraphQLScanner()._looks_like_graphql({"status": 200, "error": "timeout"}) is False

    def test_empty_dict_is_not_graphql(self):
        assert GraphQLScanner()._looks_like_graphql(gql_response({})) is False


class TestIntrospectionDetection:
    @pytest.mark.asyncio
    async def test_reports_full_schema_exposure(self, mock_client_factory):
        """A schema with many types must produce a MEDIUM finding."""
        client = mock_client_factory(default=gql_response(make_schema(30)))
        findings = await GraphQLScanner().execute(
            "https://example.com",
            client,
            {"graphql_endpoints": ["https://example.com/graphql"]},
        )
        titles = [f["title"] for f in findings]
        assert any("introspection enabled" in t for t in titles)

    @pytest.mark.asyncio
    async def test_ignores_tiny_introspection_result(self, mock_client_factory):
        """Only built-in types returned means introspection is effectively closed."""
        client = mock_client_factory(default=gql_response(make_schema(2)))
        findings = await GraphQLScanner().execute(
            "https://example.com",
            client,
            {"graphql_endpoints": ["https://example.com/graphql"]},
        )
        assert not any("introspection enabled" in f["title"] for f in findings)

    @pytest.mark.asyncio
    async def test_no_finding_when_introspection_disabled(self, mock_client_factory):
        client = mock_client_factory(default=gql_response({"errors": [{"message": "Introspection is not allowed"}]}))
        findings = await GraphQLScanner().execute(
            "https://example.com",
            client,
            {"graphql_endpoints": ["https://example.com/graphql"]},
        )
        assert not any("introspection" in f["title"] for f in findings)


class TestAliasBatching:
    @pytest.mark.asyncio
    async def test_detects_alias_batch_acceptance(self, mock_client_factory):
        """A server resolving 25 aliases in one request must be reported."""
        batch = {"data": {f"q{i}": "Query" for i in range(25)}}
        client = mock_client_factory(default=gql_response(batch))
        findings = await GraphQLScanner().execute(
            "https://example.com",
            client,
            {"graphql_endpoints": ["https://example.com/graphql"]},
        )
        assert any("alias batching" in f["title"] for f in findings)

    @pytest.mark.asyncio
    async def test_partial_batch_not_reported(self, mock_client_factory):
        """Fewer aliases resolved than sent means a limit is in place."""
        batch = {"data": {f"q{i}": "Query" for i in range(3)}}
        client = mock_client_factory(default=gql_response(batch))
        findings = await GraphQLScanner().execute(
            "https://example.com",
            client,
            {"graphql_endpoints": ["https://example.com/graphql"]},
        )
        assert not any("alias batching" in f["title"] for f in findings)

    @pytest.mark.asyncio
    async def test_non_dict_data_not_reported(self, mock_client_factory):
        client = mock_client_factory(default=gql_response({"data": "unexpected"}))
        findings = await GraphQLScanner().execute(
            "https://example.com",
            client,
            {"graphql_endpoints": ["https://example.com/graphql"]},
        )
        assert not any("alias batching" in f["title"] for f in findings)


class TestComplexityLimit:
    @pytest.mark.asyncio
    async def test_reports_missing_complexity_limit(self, mock_client_factory):
        wide = {"data": {f"f{i}": "Query" for i in range(200)}}
        client = mock_client_factory(default=gql_response(wide))
        findings = await GraphQLScanner().execute(
            "https://example.com",
            client,
            {"graphql_endpoints": ["https://example.com/graphql"]},
        )
        assert any("complexity limit" in f["title"] for f in findings)

    @pytest.mark.asyncio
    async def test_errors_without_data_means_limited(self, mock_client_factory):
        client = mock_client_factory(default=gql_response({"errors": [{"message": "query too complex"}]}))
        findings = await GraphQLScanner().execute(
            "https://example.com",
            client,
            {"graphql_endpoints": ["https://example.com/graphql"]},
        )
        assert not any("complexity limit" in f["title"] for f in findings)


class TestNonGraphqlTarget:
    @pytest.mark.asyncio
    async def test_no_findings_on_html_site(self, mock_client_factory):
        client = mock_client_factory(default=gql_response("<html>Not found</html>", status=404))
        findings = await GraphQLScanner().execute("https://example.com", client, {})
        assert findings == []


class TestFindingShape:
    @pytest.mark.asyncio
    async def test_findings_carry_required_fields(self, mock_client_factory):
        client = mock_client_factory(default=gql_response(make_schema(30)))
        findings = await GraphQLScanner().execute(
            "https://example.com",
            client,
            {"graphql_endpoints": ["https://example.com/graphql"]},
        )
        assert findings
        for f in findings:
            for field in ("severity", "title", "description", "evidence", "impact", "remediation"):
                assert f.get(field), f"missing {field}"

    def test_introspection_query_targets_schema(self):
        assert "__schema" in INTROSPECTION_QUERY
