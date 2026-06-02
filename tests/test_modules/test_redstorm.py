"""Tests for modules.redstorm – RedStormScanner."""
import pytest
from modules.redstorm import RedStormScanner
from tests.conftest import MockAsyncClient, make_response


@pytest.fixture
def scanner():
    s = RedStormScanner()
    s.reset()
    return s


class TestRedStormInit:
    def test_name(self, scanner):
        assert scanner.name == "redstorm_scanner"

    def test_has_endpoints(self, scanner):
        assert len(scanner.ENDPOINTS) > 0

    def test_has_slugs(self, scanner):
        assert "rswebapppltf" in scanner.PROGRAM_SLUGS
        assert "admin" in scanner.PROGRAM_SLUGS


class TestFindSensitiveFields:
    def test_detects_email(self, scanner):
        result = scanner._find_sensitive_fields({"email": "a@b.com", "name": "Alice"})
        assert "email" in result

    def test_detects_nested(self, scanner):
        data = {"user": {"profile": {"phone": "123"}}}
        result = scanner._find_sensitive_fields(data)
        assert any("phone" in r for r in result)

    def test_no_sensitive(self, scanner):
        result = scanner._find_sensitive_fields({"name": "Alice", "age": 30})
        assert result == []

    def test_list_data(self, scanner):
        data = [{"token": "abc"}, {"name": "ok"}]
        result = scanner._find_sensitive_fields(data)
        assert any("token" in r for r in result)

    def test_empty_data(self, scanner):
        assert scanner._find_sensitive_fields({}) == []


class TestStageLeaderboard:
    @pytest.mark.asyncio
    async def test_leaderboard_with_usernames(self, scanner):
        resp = make_response(body={
            "leaderboard": [
                {"username": "alice", "id": 1},
                {"username": "bob", "id": 2},
            ]
        })
        client = MockAsyncClient(responses={"leaderboard": resp})
        usernames = await scanner._stage_leaderboard("https://example.com", client)
        assert "alice" in usernames
        assert "bob" in usernames

    @pytest.mark.asyncio
    async def test_leaderboard_with_sensitive_data(self, scanner):
        resp = make_response(body={
            "leaderboard": [
                {"username": "alice", "email": "a@b.com", "is_admin": True},
            ]
        })
        client = MockAsyncClient(responses={"leaderboard": resp})
        await scanner._stage_leaderboard("https://example.com", client)
        findings = [f for f in scanner.findings if "sensitive" in f.get("title", "").lower()]
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_leaderboard_cloudflare(self, scanner):
        resp = make_response(status=403, error="cloudflare_challenge")
        client = MockAsyncClient(responses={"leaderboard": resp})
        usernames = await scanner._stage_leaderboard("https://example.com", client)
        assert usernames == []

    @pytest.mark.asyncio
    async def test_leaderboard_non_200(self, scanner):
        resp = make_response(status=401)
        client = MockAsyncClient(responses={"leaderboard": resp})
        usernames = await scanner._stage_leaderboard("https://example.com", client)
        assert usernames == []

    @pytest.mark.asyncio
    async def test_leaderboard_non_dict_body(self, scanner):
        resp = make_response(body="plain text")
        client = MockAsyncClient(responses={"leaderboard": resp})
        usernames = await scanner._stage_leaderboard("https://example.com", client)
        assert usernames == []

    @pytest.mark.asyncio
    async def test_leaderboard_data_key(self, scanner):
        resp = make_response(body={
            "data": [
                {"user_id": "u1"},
                {"_id": "u2"},
            ]
        })
        client = MockAsyncClient(responses={"leaderboard": resp})
        usernames = await scanner._stage_leaderboard("https://example.com", client)
        assert "u1" in usernames
        assert "u2" in usernames


class TestStageIDOR:
    @pytest.mark.asyncio
    async def test_idor_finding_on_200_with_data(self, scanner):
        responses = {}
        for pattern in ["/api/researcher/submission/", "/api/researcher/profile/",
                        "/api/researcher/user/", "/api/researcher/submissions/",
                        "/api/researcher/report/"]:
            responses[pattern] = make_response(body={"data": {"secret": "value"}})

        client = MockAsyncClient(responses=responses)
        await scanner._stage_idor("https://example.com", client, ["user1"])
        idor_findings = [f for f in scanner.findings if "IDOR" in f.get("title", "")]
        assert len(idor_findings) > 0


class TestStagePrograms:
    @pytest.mark.asyncio
    async def test_programs_accessible(self, scanner):
        resp = make_response(body={"name": "Test Program"})
        client = MockAsyncClient(responses={"program/": resp})
        await scanner._stage_programs("https://example.com", client)
        findings = [f for f in scanner.findings if "program" in f.get("title", "").lower() or "Program" in f.get("title", "")]
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_private_program_detected(self, scanner):
        resp = make_response(body={"name": "Internal", "is_private": True})
        client = MockAsyncClient(responses={"program/": resp})
        await scanner._stage_programs("https://example.com", client)
        private_findings = [f for f in scanner.findings if "private" in f.get("title", "").lower() or "Private" in f.get("title", "")]
        assert len(private_findings) > 0


class TestStageEndpoints:
    @pytest.mark.asyncio
    async def test_admin_endpoint_privilege_escalation(self, scanner):
        responses = {}
        for ep in scanner.ENDPOINTS:
            if "/admin/" in ep or "/customer/" in ep:
                responses[ep] = make_response(status=200, body={"data": "admin"})
            else:
                responses[ep] = make_response(status=200, body={"data": "ok"})
        client = MockAsyncClient(responses=responses)
        await scanner._stage_endpoints("https://example.com", client)
        priv_findings = [f for f in scanner.findings if "escalation" in f.get("title", "").lower() or "Privilege" in f.get("title", "")]
        assert len(priv_findings) > 0

    @pytest.mark.asyncio
    async def test_502_errors_noted(self, scanner):
        responses = {}
        for ep in scanner.ENDPOINTS:
            responses[ep] = make_response(status=502)
        client = MockAsyncClient(responses=responses)
        await scanner._stage_endpoints("https://example.com", client)
        # The finding title is "Server errors on N endpoints"
        info_findings = [f for f in scanner.findings if "Server errors" in f.get("title", "")]
        assert len(info_findings) > 0


class TestExecute:
    @pytest.mark.asyncio
    async def test_execute_runs_all_stages(self, scanner):
        client = MockAsyncClient(default=make_response(status=404))
        findings = await scanner.execute("https://example.com", client, {})
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_execute_with_custom_target(self, scanner):
        client = MockAsyncClient(default=make_response(status=404))
        findings = await scanner.execute("https://custom.target.com", client, {})
        assert isinstance(findings, list)
