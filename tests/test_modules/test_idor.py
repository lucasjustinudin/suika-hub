"""Tests for modules.idor – IDORScanner."""
import pytest
from suika_hub.modules.idor import IDORScanner
from tests.conftest import MockAsyncClient, make_response


@pytest.fixture
def scanner():
    s = IDORScanner()
    s.reset()
    return s


class TestIDORInit:
    def test_name(self, scanner):
        assert scanner.name == "idor_scanner"

    def test_has_patterns(self, scanner):
        assert len(scanner.DEFAULT_PATTERNS) > 0
        assert any("{id}" in p for p in scanner.DEFAULT_PATTERNS)

    def test_has_ids(self, scanner):
        assert "1" in scanner.DEFAULT_IDS
        assert "admin" in scanner.DEFAULT_IDS


class TestOwnDataDetection:
    def test_same_user_detected(self, scanner):
        body = {"id": 42, "name": "Alice"}
        baseline = {"id": 42, "name": "Alice"}
        assert scanner._is_own_data(body, baseline) is True

    def test_different_user(self, scanner):
        body = {"id": 99, "name": "Bob"}
        baseline = {"id": 42, "name": "Alice"}
        assert scanner._is_own_data(body, baseline) is False

    def test_empty_baseline(self, scanner):
        body = {"id": 99}
        assert scanner._is_own_data(body, {}) is False

    def test_non_dict_body(self, scanner):
        assert scanner._is_own_data("string body", {"id": 1}) is False

    def test_underscore_id(self, scanner):
        body = {"_id": "abc123"}
        baseline = {"_id": "abc123"}
        assert scanner._is_own_data(body, baseline) is True

    def test_user_id_key(self, scanner):
        body = {"user_id": 5}
        baseline = {"user_id": 5}
        assert scanner._is_own_data(body, baseline) is True


class TestMeaningfulData:
    def test_dict_with_data(self, scanner):
        assert scanner._has_meaningful_data({"key1": "v1", "key2": "v2"}) is True

    def test_dict_error_response(self, scanner):
        assert scanner._has_meaningful_data({"error": "not found"}) is False

    def test_dict_not_found_message(self, scanner):
        assert scanner._has_meaningful_data({"message": "not found"}) is False

    def test_single_key_dict(self, scanner):
        assert scanner._has_meaningful_data({"count": 0}) is False

    def test_long_string(self, scanner):
        assert scanner._has_meaningful_data("A" * 100) is True

    def test_short_string(self, scanner):
        assert scanner._has_meaningful_data("short") is False

    def test_string_not_found(self, scanner):
        assert scanner._has_meaningful_data("item not found in database") is False

    def test_int_value(self, scanner):
        assert scanner._has_meaningful_data(42) is False


class TestDetectSensitive:
    def test_detects_email(self, scanner):
        result = scanner._detect_sensitive({"email": "a@b.com"})
        assert "email" in result

    def test_detects_token(self, scanner):
        result = scanner._detect_sensitive({"token": "secret"})
        assert "token" in result

    def test_no_sensitive(self, scanner):
        result = scanner._detect_sensitive({"name": "Alice"})
        assert result == []

    def test_multiple_sensitive(self, scanner):
        result = scanner._detect_sensitive({"email": "a@b.com", "phone": "123", "name": "A"})
        assert "email" in result
        assert "phone" in result


class TestGetBaseline:
    @pytest.mark.asyncio
    async def test_baseline_success(self, scanner):
        resp = make_response(body={"id": 1, "name": "me"})
        client = MockAsyncClient(responses={"/api/user/me": resp})
        baseline = await scanner._get_baseline("https://example.com", client, {})
        assert baseline == {"id": 1, "name": "me"}

    @pytest.mark.asyncio
    async def test_baseline_failure(self, scanner):
        client = MockAsyncClient(default=make_response(status=401))
        baseline = await scanner._get_baseline("https://example.com", client, {})
        assert baseline == {}

    @pytest.mark.asyncio
    async def test_baseline_non_dict_body(self, scanner):
        resp = make_response(body="not json")
        client = MockAsyncClient(responses={"/api/user/me": resp})
        baseline = await scanner._get_baseline("https://example.com", client, {})
        assert baseline == {}


class TestIDORExecute:
    @pytest.mark.asyncio
    async def test_execute_finds_idor(self, scanner):
        # Baseline returns user 1, other endpoints return different user data
        baseline_resp = make_response(body={"id": 1, "name": "me"})
        idor_resp = make_response(body={"id": 2, "name": "victim", "email": "v@ctim.com"})

        responses = {"/api/user/me": baseline_resp}
        for pattern in scanner.DEFAULT_PATTERNS:
            responses[pattern.format(id="2")] = idor_resp

        client = MockAsyncClient(responses=responses, default=make_response(status=404))
        findings = await scanner.execute("https://example.com", client, {})
        idor = [f for f in findings if "IDOR" in f.get("title", "")]
        assert len(idor) > 0

    @pytest.mark.asyncio
    async def test_execute_no_finding_for_own_data(self, scanner):
        baseline_resp = make_response(body={"id": 1, "name": "me"})
        own_resp = make_response(body={"id": 1, "name": "me"})

        responses = {"/api/user/me": baseline_resp}
        for pattern in scanner.DEFAULT_PATTERNS:
            responses[pattern.format(id="1")] = own_resp

        client = MockAsyncClient(responses=responses, default=make_response(status=404))
        findings = await scanner.execute("https://example.com", client, {})
        idor = [f for f in findings if "IDOR" in f.get("title", "")]
        assert len(idor) == 0
