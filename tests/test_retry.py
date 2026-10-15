"""Tests for suika_hub.core.retry -- RetryPolicy and Retry-After parsing."""

import datetime as dt

import pytest

from suika_hub.core.retry import RetryPolicy, parse_retry_after


class TestParseRetryAfter:
    def test_absent_header_returns_none(self):
        assert parse_retry_after({}) is None

    def test_delta_seconds(self):
        assert parse_retry_after({"Retry-After": "120"}) == 120.0

    def test_case_insensitive_header_name(self):
        assert parse_retry_after({"retry-after": "5"}) == 5.0

    def test_negative_clamped_to_zero(self):
        assert parse_retry_after({"Retry-After": "-10"}) == 0.0

    def test_http_date_in_future(self):
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=90)
        value = parse_retry_after({"Retry-After": future.strftime("%a, %d %b %Y %H:%M:%S GMT")})
        assert value is not None
        assert 80 <= value <= 100

    def test_http_date_in_past_clamped(self):
        past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=90)
        assert parse_retry_after({"Retry-After": past.strftime("%a, %d %b %Y %H:%M:%S GMT")}) == 0.0

    def test_garbage_returns_none(self):
        assert parse_retry_after({"Retry-After": "soon-ish"}) is None

    def test_empty_value_returns_none(self):
        assert parse_retry_after({"Retry-After": ""}) is None


class TestShouldRetry:
    def test_retries_rate_limit(self):
        assert RetryPolicy().should_retry({"status": 429, "error": None}) is True

    @pytest.mark.parametrize("status", [500, 502, 503, 504, 520, 521, 522, 523, 524, 408, 425])
    def test_retries_transient_server_errors(self, status):
        assert RetryPolicy().should_retry({"status": status, "error": None}) is True

    @pytest.mark.parametrize("status", [200, 201, 204, 301, 400, 401, 403, 404, 422])
    def test_does_not_retry_deterministic_responses(self, status):
        assert RetryPolicy().should_retry({"status": status, "error": None}) is False

    def test_retries_timeout(self):
        assert RetryPolicy().should_retry({"status": 0, "error": "timeout"}) is True

    def test_retries_connection_error(self):
        assert RetryPolicy().should_retry({"status": 0, "error": "connection_error"}) is True

    def test_does_not_retry_waf_block(self):
        """A WAF block is a policy decision; retrying just burns the IP."""
        assert RetryPolicy().should_retry({"status": 403, "error": "waf_blocked"}) is False

    def test_zero_status_without_error_is_retried(self):
        assert RetryPolicy().should_retry({"status": 0}) is True


class TestDelayFor:
    def test_honours_retry_after(self):
        policy = RetryPolicy(base_delay=1.0, jitter=False)
        assert policy.delay_for(1, {"status": 429, "headers": {"Retry-After": "7"}}) == 7.0

    def test_retry_after_capped_by_max_delay(self):
        policy = RetryPolicy(max_delay=10.0)
        assert policy.delay_for(1, {"status": 429, "headers": {"Retry-After": "600"}}) == 10.0

    def test_exponential_growth_without_jitter(self):
        policy = RetryPolicy(base_delay=1.0, max_delay=100.0, jitter=False)
        assert policy.delay_for(1) == 1.0
        assert policy.delay_for(2) == 2.0
        assert policy.delay_for(3) == 4.0

    def test_backoff_capped(self):
        policy = RetryPolicy(base_delay=1.0, max_delay=5.0, jitter=False)
        assert policy.delay_for(10) == 5.0

    def test_jitter_stays_within_cap(self):
        policy = RetryPolicy(base_delay=2.0, max_delay=60.0, jitter=True)
        for attempt in range(1, 6):
            assert 0 <= policy.delay_for(attempt) <= min(2.0 * (2 ** (attempt - 1)), 60.0)

    def test_retry_after_ignored_when_disabled(self):
        policy = RetryPolicy(base_delay=1.0, jitter=False, respect_retry_after=False)
        assert policy.delay_for(1, {"status": 429, "headers": {"Retry-After": "99"}}) == 1.0

    def test_missing_headers_falls_back_to_backoff(self):
        policy = RetryPolicy(base_delay=1.0, jitter=False)
        assert policy.delay_for(2, {"status": 503}) == 2.0
