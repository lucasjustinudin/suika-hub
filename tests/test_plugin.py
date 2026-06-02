"""Tests for core.decision_engine – module recommendation / plugin logic.

The project uses a decision engine rather than a traditional plugin registry;
this file tests the scoring, recommendation, and analysis logic.
"""
import pytest
from core.decision_engine import (
    DecisionEngine,
    TargetProfile,
    VULN_PRIORITY,
    MODULE_EFFECTIVENESS,
    MODULE_TIME_ESTIMATE,
)


class TestTargetProfile:
    def test_defaults(self):
        p = TargetProfile(domain="example.com")
        assert p.domain == "example.com"
        assert p.stack == []
        assert p.frameworks == []
        assert p.database == ""
        assert p.has_upload is False
        assert p.has_websocket is False

    def test_full_profile(self):
        p = TargetProfile(
            domain="app.com",
            stack=["python"],
            frameworks=["django"],
            database="postgresql",
            auth_type="jwt",
            waf="cloudflare",
            api_style="rest",
            endpoints_count=50,
            has_upload=True,
            has_websocket=True,
        )
        assert p.stack == ["python"]
        assert p.has_upload is True


class TestConstants:
    def test_vuln_priority_keys(self):
        assert "nodejs" in VULN_PRIORITY
        assert "python" in VULN_PRIORITY
        assert "default" in VULN_PRIORITY

    def test_module_effectiveness_keys(self):
        assert "idor_scanner" in MODULE_EFFECTIVENESS
        assert "api_fuzzer" in MODULE_EFFECTIVENESS
        assert len(MODULE_EFFECTIVENESS) == 7

    def test_module_time_estimates(self):
        for name, t in MODULE_TIME_ESTIMATE.items():
            assert isinstance(t, int)
            assert t > 0


class TestRecommendModules:
    def test_recommend_returns_list(self):
        engine = DecisionEngine()
        profile = TargetProfile(domain="test.com")
        recs = engine.recommend_modules(profile)
        assert isinstance(recs, list)
        assert len(recs) > 0

    def test_recommend_sorted_by_score(self):
        engine = DecisionEngine()
        profile = TargetProfile(domain="test.com")
        recs = engine.recommend_modules(profile)
        scores = [r["score"] for r in recs]
        assert scores == sorted(scores, reverse=True)

    def test_recommend_respects_time_budget(self):
        engine = DecisionEngine()
        profile = TargetProfile(domain="test.com")
        recs = engine.recommend_modules(profile, time_budget=50)
        total_time = sum(r["time_estimate"] for r in recs)
        assert total_time <= 50

    def test_recommend_infinite_budget(self):
        engine = DecisionEngine()
        profile = TargetProfile(domain="test.com")
        recs = engine.recommend_modules(profile, time_budget=99999)
        assert len(recs) == len(MODULE_TIME_ESTIMATE)

    def test_recommend_has_required_fields(self):
        engine = DecisionEngine()
        recs = engine.recommend_modules(TargetProfile(domain="test.com"))
        for r in recs:
            assert "module" in r
            assert "score" in r
            assert "time_estimate" in r
            assert "reason" in r

    def test_nodejs_profile_boosts_nosql(self):
        engine = DecisionEngine()
        profile = TargetProfile(domain="test.com", stack=["nodejs"], database="mongodb")
        recs = engine.recommend_modules(profile)
        api_rec = next(r for r in recs if r["module"] == "api_fuzzer")
        # MongoDB + nodejs should boost api_fuzzer
        profile_default = TargetProfile(domain="test.com")
        recs_default = engine.recommend_modules(profile_default)
        api_default = next(r for r in recs_default if r["module"] == "api_fuzzer")
        assert api_rec["score"] >= api_default["score"]

    def test_upload_detected_boosts_upload_scanner(self):
        engine = DecisionEngine()
        # Use large budget so all modules are included
        profile_with = TargetProfile(domain="test.com", has_upload=True)
        profile_without = TargetProfile(domain="test.com", has_upload=False)
        recs_with = engine.recommend_modules(profile_with, time_budget=9999)
        recs_without = engine.recommend_modules(profile_without, time_budget=9999)
        upload_with = next(r for r in recs_with if r["module"] == "upload_scanner")
        upload_without = next(r for r in recs_without if r["module"] == "upload_scanner")
        assert upload_with["score"] > upload_without["score"]


class TestRecommendForRedstorm:
    def test_returns_list(self):
        engine = DecisionEngine()
        recs = engine.recommend_for_redstorm()
        assert isinstance(recs, list)
        assert len(recs) > 0

    def test_has_notes_for_key_modules(self):
        engine = DecisionEngine()
        recs = engine.recommend_for_redstorm()
        modules_with_notes = {r["module"] for r in recs if "notes" in r}
        assert "redstorm_scanner" in modules_with_notes or "api_fuzzer" in modules_with_notes

    def test_redstorm_module_present(self):
        engine = DecisionEngine()
        recs = engine.recommend_for_redstorm()
        module_names = [r["module"] for r in recs]
        assert "redstorm_scanner" in module_names


class TestAnalyzeFindings:
    def test_empty_findings(self):
        engine = DecisionEngine()
        result = engine.analyze_findings([])
        assert "next_steps" in result
        assert len(result["next_steps"]) > 0

    def test_critical_findings(self, sample_findings):
        engine = DecisionEngine()
        result = engine.analyze_findings(sample_findings)
        assert result["total_findings"] == 5
        assert result["severity_breakdown"]["CRITICAL"] == 1
        assert any("CRITICAL" in s for s in result["next_steps"])

    def test_chain_detection(self):
        engine = DecisionEngine()
        findings = [
            {"severity": "HIGH", "title": "IDOR in /api/user/{id}"},
            {"severity": "LOW", "title": "User enumeration via leaderboard"},
        ]
        result = engine.analyze_findings(findings)
        assert result["chain_potential"] is True
        assert any("CHAIN" in s for s in result["next_steps"])

    def test_no_chain_without_both(self):
        engine = DecisionEngine()
        findings = [{"severity": "HIGH", "title": "IDOR in /api/user/{id}"}]
        result = engine.analyze_findings(findings)
        assert result["chain_potential"] is False
