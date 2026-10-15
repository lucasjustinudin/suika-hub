"""Tests for core.decision_engine – module recommendation / plugin logic.

The project uses a decision engine rather than a traditional plugin registry;
this file tests the scoring, recommendation, and analysis logic.
"""

from suika_hub.core.decision_engine import (
    MODULE_EFFECTIVENESS,
    MODULE_TIME_ESTIMATE,
    VULN_PRIORITY,
    DecisionEngine,
    TargetProfile,
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

    def test_every_registered_module_is_scored(self):
        """A module missing from MODULE_EFFECTIVENESS can never be recommended.

        Asserting the set of shipped modules rather than a hardcoded count: a
        new module must be added to the scoring table, and a bare number would
        just be edited to match instead of catching the omission.
        """
        from suika_hub.modules import (
            APIFuzzer,
            AuthBypassScanner,
            FileUploadScanner,
            GraphQLScanner,
            IDORScanner,
            JWTScanner,
            ReconScanner,
            SSRFScanner,
        )

        shipped = {
            cls.name
            for cls in (
                APIFuzzer,
                AuthBypassScanner,
                FileUploadScanner,
                GraphQLScanner,
                IDORScanner,
                JWTScanner,
                ReconScanner,
                SSRFScanner,
            )
        }
        assert shipped == set(MODULE_EFFECTIVENESS), (
            f"modules missing from MODULE_EFFECTIVENESS: {shipped - set(MODULE_EFFECTIVENESS)}; "
            f"stale entries: {set(MODULE_EFFECTIVENESS) - shipped}"
        )

    def test_every_module_has_a_time_estimate(self):
        missing = set(MODULE_EFFECTIVENESS) - set(MODULE_TIME_ESTIMATE)
        assert not missing, f"modules without a time estimate: {missing}"

    def test_module_time_estimates(self):
        for _name, t in MODULE_TIME_ESTIMATE.items():
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


class TestRecommendForProfile:
    def test_returns_list(self):
        engine = DecisionEngine()
        recs = engine.recommend_for_profile("nodejs")
        assert isinstance(recs, list)
        assert len(recs) > 0

    def test_has_notes_for_key_modules(self):
        engine = DecisionEngine()
        recs = engine.recommend_for_profile("nodejs")
        modules_with_notes = {r["module"] for r in recs if "notes" in r}
        assert "api_fuzzer" in modules_with_notes

    def test_technology_matched_modules_rank_highly(self):
        """Regression: a module targeting the detected tech must not score zero.

        The vuln-priority list is derived from the stack and shares no key with
        the module's effectiveness table for some profiles, so a pure
        multiplier left graphql/jwt at 0.00 for the exact profile that detects
        GraphQL/JWT. A relevance floor keeps them in contention.
        """
        engine = DecisionEngine()
        recs = engine.recommend_for_profile("spa")
        by_module = {r["module"]: r["score"] for r in recs}
        assert by_module["graphql_scanner"] > 0, "graphql scored zero on a graphql profile"
        assert by_module["jwt_scanner"] > 0, "jwt scored zero on a jwt profile"

        # And they must actually rank near the top, not merely be non-zero.
        ranked = [r["module"] for r in recs]
        assert ranked.index("graphql_scanner") < 3
        assert ranked.index("jwt_scanner") < 3

    def test_profile_notes_are_attached(self):
        engine = DecisionEngine()
        recs = engine.recommend_for_profile("spa")
        noted = {r["module"] for r in recs if "notes" in r}
        assert "graphql_scanner" in noted
        assert "jwt_scanner" in noted

    def test_unknown_profile_returns_empty(self):
        """An unknown name must be distinguishable from a profile with no modules."""
        assert DecisionEngine().recommend_for_profile("no-such-profile") == []

    def test_profile_module_present(self):
        engine = DecisionEngine()
        recs = engine.recommend_for_profile("nodejs")
        module_names = [r["module"] for r in recs]
        assert "api_fuzzer" in module_names


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
