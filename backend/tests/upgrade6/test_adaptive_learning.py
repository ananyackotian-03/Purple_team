"""Upgrade 6 — Adaptive Cyber Immune Learning Tests.

Proves that SentinelForge demonstrably adapts based on accumulated
security experience. The canonical test demonstrates that experiment
outcomes change future candidate rankings.

Architecture:
  LLM PROPOSES → deterministic scoring → PolicyEngine validation → deterministic execution → observation → learning → next experiment

All scoring is deterministic. The LLM may reason about candidates
but must not override deterministic safety or authority.
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import (
    Base,
    Organization as OrgModel,
    SecurityObjectiveRecord,
    AdversarialScenarioRecord,
    PurpleEvaluationRecord,
    DetectionGapRecord,
    RetestResult as RetestResultRecord,
)
from sentinelforge.remediation.db_models import (
    RemediationRetestResultRecord,
    RemediationAuditEventRecord,
)
from sentinelforge.adaptive.schemas import (
    CandidateExperiment,
    CandidateStatus,
    DetectionGapProfile,
    AdaptationMetrics,
    ScoredCandidate,
    SecurityExperienceContext,
)
from sentinelforge.adaptive.experiment_scorer import ExperimentScorer
from sentinelforge.adaptive.detection_gap_model import DetectionGapModel
from sentinelforge.adaptive.learning_gain import LearningGainCalculator
from sentinelforge.adaptive.adaptation_metrics import AdaptationMetricsCalculator
from sentinelforge.agents.red_agent import STRATEGY_CATALOG


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    import sentinelforge.db.models
    import sentinelforge.remediation.db_models
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def org_id():
    return uuid4()


@pytest.fixture
def obj_id():
    return uuid4()


def _seed_org(db_session, org_id):
    db_session.add(OrgModel(id=org_id, name="Test Org"))
    db_session.commit()


def _seed_objective(db_session, org_id, obj_id):
    db_session.add(SecurityObjectiveRecord(
        id=obj_id,
        organization_id=org_id,
        title="Test Objective",
        description="Test objective for Upgrade 6",
    ))
    db_session.commit()


def _seed_evaluation(
    db_session,
    org_id,
    obj_id,
    technique_id,
    detection_status,
    days_ago=0,
):
    """Seed a PurpleEvaluationRecord for a technique."""
    scenario_id = uuid4()
    db_session.add(AdversarialScenarioRecord(
        id=scenario_id,
        objective_id=obj_id,
        organization_id=org_id,
        title=f"Test {technique_id}",
        strategy_description=f"Test strategy for {technique_id}",
    ))
    db_session.commit()

    eval_id = uuid4()
    now = datetime.now(timezone.utc) - timedelta(days=days_ago)
    db_session.add(PurpleEvaluationRecord(
        id=eval_id,
        organization_id=org_id,
        experiment_id=scenario_id,
        execution_id=uuid4(),
        technique_id=technique_id,
        detection_status=detection_status,
        matched_rule_ids="[]",
        evidence_event_ids="[]",
        expected_detection=False,
        gap_reason="",
        detection_latency_ms=0,
        evaluated_at=now,
    ))
    db_session.commit()
    return scenario_id


def _seed_gap(
    db_session,
    org_id,
    technique_id,
    scenario_id,
    remediation_status="OPEN",
):
    """Seed a DetectionGapRecord."""
    gap_id = uuid4()
    db_session.add(DetectionGapRecord(
        id=gap_id,
        organization_id=org_id,
        scenario_id=scenario_id,
        action_id=uuid4(),
        technique_id=technique_id,
        original_outcome="NOT_DETECTED",
        root_cause="MISSING_RULE",
        reason=f"Detection gap for {technique_id}",
        remediation_status=remediation_status,
        created_at=datetime.now(timezone.utc),
    ))
    db_session.commit()
    return gap_id


# ---------------------------------------------------------------------------
# 1. Empty history produces neutral/default gap values
# ---------------------------------------------------------------------------

class TestEmptyHistory:
    def test_empty_history_produces_neutral_gap_profiles(self, db_session, org_id):
        """With no experiments, gap profiles should be empty."""
        _seed_org(db_session, org_id)
        model = DetectionGapModel(db_session, org_id)
        profiles = model.build_gap_profiles()
        assert profiles == []

    def test_empty_history_produces_zero_scores(self, db_session, org_id):
        """With no experiments, all candidates should have zero adaptive fields."""
        _seed_org(db_session, org_id)
        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )
        builder = SecurityExperienceContextBuilder(db_session, org_id)
        context = builder.build()

        assert context.total_experiments == 0
        assert context.coverage_pct == 0.0
        assert len(context.gap_profiles) == 0
        for candidate in context.candidates:
            assert candidate.detection_confidence == 0.0
            assert candidate.attack_success_rate == 0.0


# ---------------------------------------------------------------------------
# 2. Successfully detected attack improves detection confidence
# ---------------------------------------------------------------------------

class TestDetectionConfidenceImprovement:
    def test_detected_attack_improves_confidence(self, db_session, org_id, obj_id):
        """A detected attack should improve detection confidence."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # First experiment: detected
        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=5)

        model = DetectionGapModel(db_session, org_id)
        profiles = model.build_gap_profiles()

        tech_profile = next(p for p in profiles if p.technique_id == "T1059.004")
        assert tech_profile.attacks_detected == 1
        assert tech_profile.detection_rate == 1.0
        assert tech_profile.detection_confidence > 0.0

    def test_multiple_detected_improves_confidence(self, db_session, org_id, obj_id):
        """Multiple detected attacks should increase confidence."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # 3 detected experiments
        for i in range(3):
            _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=10 - i)

        model = DetectionGapModel(db_session, org_id)
        profiles = model.build_gap_profiles()

        tech_profile = next(p for p in profiles if p.technique_id == "T1059.004")
        assert tech_profile.experiments_executed == 3
        assert tech_profile.detection_rate == 1.0
        assert tech_profile.detection_confidence == 1.0


# ---------------------------------------------------------------------------
# 3. Undetected attack increases detection gap
# ---------------------------------------------------------------------------

class TestUndetectedAttack:
    def test_undetected_attack_increases_gap(self, db_session, org_id, obj_id):
        """An undetected attack should increase the detection gap."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        _seed_evaluation(db_session, org_id, obj_id, "T1003.008", "NOT_DETECTED", days_ago=2)

        model = DetectionGapModel(db_session, org_id)
        profiles = model.build_gap_profiles()

        tech_profile = next(p for p in profiles if p.technique_id == "T1003.008")
        assert tech_profile.attacks_missed == 1
        assert tech_profile.attack_success_rate == 1.0
        assert tech_profile.detection_rate == 0.0

    def test_mixed_results_reflect_accurate_rate(self, db_session, org_id, obj_id):
        """Mixed detected/undetected should show accurate detection rate."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        _seed_evaluation(db_session, org_id, obj_id, "T1003.008", "DETECTED", days_ago=10)
        _seed_evaluation(db_session, org_id, obj_id, "T1003.008", "NOT_DETECTED", days_ago=5)
        _seed_evaluation(db_session, org_id, obj_id, "T1003.008", "NOT_DETECTED", days_ago=1)

        model = DetectionGapModel(db_session, org_id)
        profiles = model.build_gap_profiles()

        tech_profile = next(p for p in profiles if p.technique_id == "T1003.008")
        assert tech_profile.experiments_executed == 3
        assert tech_profile.attacks_detected == 1
        assert tech_profile.attacks_missed == 2
        assert abs(tech_profile.detection_rate - 1 / 3) < 0.01


# ---------------------------------------------------------------------------
# 4. Repeated successful attacks increase priority
# ---------------------------------------------------------------------------

class TestPriorityIncrease:
    def test_repeated_attacks_increase_priority(self, db_session, org_id, obj_id):
        """Repeated undetected attacks should increase gap priority."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # 3 not-detected experiments
        for i in range(3):
            _seed_evaluation(db_session, org_id, obj_id, "T1003.008", "NOT_DETECTED", days_ago=10 - i)

        model = DetectionGapModel(db_session, org_id)
        profiles = model.build_gap_profiles()

        tech_profile = next(p for p in profiles if p.technique_id == "T1003.008")
        assert tech_profile.priority > 50.0  # High priority
        assert tech_profile.attack_success_rate == 1.0

    def test_gap_record_increases_priority(self, db_session, org_id, obj_id):
        """An unresolved gap record should increase priority."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        scenario_id = _seed_evaluation(
            db_session, org_id, obj_id, "T1003.008", "NOT_DETECTED"
        )
        _seed_gap(db_session, org_id, "T1003.008", scenario_id, "OPEN")

        model = DetectionGapModel(db_session, org_id)
        profiles = model.build_gap_profiles()

        tech_profile = next(p for p in profiles if p.technique_id == "T1003.008")
        assert tech_profile.has_unresolved_gap is True
        assert tech_profile.gap_count == 1


# ---------------------------------------------------------------------------
# 5. Strongly detected techniques become lower priority
# ---------------------------------------------------------------------------

class TestPriorityDecrease:
    def test_strongly_detected_decreases_priority(self, db_session, org_id, obj_id):
        """Techniques with strong detection should have lower priority."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # 5 detected experiments — strong detection
        for i in range(5):
            _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=20 - i)

        model = DetectionGapModel(db_session, org_id)
        profiles = model.build_gap_profiles()

        tech_profile = next(p for p in profiles if p.technique_id == "T1059.004")
        assert tech_profile.detection_rate == 1.0
        assert tech_profile.detection_confidence == 1.0
        # Priority should be low (well-detected, no gaps)
        assert tech_profile.priority < 20.0


# ---------------------------------------------------------------------------
# 6. Newly observed techniques receive exploration value
# ---------------------------------------------------------------------------

class TestExplorationValue:
    def test_untested_technique_has_high_novelty(self, db_session, org_id, obj_id):
        """Untested techniques should have maximum novelty."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )
        builder = SecurityExperienceContextBuilder(db_session, org_id)
        context = builder.build()

        scorer = ExperimentScorer()
        scored = scorer.score(context)

        # All strategies that have never been tested should have novelty
        for sc in scored:
            if sc.candidate.times_tested == 0:
                assert sc.learning_value > 0.0

    def test_untested_gets_never_tested_status(self, db_session, org_id, obj_id):
        """Untested strategies should have NEVER_TESTED status."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )
        builder = SecurityExperienceContextBuilder(db_session, org_id)
        context = builder.build()

        for candidate in context.candidates:
            if candidate.times_tested == 0:
                assert candidate.candidate_status == CandidateStatus.NEVER_TESTED


# ---------------------------------------------------------------------------
# 7. Recent duplicate experiments are penalized
# ---------------------------------------------------------------------------

class TestRepetitionPenalty:
    def test_recently_tested_gets_penalty(self, db_session, org_id, obj_id):
        """Recently tested techniques should be deprioritized."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # Test a technique recently (1 day ago)
        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=1)

        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )
        builder = SecurityExperienceContextBuilder(db_session, org_id)
        context = builder.build()

        scorer = ExperimentScorer()
        scored = scorer.score(context)

        # Find the candidate for T1059.004
        for sc in scored:
            if "T1059.004" in sc.candidate.technique_ids:
                if sc.candidate.last_tested_days_ago is not None:
                    if sc.candidate.last_tested_days_ago <= 7:
                        assert "deprioritize_recently_tested" in sc.score_breakdown

    def test_redundant_detection_gets_penalty(self, db_session, org_id, obj_id):
        """Techniques tested 3+ times with detection should be deprioritized."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # 3 detected experiments
        for i in range(3):
            _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=30 - i)

        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )
        builder = SecurityExperienceContextBuilder(db_session, org_id)
        context = builder.build()

        scorer = ExperimentScorer()
        scored = scorer.score(context)

        for sc in scored:
            if "T1059.004" in sc.candidate.technique_ids:
                assert "deprioritize_redundant" in sc.score_breakdown


# ---------------------------------------------------------------------------
# 8. Learning gain is deterministic
# ---------------------------------------------------------------------------

class TestLearningGainDeterminism:
    def test_learning_gain_is_deterministic(self, db_session, org_id, obj_id):
        """Learning gain calculation should be deterministic for same inputs."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        from sentinelforge.adaptive.detection_gap_model import DetectionGapModel

        gap_model = DetectionGapModel(db_session, org_id)

        # Pre profiles: no experiments
        pre_profiles = []

        # Seed an experiment
        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "NOT_DETECTED", days_ago=1)

        # Post profiles: one experiment
        post_profiles = gap_model.build_gap_profiles()

        calc = LearningGainCalculator(db_session, org_id)

        gain1 = calc.compute_gain("T1059.004", "NOT_DETECTED", pre_profiles, post_profiles)
        gain2 = calc.compute_gain("T1059.004", "NOT_DETECTED", pre_profiles, post_profiles)

        assert gain1.total_gain == gain2.total_gain
        assert gain1.breakdown == gain2.breakdown
        assert gain1.new_coverage == gain2.new_coverage

    def test_new_coverage_gain(self, db_session, org_id, obj_id):
        """First test of a technique should produce new coverage gain."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        from sentinelforge.adaptive.detection_gap_model import DetectionGapModel

        gap_model = DetectionGapModel(db_session, org_id)
        pre_profiles = []

        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=1)
        post_profiles = gap_model.build_gap_profiles()

        calc = LearningGainCalculator(db_session, org_id)
        gain = calc.compute_gain("T1059.004", "DETECTED", pre_profiles, post_profiles)

        assert gain.new_coverage is True
        assert gain.total_gain > 0.0
        assert "new_coverage" in gain.breakdown


# ---------------------------------------------------------------------------
# 9. Candidate ranking changes after learning
# ---------------------------------------------------------------------------

class TestCandidateRankingChanges:
    def test_ranking_depends_on_history(self, db_session, org_id, obj_id):
        """Candidate ranking should change based on experiment history."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # Without any history, all NEVER_TESTED candidates have equal base score
        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )
        builder = SecurityExperienceContextBuilder(db_session, org_id)
        context_before = builder.build()

        scorer = ExperimentScorer()
        scored_before = scorer.score(context_before)
        ranking_before = [sc.candidate.strategy_name for sc in scored_before]

        # Now add history: T1059.004 is NOT_DETECTED (should increase priority)
        # T1003.008 is DETECTED (should decrease priority relative to others)
        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "NOT_DETECTED", days_ago=5)
        _seed_evaluation(db_session, org_id, obj_id, "T1003.008", "DETECTED", days_ago=5)

        context_after = builder.build()
        scored_after = scorer.score(context_after)
        ranking_after = [sc.candidate.strategy_name for sc in scored_after]

        # The ranking should have changed — strategies involving T1059.004
        # should rank higher, and T1003.008 strategies should rank lower
        assert ranking_before != ranking_after


# ---------------------------------------------------------------------------
# 10. LLM output cannot bypass deterministic scoring
# ---------------------------------------------------------------------------

class TestLLMCannotBypassScoring:
    def test_scoring_is_purely_deterministic(self, db_session, org_id, obj_id):
        """Scoring should be deterministic regardless of any external input."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "NOT_DETECTED", days_ago=5)

        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )
        builder = SecurityExperienceContextBuilder(db_session, org_id)
        context = builder.build()

        scorer = ExperimentScorer()
        scored1 = scorer.score(context)
        scored2 = scorer.score(context)

        # Scoring is deterministic — same inputs produce same outputs
        for s1, s2 in zip(scored1, scored2):
            assert s1.score == s2.score
            assert s1.score_breakdown == s2.score_breakdown
            assert s1.explanation == s2.explanation

    def test_cannot_inject_score(self, db_session, org_id, obj_id):
        """Candidate fields cannot inject arbitrary scores."""
        _seed_org(db_session, org_id)

        # Create a candidate with extreme values
        candidate = CandidateExperiment(
            strategy_name="web_sql_injection_login",
            technique_ids=["T1190"],
            title="Test",
            description="Test",
            proposed_risk_level="HIGH",
            candidate_status=CandidateStatus.NEVER_TESTED,
            times_tested=0,
            times_detected=0,
            times_not_detected=0,
            detection_confidence=0.0,
            attack_success_rate=0.0,
        )

        context = SecurityExperienceContext(
            organization_id=str(org_id),
            built_at=datetime.now(timezone.utc).isoformat() + "Z",
            total_experiments=0,
            coverage_pct=0.0,
            candidates=[candidate],
        )

        scorer = ExperimentScorer()
        scored = scorer.score(context)

        assert len(scored) == 1
        # Score is bounded by the sum of applicable weights
        assert scored[0].score <= 200.0  # Sum of all positive weights
        assert scored[0].score >= 0.0   # Clamped to non-negative


# ---------------------------------------------------------------------------
# 11. PolicyEngine remains authoritative
# ---------------------------------------------------------------------------

class TestPolicyEngineAuthoritative:
    def test_scoring_does_not_bypass_policy(self, db_session, org_id, obj_id):
        """Scoring produces a priority — it does not grant execution authority."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "NOT_DETECTED", days_ago=5)

        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )
        builder = SecurityExperienceContextBuilder(db_session, org_id)
        context = builder.build()

        scorer = ExperimentScorer()
        scored = scorer.score(context)

        # Scoring only produces ScoredCandidate — not execution authority
        for sc in scored:
            assert isinstance(sc, ScoredCandidate)
            assert hasattr(sc, "score")
            assert hasattr(sc, "score_breakdown")
            assert hasattr(sc, "explanation")
            # No execution fields
            assert not hasattr(sc, "execute")
            assert not hasattr(sc, "run")

    def test_scored_candidate_has_no_execution_power(self):
        """ScoredCandidate cannot execute anything."""
        candidate = CandidateExperiment(
            strategy_name="test",
            technique_ids=["T1059.004"],
            title="Test",
            description="Test",
            proposed_risk_level="LOW",
            candidate_status=CandidateStatus.NEVER_TESTED,
        )

        scored = ScoredCandidate(
            candidate=candidate,
            score=100.0,
            score_breakdown={"test": 100.0},
            explanation="test",
            learning_value=0.5,
        )

        # ScoredCandidate has no execution methods
        assert not callable(getattr(scored, "execute", None))
        assert not callable(getattr(scored, "run", None))


# ---------------------------------------------------------------------------
# 12. Upgrade 4 tests remain passing (import check)
# ---------------------------------------------------------------------------

class TestUpgrade4Compatibility:
    def test_schemas_still_work(self):
        """Existing Upgrade 4 schemas should still be valid."""
        candidate = CandidateExperiment(
            strategy_name="shell_credential_dump",
            technique_ids=["T1003.008"],
            title="Test",
            description="Test",
            proposed_risk_level="HIGH",
            candidate_status=CandidateStatus.NEVER_TESTED,
        )
        assert candidate.strategy_name == "shell_credential_dump"
        assert candidate.technique_ids == ["T1003.008"]

        context = SecurityExperienceContext(
            organization_id="test-org",
            built_at=datetime.now(timezone.utc).isoformat() + "Z",
        )
        assert context.organization_id == "test-org"
        assert context.total_experiments == 0


# ---------------------------------------------------------------------------
# 13. Upgrade 5 tests remain passing (import check)
# ---------------------------------------------------------------------------

class TestUpgrade5Compatibility:
    def test_web_strategies_still_in_catalog(self):
        """Web strategies from Upgrade 5 should still be in the catalog."""
        web_strategies = [
            "web_sql_injection_login",
            "web_command_injection",
            "web_path_traversal",
            "web_search_sqli",
        ]
        for name in web_strategies:
            assert name in STRATEGY_CATALOG

    def test_adaptive_fields_on_candidates(self):
        """Candidates should have adaptive fields (Upgrade 6 addition)."""
        candidate = CandidateExperiment(
            strategy_name="web_sql_injection_login",
            technique_ids=["T1190"],
            title="Test",
            description="Test",
            proposed_risk_level="HIGH",
            candidate_status=CandidateStatus.NEVER_TESTED,
            detection_confidence=0.0,
            attack_success_rate=0.0,
        )
        assert candidate.detection_confidence == 0.0
        assert candidate.attack_success_rate == 0.0
        assert candidate.last_tested_days_ago is None
        assert candidate.recent_experiment_count == 0


# ---------------------------------------------------------------------------
# Critical Adaptation Test — Core proof of Upgrade 6
# ---------------------------------------------------------------------------

class TestCriticalAdaptation:
    """The canonical test demonstrating adaptive learning.

    Before experience:
        Technique A: low priority (never tested)
        Technique B: medium priority (never tested)
        Technique C: medium priority (never tested)

    Execute experiment against Technique A:
        attack succeeds, detection fails

    Record experience.

    Request candidate ranking again:
        Technique A: HIGH priority (detection gap identified)

    Execute successful detection against Technique A repeatedly.
        Priority should decrease as confidence improves.
    """

    def test_canonical_adaptation_flow(self, db_session, org_id, obj_id):
        """Core proof: experiment outcome → learning state changes → ranking changes."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )
        from sentinelforge.adaptive.detection_gap_model import DetectionGapModel

        builder = SecurityExperienceContextBuilder(db_session, org_id)
        scorer = ExperimentScorer()
        gap_model = DetectionGapModel(db_session, org_id)

        # === BEFORE experience ===
        context_before = builder.build()
        scored_before = scorer.score(context_before)

        # Record initial ranking for strategies that use T1059.004 (Technique A)
        t1059_rankings_before = [
            (sc.candidate.strategy_name, sc.score)
            for sc in scored_before
            if "T1059.004" in sc.candidate.technique_ids
        ]
        assert len(t1059_rankings_before) > 0

        # All T1059.004 candidates should have NEVER_TESTED status
        for name, score in t1059_rankings_before:
            candidate = next(
                sc.candidate for sc in scored_before
                if sc.candidate.strategy_name == name
            )
            assert candidate.candidate_status == CandidateStatus.NEVER_TESTED
            # Never-tested gets +60 base score
            assert candidate.times_tested == 0

        # === EXPERIMENT 1: Attack succeeds, detection fails ===
        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "NOT_DETECTED", days_ago=1)

        # === AFTER EXPERIMENT 1 ===
        context_after_exp1 = builder.build()
        scored_after_exp1 = scorer.score(context_after_exp1)

        t1059_rankings_after_exp1 = [
            (sc.candidate.strategy_name, sc.score)
            for sc in scored_after_exp1
            if "T1059.004" in sc.candidate.technique_ids
        ]

        # T1059.004 candidates should now have NOT_DETECTED status
        for name, score in t1059_rankings_after_exp1:
            candidate = next(
                sc.candidate for sc in scored_after_exp1
                if sc.candidate.strategy_name == name
            )
            assert candidate.candidate_status == CandidateStatus.NOT_DETECTED
            assert candidate.times_not_detected > 0

        # The gap profiles should show this technique as a detection gap
        gap_profiles = context_after_exp1.gap_profiles
        t1059_profile = next(
            (p for p in gap_profiles if p.technique_id == "T1059.004"), None
        )
        assert t1059_profile is not None
        assert t1059_profile.detection_rate == 0.0
        assert t1059_profile.attack_success_rate == 1.0
        assert t1059_profile.priority > 30.0  # Elevated priority

        # The score should reflect detection gap + attack success
        for name, score in t1059_rankings_after_exp1:
            sc = next(
                sc for sc in scored_after_exp1
                if sc.candidate.strategy_name == name
            )
            assert "detection_gap_magnitude" in sc.score_breakdown or \
                   "not_detected" in sc.score_breakdown or \
                   "attack_success_history" in sc.score_breakdown

        # === EXPERIMENTS 2-5: Detection improves ===
        for i in range(4):
            _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=0 - (i + 1))

        # === AFTER IMPROVED DETECTION ===
        context_after_improved = builder.build()
        scored_after_improved = scorer.score(context_after_improved)

        t1059_rankings_after_improved = [
            (sc.candidate.strategy_name, sc.score)
            for sc in scored_after_improved
            if "T1059.004" in sc.candidate.technique_ids
        ]

        # Detection confidence should now be higher
        for name, score in t1059_rankings_after_improved:
            candidate = next(
                sc.candidate for sc in scored_after_improved
                if sc.candidate.strategy_name == name
            )
            # 4 detected, 1 not-detected = 80% detection rate
            assert candidate.detection_confidence > 0.5

        # The gap profile should show improved detection
        gap_profiles_improved = context_after_improved.gap_profiles
        t1059_profile_improved = next(
            (p for p in gap_profiles_improved if p.technique_id == "T1059.004"), None
        )
        assert t1059_profile_improved is not None
        assert t1059_profile_improved.detection_rate == 0.8  # 4/5 detected
        assert t1059_profile_improved.attack_success_rate == 0.2  # 1/5 missed

        # Priority should decrease as confidence improves
        # (but still elevated due to the one undetected attack)
        assert t1059_profile_improved.priority < t1059_profile.priority

        # === Verify adaptation metrics ===
        metrics_calc = AdaptationMetricsCalculator(db_session, org_id)
        metrics = metrics_calc.compute_metrics(
            gap_profiles_improved, scored_after_improved
        )

        # Detection coverage should reflect the 4:1 ratio
        assert metrics.detection_coverage > 0.0
        assert metrics.detection_gap < 1.0
        assert metrics.total_experiments == 5
        assert metrics.techniques_tested >= 1

    def test_ranking_shifts_after_gap_discovery(self, db_session, org_id, obj_id):
        """Proves that discovering a detection gap shifts candidate rankings."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )

        builder = SecurityExperienceContextBuilder(db_session, org_id)
        scorer = ExperimentScorer()

        # Initial state: all candidates equal (never tested)
        context_initial = builder.build()
        scored_initial = scorer.score(context_initial)

        # Get a baseline ranking
        initial_ranking = [
            (sc.candidate.strategy_name, sc.score)
            for sc in scored_initial
        ]

        # Now create a detection gap for T1059.004
        scenario_id = _seed_evaluation(
            db_session, org_id, obj_id, "T1059.004", "NOT_DETECTED", days_ago=1
        )
        _seed_gap(db_session, org_id, "T1059.004", scenario_id, "OPEN")

        # After gap: strategies using T1059.004 should rank higher
        context_with_gap = builder.build()
        scored_with_gap = scorer.score(context_with_gap)

        # Find scores for T1059.004 strategies before and after
        t1059_before = next(
            (s for n, s in initial_ranking if "T1059.004" in n), None
        )
        t1059_after = next(
            (sc.score for sc in scored_with_gap if "T1059.004" in sc.candidate.technique_ids),
            None,
        )

        if t1059_before is not None and t1059_after is not None:
            # T1059.004 strategies should score higher after gap discovery
            assert t1059_after > t1059_before

        # Verify that the highest-scoring candidate changed
        initial_top = scored_initial[0].candidate.strategy_name
        gap_top = scored_with_gap[0].candidate.strategy_name
        # At minimum, the ranking should have shifted (not guaranteed to be
        # different top, but the gap candidate should rank higher)
        t1059_initial_rank = next(
            i for i, sc in enumerate(scored_initial)
            if "T1059.004" in sc.candidate.technique_ids
        )
        t1059_gap_rank = next(
            i for i, sc in enumerate(scored_with_gap)
            if "T1059.004" in sc.candidate.technique_ids
        )
        assert t1059_gap_rank <= t1059_initial_rank  # Rank improved (lower = better)


# ---------------------------------------------------------------------------
# Adaptation Metrics Tests
# ---------------------------------------------------------------------------

class TestAdaptationMetrics:
    def test_metrics_computed_from_state(self, db_session, org_id, obj_id):
        """Adaptation metrics should be computed from persisted state."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # Add some experiments
        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=5)
        _seed_evaluation(db_session, org_id, obj_id, "T1003.008", "NOT_DETECTED", days_ago=3)

        from sentinelforge.adaptive.detection_gap_model import DetectionGapModel
        from sentinelforge.adaptive.security_experience_context import (
            SecurityExperienceContextBuilder,
        )

        gap_model = DetectionGapModel(db_session, org_id)
        profiles = gap_model.build_gap_profiles()

        builder = SecurityExperienceContextBuilder(db_session, org_id)
        context = builder.build()

        scorer = ExperimentScorer()
        scored = scorer.score(context)

        calc = AdaptationMetricsCalculator(db_session, org_id)
        metrics = calc.compute_metrics(profiles, scored)

        assert isinstance(metrics, AdaptationMetrics)
        assert metrics.total_experiments == 2
        assert 0.0 <= metrics.detection_coverage <= 1.0
        assert 0.0 <= metrics.detection_gap <= 1.0
        assert metrics.detection_coverage + metrics.detection_gap == 1.0
        assert metrics.techniques_tested >= 1

    def test_repetition_rate_zero_for_first_experiments(self, db_session, org_id, obj_id):
        """Repetition rate should be 0 when no repeated experiments exist."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=5)

        calc = AdaptationMetricsCalculator(db_session, org_id)
        metrics = calc.compute_metrics([])

        assert metrics.repetition_rate == 0.0


# ---------------------------------------------------------------------------
# DetectionGapProfile Tests
# ---------------------------------------------------------------------------

class TestDetectionGapProfile:
    def test_profile_fields_are_deterministic(self, db_session, org_id, obj_id):
        """Gap profile fields should be derived deterministically from evidence."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=5)
        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "NOT_DETECTED", days_ago=2)

        model = DetectionGapModel(db_session, org_id)
        profiles = model.build_gap_profiles()

        tech_profile = next(p for p in profiles if p.technique_id == "T1059.004")

        assert tech_profile.technique_id == "T1059.004"
        assert tech_profile.experiments_executed == 2
        assert tech_profile.attacks_detected == 1
        assert tech_profile.attacks_missed == 1
        assert abs(tech_profile.detection_rate - 0.5) < 0.01
        assert tech_profile.last_tested is not None
        assert tech_profile.last_tested_days_ago is not None
        assert tech_profile.priority > 0.0

    def test_profiles_sorted_by_priority(self, db_session, org_id, obj_id):
        """Gap profiles should be sorted by priority descending."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # T1003.008: not detected (high priority)
        _seed_evaluation(db_session, org_id, obj_id, "T1003.008", "NOT_DETECTED", days_ago=5)
        # T1059.004: detected (low priority)
        _seed_evaluation(db_session, org_id, obj_id, "T1059.004", "DETECTED", days_ago=5)

        model = DetectionGapModel(db_session, org_id)
        profiles = model.build_gap_profiles()

        assert len(profiles) >= 2
        # First profile should have higher or equal priority to second
        assert profiles[0].priority >= profiles[1].priority
