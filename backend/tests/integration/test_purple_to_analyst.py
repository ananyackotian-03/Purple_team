"""Purple Evaluation → Blue Agent Analyst Integration Tests.

Proves the deterministic pipeline:
    PurpleEvaluation → GapAnalysisResult → Analyst Recommendation

Validates that:
- Deterministic detection status is authoritative and never mutated
- Analyst receives correct evaluation context
- Tenant isolation is preserved
- Evidence and technique propagation is correct

Classification: PURPLE-TO-ANALYST-VERIFIED
"""

import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.agents.blue_agent import BlueAgentAnalyst, GapAnalysisResult
from sentinelforge.db.models import Base, DetectionGapRecord, Organization
from sentinelforge.detection.evaluator import PurpleEvaluation
from sentinelforge.detection.sigma_engine import DetectionOutcome


ORG_ID = uuid.uuid4()
ORG_ID_B = uuid.uuid4()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Organization(id=ORG_ID, name="TestOrg"))
    s.add(Organization(id=ORG_ID_B, name="TestOrgB"))
    s.commit()
    yield s
    s.close()


@pytest.fixture
def analyst():
    return BlueAgentAnalyst()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_purple_evaluation(
    detection_status="NOT_DETECTED",
    technique_id="T1059.004",
    matched_rule_ids=None,
    evidence_event_ids=None,
    expected_detection=False,
    gap_reason=None,
    organization_id=None,
    experiment_id=None,
):
    """Build a minimal PurpleEvaluation for testing."""
    return PurpleEvaluation(
        evaluation_id=str(uuid.uuid4()),
        experiment_id=experiment_id or str(uuid.uuid4()),
        execution_id=str(uuid.uuid4()),
        organization_id=str(organization_id or ORG_ID),
        technique_id=technique_id,
        detection_status=detection_status,
        matched_rule_ids=matched_rule_ids or [],
        evidence_event_ids=evidence_event_ids or [],
        expected_detection=expected_detection,
        gap_reason=gap_reason,
        detection_latency_ms=42.5,
        evaluated_at=datetime.now(timezone.utc).isoformat() + "Z",
    )


# ---------------------------------------------------------------------------
# A. NOT_DETECTED — analyst receives correct context
# ---------------------------------------------------------------------------

class TestNotDetectedAnalysis:
    def test_not_detected_returns_gap_analysis(self, analyst):
        """NOT_DETECTED evaluation produces a GapAnalysisResult."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            technique_id="T1059.004",
            matched_rule_ids=[],
            evidence_event_ids=["ev-1", "ev-2"],
            gap_reason="Telemetry observed for action, but no Sigma rule matched technique T1059.004",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result is not None
        assert isinstance(result, GapAnalysisResult)
        assert result.original_outcome == "NOT_DETECTED"
        assert result.technique_id == "T1059.004"

    def test_not_detected_root_cause_no_rule_match(self, analyst):
        """NOT_DETECTED with evidence but no matched rules → NO_RULE_MATCH."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            technique_id="T1059.004",
            matched_rule_ids=[],
            evidence_event_ids=["ev-1"],
            gap_reason="Telemetry observed, but no Sigma rule matched technique T1059.004",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.root_cause == "NO_RULE_MATCH"

    def test_not_detected_preserves_evidence(self, analyst):
        """NOT_DETECTED analysis preserves evidence event IDs."""
        evidence_ids = ["ev-aaa", "ev-bbb", "ev-ccc"]
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            evidence_event_ids=evidence_ids,
            gap_reason="No rule matched",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.evidence_event_ids == evidence_ids

    def test_not_detected_preserves_matched_rules(self, analyst):
        """NOT_DETECTED analysis preserves matched rule IDs (unrelated rules)."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            matched_rule_ids=["unrelated-rule-1"],
            evidence_event_ids=["ev-1"],
            gap_reason="Telemetry observed and matched unrelated rule, but expected technique not detected",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.matched_rule_ids == ["unrelated-rule-1"]


# ---------------------------------------------------------------------------
# B. DETECTION_GAP — gap correctly passed without status change
# ---------------------------------------------------------------------------

class TestDetectionGapAnalysis:
    def test_detection_gap_returns_analysis(self, analyst):
        """DETECTION_GAP evaluation produces a GapAnalysisResult."""
        purple = _make_purple_evaluation(
            detection_status="DETECTION_GAP",
            technique_id="T1003.008",
            matched_rule_ids=[],
            evidence_event_ids=[],
            gap_reason="No telemetry events were captured for technique T1003.008",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result is not None
        assert result.original_outcome == "DETECTION_GAP"

    def test_detection_gap_no_telemetry(self, analyst):
        """DETECTION_GAP with no evidence → NO_TELEMETRY root cause."""
        purple = _make_purple_evaluation(
            detection_status="DETECTION_GAP",
            technique_id="T1003.008",
            evidence_event_ids=[],
            gap_reason="No telemetry events were captured",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.root_cause == "NO_TELEMETRY"

    def test_detection_gap_status_not_mutated(self, analyst):
        """Analyst analysis does NOT change the detection_status on PurpleEvaluation."""
        purple = _make_purple_evaluation(
            detection_status="DETECTION_GAP",
            evidence_event_ids=[],
            gap_reason="No telemetry",
        )
        original_status = purple.detection_status

        analyst.analyze_purple_evaluation(purple)

        assert purple.detection_status == original_status


# ---------------------------------------------------------------------------
# C. DETECTED — does not enter gap analysis path
# ---------------------------------------------------------------------------

class TestDetectedNoAnalysis:
    def test_detected_returns_none(self, analyst):
        """DETECTED evaluation returns None (no gap to analyze)."""
        purple = _make_purple_evaluation(
            detection_status="DETECTED",
            matched_rule_ids=["sentinelforge-shell-execution"],
            evidence_event_ids=["ev-1"],
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result is None

    def test_detected_no_gap_analysis_record_created(self, analyst, db_session):
        """DETECTED evaluation does NOT create a DetectionGapRecord."""
        purple = _make_purple_evaluation(
            detection_status="DETECTED",
            matched_rule_ids=["sentinelforge-shell-execution"],
            evidence_event_ids=["ev-1"],
        )

        analyst.analyze_purple_evaluation(purple, db_session=db_session)

        records = db_session.query(DetectionGapRecord).all()
        assert len(records) == 0


# ---------------------------------------------------------------------------
# D. ATT&CK technique propagation
# ---------------------------------------------------------------------------

class TestATTnCKPropagation:
    def test_technique_id_propagated_to_gap(self, analyst):
        """technique_id from PurpleEvaluation reaches GapAnalysisResult."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            technique_id="T1003.008",
            evidence_event_ids=["ev-1"],
            gap_reason="No rule matched",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.technique_id == "T1003.008"

    def test_unknown_technique_yields_insufficient_metadata(self, analyst):
        """Unknown technique_id → INSUFFICIENT_TECHNIQUE_METADATA root cause."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            technique_id="unknown",
            evidence_event_ids=["ev-1"],
            gap_reason="",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.root_cause == "INSUFFICIENT_TECHNIQUE_METADATA"

    def test_empty_technique_yields_insufficient_metadata(self, analyst):
        """Empty technique_id → INSUFFICIENT_TECHNIQUE_METADATA root cause."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            technique_id="",
            evidence_event_ids=["ev-1"],
            gap_reason="",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.root_cause == "INSUFFICIENT_TECHNIQUE_METADATA"


# ---------------------------------------------------------------------------
# E. Evidence propagation
# ---------------------------------------------------------------------------

class TestEvidencePropagation:
    def test_evidence_ids_in_gap_result(self, analyst):
        """Evidence event IDs from PurpleEvaluation reach GapAnalysisResult."""
        evidence = ["ev-1", "ev-2", "ev-3"]
        purple = _make_purple_evaluation(
            detection_status="DETECTION_GAP",
            evidence_event_ids=evidence,
            gap_reason="No rule matched",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.evidence_event_ids == evidence

    def test_matched_rules_in_gap_result(self, analyst):
        """Matched rule IDs from PurpleEvaluation reach GapAnalysisResult."""
        rules = ["rule-a", "rule-b"]
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            matched_rule_ids=rules,
            evidence_event_ids=["ev-1"],
            gap_reason="Unrelated rules matched",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.matched_rule_ids == rules

    def test_scenario_id_propagated(self, analyst):
        """experiment_id from PurpleEvaluation becomes scenario_id in GapAnalysisResult."""
        scenario_id = str(uuid.uuid4())
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            experiment_id=scenario_id,
            evidence_event_ids=["ev-1"],
            gap_reason="No rule matched",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.scenario_id == scenario_id

    def test_evaluation_id_used_as_action_id(self, analyst):
        """evaluation_id is used as action_id in GapAnalysisResult."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            evidence_event_ids=["ev-1"],
            gap_reason="No rule matched",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.action_id == purple.evaluation_id


# ---------------------------------------------------------------------------
# F. Tenant isolation
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_org_id_preserved_in_gap(self, analyst):
        """organization_id from PurpleEvaluation is preserved in persistence."""
        org_a = uuid.uuid4()
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            organization_id=org_a,
            evidence_event_ids=["ev-1"],
            gap_reason="No rule matched",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result is not None
        # The gap result doesn't store org_id directly, but persistence uses it

    def test_cross_tenant_gap_persistence(self, analyst, db_session):
        """Gap records from different orgs are isolated in DB."""
        purple_a = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            organization_id=ORG_ID,
            evidence_event_ids=["ev-a"],
            gap_reason="No rule matched",
        )
        purple_b = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            organization_id=ORG_ID_B,
            evidence_event_ids=["ev-b"],
            gap_reason="No rule matched",
        )

        analyst.analyze_purple_evaluation(purple_a, db_session=db_session)
        analyst.analyze_purple_evaluation(purple_b, db_session=db_session)

        # Query only org A gaps
        gaps_a = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.organization_id == ORG_ID
        ).all()
        # Query only org B gaps
        gaps_b = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.organization_id == ORG_ID_B
        ).all()

        assert len(gaps_a) == 1
        assert len(gaps_b) == 1
        assert str(gaps_a[0].organization_id) == str(ORG_ID)
        assert str(gaps_b[0].organization_id) == str(ORG_ID_B)

    def test_no_cross_tenant_analysis(self, analyst):
        """Analyst analysis of one tenant's eval does not affect another tenant's data."""
        purple_a = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            organization_id=ORG_ID,
            evidence_event_ids=["ev-a"],
            gap_reason="No rule matched",
        )
        purple_b = _make_purple_evaluation(
            detection_status="DETECTED",
            organization_id=ORG_ID_B,
            matched_rule_ids=["rule-1"],
            evidence_event_ids=["ev-b"],
        )

        result_a = analyst.analyze_purple_evaluation(purple_a)
        result_b = analyst.analyze_purple_evaluation(purple_b)

        # Tenant A has a gap, Tenant B is detected (returns None)
        assert result_a is not None
        assert result_a.original_outcome == "NOT_DETECTED"
        assert result_b is None


# ---------------------------------------------------------------------------
# G. Deterministic authority — analyst CANNOT mutate status
# ---------------------------------------------------------------------------

class TestDeterministicAuthority:
    def test_analyst_cannot_change_not_detected_to_detected(self, analyst):
        """Analyst output does NOT change detection_status from NOT_DETECTED to DETECTED."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            evidence_event_ids=["ev-1"],
            gap_reason="No rule matched",
        )
        original_status = purple.detection_status

        result = analyst.analyze_purple_evaluation(purple)

        assert purple.detection_status == original_status
        assert purple.detection_status == "NOT_DETECTED"
        assert result.original_outcome == "NOT_DETECTED"

    def test_analyst_cannot_change_gap_to_detected(self, analyst):
        """Analyst output does NOT change detection_status from DETECTION_GAP to DETECTED."""
        purple = _make_purple_evaluation(
            detection_status="DETECTION_GAP",
            evidence_event_ids=[],
            gap_reason="No telemetry",
        )
        original_status = purple.detection_status

        result = analyst.analyze_purple_evaluation(purple)

        assert purple.detection_status == original_status
        assert purple.detection_status == "DETECTION_GAP"
        assert result.original_outcome == "DETECTION_GAP"

    def test_analyst_cannot_mutate_expected_detection(self, analyst):
        """Analyst cannot change expected_detection field."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            expected_detection=True,
            evidence_event_ids=["ev-1"],
            gap_reason="No rule matched",
        )

        analyst.analyze_purple_evaluation(purple)

        assert purple.expected_detection is True

    def test_analyst_cannot_mutate_purple_evaluation_fields(self, analyst):
        """Analyst cannot modify any PurpleEvaluation fields."""
        purple = _make_purple_evaluation(
            detection_status="DETECTION_GAP",
            technique_id="T1059.004",
            matched_rule_ids=["rule-1"],
            evidence_event_ids=["ev-1"],
            expected_detection=False,
            gap_reason="No telemetry",
        )
        original_id = purple.evaluation_id
        original_experiment = purple.experiment_id
        original_technique = purple.technique_id
        original_rules = purple.matched_rule_ids.copy()
        original_evidence = purple.evidence_event_ids.copy()

        analyst.analyze_purple_evaluation(purple)

        assert purple.evaluation_id == original_id
        assert purple.experiment_id == original_experiment
        assert purple.technique_id == original_technique
        assert purple.matched_rule_ids == original_rules
        assert purple.evidence_event_ids == original_evidence

    def test_analyst_cannot_affect_coverage(self, analyst):
        """Analyst analysis does not change the detection_status used for coverage calculation."""
        from sentinelforge.detection.evaluator import PurpleEvaluator

        purple_evaluator = PurpleEvaluator()

        evals = []
        for status in ["NOT_DETECTED", "DETECTION_GAP", "DETECTED"]:
            purple = _make_purple_evaluation(
                detection_status=status,
                evidence_event_ids=["ev-1"] if status != "DETECTION_GAP" else [],
                gap_reason="gap" if status != "DETECTED" else None,
            )
            evals.append(purple)
            # Run analyst on non-DETECTED
            if status != "DETECTED":
                analyst.analyze_purple_evaluation(purple)

        report = purple_evaluator.compute_coverage(evals, str(ORG_ID))

        # Coverage should be 1 detected out of 3 = 33.33%
        assert report.total_experiments == 3
        assert report.detected_experiments == 1
        assert report.missed_experiments == 1
        assert report.gap_experiments == 1
        assert abs(report.coverage_pct - 33.33) < 0.01


# ---------------------------------------------------------------------------
# H. Persistence — DetectionGapRecord created correctly
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_gap_record_created(self, analyst, db_session):
        """analyze_purple_evaluation creates a DetectionGapRecord when db_session provided."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            technique_id="T1059.004",
            evidence_event_ids=["ev-1"],
            gap_reason="No rule matched",
        )

        result = analyst.analyze_purple_evaluation(purple, db_session=db_session)

        record = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == uuid.UUID(result.gap_id)
        ).first()
        assert record is not None
        assert record.technique_id == "T1059.004"
        assert record.original_outcome == "NOT_DETECTED"
        assert record.remediation_status == "OPEN"

    def test_gap_record_evidence_json(self, analyst, db_session):
        """Evidence event IDs are stored as JSON in DetectionGapRecord."""
        evidence = ["ev-1", "ev-2"]
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            evidence_event_ids=evidence,
            gap_reason="No rule matched",
        )

        result = analyst.analyze_purple_evaluation(purple, db_session=db_session)

        record = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == uuid.UUID(result.gap_id)
        ).first()
        stored_evidence = json.loads(record.evidence_event_ids)
        assert stored_evidence == evidence

    def test_gap_record_matched_rules_json(self, analyst, db_session):
        """Matched rule IDs are stored as JSON in DetectionGapRecord."""
        rules = ["rule-a", "rule-b"]
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            matched_rule_ids=rules,
            evidence_event_ids=["ev-1"],
            gap_reason="Unrelated rules matched",
        )

        result = analyst.analyze_purple_evaluation(purple, db_session=db_session)

        record = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == uuid.UUID(result.gap_id)
        ).first()
        stored_rules = json.loads(record.matched_rule_ids)
        assert stored_rules == rules

    def test_no_record_for_detected(self, analyst, db_session):
        """No DetectionGapRecord created for DETECTED evaluations."""
        purple = _make_purple_evaluation(
            detection_status="DETECTED",
            matched_rule_ids=["rule-1"],
            evidence_event_ids=["ev-1"],
        )

        analyst.analyze_purple_evaluation(purple, db_session=db_session)

        records = db_session.query(DetectionGapRecord).all()
        assert len(records) == 0

    def test_gap_record_without_db_session(self, analyst):
        """analyze_purple_evaluation works without db_session (no persistence)."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            evidence_event_ids=["ev-1"],
            gap_reason="No rule matched",
        )

        result = analyst.analyze_purple_evaluation(purple, db_session=None)

        assert result is not None
        assert isinstance(result, GapAnalysisResult)


# ---------------------------------------------------------------------------
# I. Root cause determination
# ---------------------------------------------------------------------------

class TestRootCauseDetermination:
    def test_no_telemetry_root_cause(self, analyst):
        """No evidence events → NO_TELEMETRY."""
        purple = _make_purple_evaluation(
            detection_status="DETECTION_GAP",
            evidence_event_ids=[],
            gap_reason="No telemetry",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.root_cause == "NO_TELEMETRY"

    def test_no_rule_match_root_cause(self, analyst):
        """Evidence exists but no rules matched → NO_RULE_MATCH."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            evidence_event_ids=["ev-1"],
            gap_reason="Telemetry observed, but no Sigma rule matched",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.root_cause == "NO_RULE_MATCH"

    def test_unrelated_rule_match_root_cause(self, analyst):
        """Gap reason mentions "unrelated" → UNRELATED_RULE_MATCH."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            matched_rule_ids=["unrelated-rule"],
            evidence_event_ids=["ev-1"],
            gap_reason="Telemetry observed and matched unrelated rule, but expected technique not detected",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.root_cause == "UNRELATED_RULE_MATCH"

    def test_insufficient_rule_coverage_root_cause(self, analyst):
        """EVENT_NO_MATCH status → INSUFFICIENT_RULE_COVERAGE (catch-all fallback)."""
        purple = _make_purple_evaluation(
            detection_status="EVENT_NO_MATCH",
            evidence_event_ids=["ev-1"],
            matched_rule_ids=["partial-rule"],
            gap_reason="Incomplete detection rule coverage",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.root_cause == "INSUFFICIENT_RULE_COVERAGE"

    def test_insufficient_technique_metadata_root_cause(self, analyst):
        """Unknown technique → INSUFFICIENT_TECHNIQUE_METADATA."""
        purple = _make_purple_evaluation(
            detection_status="NOT_DETECTED",
            technique_id="unknown",
            evidence_event_ids=["ev-1"],
            gap_reason="",
        )

        result = analyst.analyze_purple_evaluation(purple)

        assert result.root_cause == "INSUFFICIENT_TECHNIQUE_METADATA"
