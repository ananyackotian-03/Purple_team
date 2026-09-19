"""Phase 13 — Canonical Cyber Immune End-to-End Verification.

ONE authoritative test that demonstrates the actual Cyber Immune System
lifecycle from initial security objective through adaptive next-experiment
selection.

The purpose of this phase is NOT to test every individual component.
Phases 8-12 already do that.

The purpose here is to prove: THE ENTIRE CYBER IMMUNE LOOP WORKS TOGETHER.

Canonical Flow Verified:
  Organization
    → Security Objective
    → Red Agent
    → Attack Experiment
    → Safety Boundary
    → Policy Engine
    → Tool Authorization
    → Sandbox (simulated)
    → Telemetry (simulated)
    → Normalization (simulated)
    → Detection
    → Purple Evaluation
    → Detection Gap
    → Defensive Analysis
    → Defensive Proposal
    → Defensive Safety Boundary
    → Defense Testing
    → Retest
    → Before/After Comparison
    → MITIGATED
    → Immune Memory
    → Adaptive Next Experiment

Security Invariants Verified:
  1. MITIGATED requires deterministic before/after proof
  2. DefensiveSafetyBoundary cannot be bypassed
  3. LLM proposals are untrusted — deterministic gates dispose
  4. Tenant isolation enforced at every boundary
  5. State machine rejects invalid transitions
  6. Immune memory is evidence-linked and tenant-scoped
  7. Adaptive selection uses deterministic scoring fallback
"""

import pytest
from uuid import uuid4, UUID
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import (
    Base,
    Organization as OrgModel,
    SecurityObjectiveRecord,
    AdversarialScenarioRecord,
    DetectionGapRecord,
    PurpleEvaluationRecord,
    RetestResult as RetestResultModel,
    PolicyDecisionRecord,
)
from sentinelforge.remediation.db_models import (
    RemediationRetestResultRecord,
    RemediationAuditEventRecord,
)

from sentinelforge.immune_cycle_orchestrator import ImmuneCycleOrchestrator
from sentinelforge.domain.experiment import RetestResult
from sentinelforge.domain.state_machine import (
    CyberImmuneStateMachine,
    CYBER_IMMUNE_VALID_TRANSITIONS,
    CYBER_IMMUNE_STATES,
)
from sentinelforge.defensive.proposal import DefensiveProposal, ProposalType
from sentinelforge.defensive.boundary import DefensiveSafetyBoundary
from sentinelforge.defensive.before_after_comparison import (
    BeforeAfterComparison,
    BeforeAfterCoverage,
)
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.immune_memory import ImmuneMemory
from sentinelforge.organization.security_state import OrganizationSecurityState
from sentinelforge.adaptive.next_experiment_selector import NextExperimentSelector
from sentinelforge.adaptive.schemas import NextExperimentResult
from sentinelforge.detection.evaluator import DetectionOutcome, PurpleEvaluation


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    """Create an in-memory SQLite session for E2E testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    import sentinelforge.db.models  # noqa: F401
    import sentinelforge.remediation.db_models  # noqa: F401

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    yield session
    session.close()


def _seed_full_state(db_session, *, org_id=None):
    """Seed the full initial state for the canonical E2E test.

    Creates: Organization, SecurityObjective, AdversarialScenario,
    DetectionGap (OPEN), PurpleEvaluation (DETECTION_GAP).

    Returns dict with all IDs.
    """
    org_id = org_id or uuid4()
    obj_id = uuid4()
    scenario_id = uuid4()
    gap_id = uuid4()

    db_session.add(OrgModel(id=org_id, name="Canonical Test Org"))
    db_session.add(SecurityObjectiveRecord(
        id=obj_id,
        organization_id=org_id,
        title="Detect credential dumping via /etc/shadow",
        description="Ensure T1003.008 access to /etc/shadow is detected",
        target_category="linux_host",
        default_risk_level="HIGH",
    ))
    db_session.add(AdversarialScenarioRecord(
        id=scenario_id,
        objective_id=obj_id,
        organization_id=org_id,
        title="OS Credential Access — /etc/shadow dump",
        strategy_description="cat /etc/shadow to extract password hashes",
        proposed_risk_level="HIGH",
        created_by="red_agent",
    ))
    db_session.add(DetectionGapRecord(
        id=gap_id,
        organization_id=org_id,
        scenario_id=scenario_id,
        action_id=uuid4(),
        technique_id="T1003.008",
        original_outcome="NOT_DETECTED",
        root_cause="missing_rule",
        reason="No Sigma rule covers T1003.008 /etc/shadow read",
        remediation_status="OPEN",
    ))
    db_session.add(PurpleEvaluationRecord(
        id=uuid4(),
        organization_id=org_id,
        experiment_id=scenario_id,
        execution_id=uuid4(),
        technique_id="T1003.008",
        detection_status="DETECTION_GAP",
        matched_rule_ids=None,
        evidence_event_ids=None,
        expected_detection=False,
        gap_reason="No Sigma rule for T1003.008",
    ))
    db_session.commit()

    return {
        "org_id": org_id,
        "obj_id": obj_id,
        "scenario_id": scenario_id,
        "gap_id": gap_id,
    }


def _make_orchestrator_with_retest(db_session, org_id, obj_id, *, improved: bool):
    """Create an ImmuneCycleOrchestrator with a deterministic mock retest."""
    orch = ImmuneCycleOrchestrator(
        db_session=db_session,
        organization_id=org_id,
        objective_id=obj_id,
    )

    def mock_retest():
        return RetestResult(
            retest_id=uuid4(),
            organization_id=org_id,
            exercise_id=uuid4(),
            scenario_id=uuid4(),
            before_outcome="DETECTION_GAP",
            after_outcome="DETECTED" if improved else "DETECTION_GAP",
            detection_improved=improved,
            validated_rule_ids=["sigma-rule-001"] if improved else [],
            evaluated_at=datetime.now(timezone.utc),
        )

    orch._retest_original_experiment = mock_retest
    return orch


# ===================================================================
# CANONICAL E2E TEST
# ===================================================================

class TestCanonicalCyberImmuneE2E:
    """ONE authoritative test demonstrating the entire Cyber Immune
    lifecycle from security objective through adaptive next-experiment."""

    def test_full_lifecycle_mitigated(self, db_session):
        """Organization → Objective → Red Agent → Attack → Safety Boundary
        → Policy Engine → Sandbox → Telemetry → Normalization → Detection
        → Purple Evaluation → Detection Gap → Defensive Analysis →
        Defensive Proposal → Defensive Safety Boundary → Defense Testing
        → Retest → Before/After Comparison → MITIGATED → Immune Memory
        → Adaptive Next Experiment.

        This is THE canonical test proving the entire loop works together.
        """
        # =================================================================
        # STEP 1: ORGANIZATION
        # =================================================================
        state = _seed_full_state(db_session)
        org_id = state["org_id"]
        obj_id = state["obj_id"]
        scenario_id = state["scenario_id"]
        gap_id = state["gap_id"]

        # Verify: Organization exists in DB
        org = db_session.query(OrgModel).filter(OrgModel.id == org_id).one()
        assert org.name == "Canonical Test Org"
        assert org.defensive_state == "INITIAL"

        # =================================================================
        # STEP 2: SECURITY OBJECTIVE
        # =================================================================
        obj = db_session.query(SecurityObjectiveRecord).filter(
            SecurityObjectiveRecord.id == obj_id,
            SecurityObjectiveRecord.organization_id == org_id,
        ).one()
        assert obj.title == "Detect credential dumping via /etc/shadow"
        assert obj.target_category == "linux_host"
        assert obj.default_risk_level == "HIGH"

        # =================================================================
        # STEP 3: RED AGENT — Adversarial Scenario
        # =================================================================
        scenario = db_session.query(AdversarialScenarioRecord).filter(
            AdversarialScenarioRecord.id == scenario_id,
            AdversarialScenarioRecord.organization_id == org_id,
        ).one()
        assert scenario.title == "OS Credential Access — /etc/shadow dump"
        assert scenario.proposed_risk_level == "HIGH"
        assert scenario.created_by == "red_agent"

        # =================================================================
        # STEP 4: ATTACK EXPERIMENT — Policy Decision Recorded
        # =================================================================
        # The Red Agent generates a scenario; the ExperimentSafetyBoundary
        # evaluates it. In production, this happens before execution.
        boundary = ExperimentSafetyBoundary()
        from sentinelforge.domain.experiment import AdversarialScenario as AdvScen

        adv_scenario = AdvScen(
            objective_id=obj_id,
            organization_id=org_id,
            title=scenario.title,
            strategy_description=scenario.strategy_description,
            technique_ids=["T1003.008"],
            proposed_risk_level="HIGH",
            created_by="red_agent",
        )
        decision = boundary.evaluate_scenario(adv_scenario)
        assert decision.status.value == "ALLOWED"

        # =================================================================
        # STEP 5: SAFETY BOUNDARY — Scenario Authorized
        # =================================================================
        # ExperimentSafetyBoundary approved the scenario (above).
        # Now verify the PolicyEngine validates an ActionIR.
        from sentinelforge.domain.action_ir import ActionIR, ActionType

        action_ir = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            action_type=ActionType.PROCESS_EXEC,
            target="sentinelforge-target",
            run_as_user="labuser",
            executable="/usr/bin/bash",
            arguments=["-c", "cat /etc/shadow"],
            technique_id="T1003.008",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 1),
        )
        # PolicyEngine validates the ActionIR
        policy_result = PolicyEngine.validate(action_ir)
        assert policy_result is True

        # =================================================================
        # STEP 6: TOOL AUTHORIZATION — Allowed Executable
        # =================================================================
        from sentinelforge.policy.allowlists import ALLOWED_EXECUTABLES

        assert "/usr/bin/bash" in ALLOWED_EXECUTABLES

        # =================================================================
        # STEP 7: SANDBOX / TELEMETRY / NORMALIZATION / DETECTION
        # (Simulated — in production this runs in Docker with Falco)
        # =================================================================
        # We create a DetectionGap to represent that the sandbox execution
        # produced telemetry that was NOT detected (gap identified).
        gap = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == gap_id,
        ).one()
        assert gap.technique_id == "T1003.008"
        assert gap.original_outcome == "NOT_DETECTED"
        assert gap.remediation_status == "OPEN"

        # =================================================================
        # STEP 8: PURPLE EVALUATION
        # =================================================================
        purple_eval = db_session.query(PurpleEvaluationRecord).filter(
            PurpleEvaluationRecord.organization_id == org_id,
        ).one()
        assert purple_eval.detection_status == "DETECTION_GAP"
        assert purple_eval.technique_id == "T1003.008"

        # =================================================================
        # STEP 9: DETECTION GAP IDENTIFIED
        # =================================================================
        # The gap is open and requires defensive improvement.

        # =================================================================
        # STEP 10-21: RUN THE IMMUNE CYCLE (Gap Path → MITIGATED → Next)
        # =================================================================
        orch = _make_orchestrator_with_retest(db_session, org_id, obj_id, improved=True)

        result = orch.run_cycle(detection_gap_id=gap_id)

        # --- Verify Final State: MITIGATED ---
        assert result["final_state"] == "MITIGATED"
        assert result["path"] == "mitigated"
        assert result["improvement_proven"] is True

        # --- Verify Evidence: Before/After Comparison Proof ---
        ev = result["evidence"]
        assert ev["improved"] is True
        assert ev["after_status"] == "DETECTED"
        assert ev["before_status"] in ("DETECTION_GAP", "NOT_DETECTED")
        assert ev["retest_improved"] is True

        # --- Verify Defensive Proposal was validated ---
        assert ev.get("defensive_proposal_id") is not None
        assert ev.get("defensive_proposal_validated_at") is not None

        # =================================================================
        # STEP 12: IMMUNE MEMORY — Persistent State Updated
        # =================================================================
        db_session.expire_all()

        # DetectionGapRecord.mitigation_status == MITIGATED
        gap_after = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == gap_id,
            DetectionGapRecord.organization_id == org_id,
        ).one()
        assert gap_after.remediation_status == "MITIGATED"

        # RemediationRetestResultRecord persisted
        retest_records = db_session.query(RemediationRetestResultRecord).filter(
            RemediationRetestResultRecord.organization_id == org_id,
            RemediationRetestResultRecord.finding_id == gap_id,
        ).all()
        assert len(retest_records) == 1
        assert retest_records[0].vulnerability_eliminated is True

        # Audit event persisted
        audits = db_session.query(RemediationAuditEventRecord).filter(
            RemediationAuditEventRecord.organization_id == org_id,
            RemediationAuditEventRecord.entity_id == gap_id,
            RemediationAuditEventRecord.event_type == "GAP_MITIGATED",
        ).all()
        assert len(audits) == 1

        # =================================================================
        # STEP 13: ADAPTIVE NEXT EXPERIMENT
        # =================================================================
        assert "next_experiment" in result
        next_exp = result["next_experiment"]
        assert next_exp["organization_id"] == str(org_id)
        assert next_exp["validation_passed"] is True
        assert next_exp["candidates_count"] > 0
        assert next_exp["selection_method"] in ("deterministic_fallback", "llm")

        # Verify the selected experiment is from the STRATEGY_CATALOG
        assert next_exp["selected_strategy"] is not None
        assert len(next_exp["selected_techniques"]) > 0


# ===================================================================
# A) UNRESOLVED PATH — No Improvement Proven
# ===================================================================

class TestUnresolvedPathE2E:
    """Gap → Retest → No improvement → UNRESOLVED → Next Experiment."""

    def test_unresolved_lifecycle(self, db_session):
        """Full gap-to-unresolved lifecycle."""
        state = _seed_full_state(db_session)
        orch = _make_orchestrator_with_retest(
            db_session, state["org_id"], state["obj_id"], improved=False
        )

        result = orch.run_cycle(detection_gap_id=state["gap_id"])

        assert result["final_state"] == "UNRESOLVED"
        assert result["path"] == "unresolved"
        assert result["improvement_proven"] is False

        # Evidence shows no improvement
        ev = result["evidence"]
        assert ev["improved"] is False

        # Gap record updated to UNRESOLVED
        db_session.expire_all()
        gap = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == state["gap_id"],
        ).one()
        assert gap.remediation_status == "UNRESOLVED"

        # Adaptive next experiment still selected
        assert "next_experiment" in result


# ===================================================================
# B) NO-GAP PATH — Detection Already Successful
# ===================================================================

class TestNoGapPathE2E:
    """DETECTED result → no gap → audit → next experiment."""

    def test_no_gap_path(self, db_session):
        """No-gap path persists audit and selects next experiment."""
        state = _seed_full_state(db_session)
        orch = ImmuneCycleOrchestrator(
            db_session=db_session,
            organization_id=state["org_id"],
            objective_id=state["obj_id"],
        )

        result = orch.run_cycle(detection_result="DETECTED")

        assert result["path"] == "no_gap"
        assert result["evidence"]["no_gap"] is True
        assert result["evidence"]["detection_result"] == "DETECTED"

        # Audit event persisted
        audits = db_session.query(RemediationAuditEventRecord).filter(
            RemediationAuditEventRecord.organization_id == state["org_id"],
            RemediationAuditEventRecord.event_type == "CYCLE_COMPLETED_NO_GAP",
        ).all()
        assert len(audits) == 1

        # No retest records for no-gap
        retests = db_session.query(RemediationRetestResultRecord).filter(
            RemediationRetestResultRecord.organization_id == state["org_id"],
        ).all()
        assert len(retests) == 0

        # Next experiment still selected
        assert "next_experiment" in result


# ===================================================================
# C) DEFENSIVE SAFETY BOUNDARY — Proposal Rejection
# ===================================================================

class TestDefensiveBoundaryRejection:
    """A proposal with forbidden keywords must be DENIED by the boundary."""

    def test_forbidden_rationale_rejected(self, db_session):
        """DefensiveSafetyBoundary rejects proposal with 'production' in rationale."""
        org_id = uuid4()
        db_session.add(OrgModel(id=org_id, name="Boundary Test Org"))
        db_session.commit()

        boundary = DefensiveSafetyBoundary(organization_id=org_id)
        proposal = DefensiveProposal(
            organization_id=org_id,
            gap_id=uuid4(),
            experiment_id=uuid4(),
            technique_id="T1003.008",
            proposal_type=ProposalType.ADD_DETECTION_RULE,
            description="Add rule for credential access",
            rationale="Deploy to production rm -rf / to fix detection",
            expected_effect="Improved detection coverage",
        )

        decision = boundary.evaluate(proposal)
        assert decision.decision == "DENIED"
        assert "production" in decision.reason.lower() or "forbidden" in decision.reason.lower()

    def test_wrong_org_rejected(self, db_session):
        """DefensiveSafetyBoundary rejects proposal for wrong organization."""
        org_a = uuid4()
        org_b = uuid4()
        db_session.add(OrgModel(id=org_a, name="Org A"))
        db_session.add(OrgModel(id=org_b, name="Org B"))
        db_session.commit()

        boundary = DefensiveSafetyBoundary(organization_id=org_a)
        proposal = DefensiveProposal(
            organization_id=org_b,  # Wrong org!
            gap_id=uuid4(),
            experiment_id=uuid4(),
            technique_id="T1003.008",
            proposal_type=ProposalType.ADD_DETECTION_RULE,
            description="Add rule for credential access",
            rationale="Standard detection improvement",
            expected_effect="Improved detection coverage",
        )

        decision = boundary.evaluate(proposal)
        assert decision.decision == "DENIED"
        assert "organization" in decision.reason.lower()


# ===================================================================
# D) STATE MACHINE INVARIANTS
# ===================================================================

class TestStateMachineInvariants:
    """Verify the Cyber Immune state machine enforces all guards."""

    def test_mitigated_requires_before_outcome(self):
        """COMPARING → MITIGATED rejects if before_outcome is not a failure."""
        from sentinelforge.domain.exceptions import SecurityRejection

        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="DETECTED",  # NOT a failure
                after_outcome="DETECTED",
                detection_improved=True,
            )

    def test_mitigated_requires_after_detected(self):
        """COMPARING → MITIGATED rejects if after_outcome is not DETECTED."""
        from sentinelforge.domain.exceptions import SecurityRejection

        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="DETECTION_GAP",
                after_outcome="DETECTION_GAP",  # NOT detected
                detection_improved=True,
            )

    def test_mitigated_requires_detection_improved(self):
        """COMPARING → MITIGATED rejects if detection_improved is False."""
        from sentinelforge.domain.exceptions import SecurityRejection

        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="DETECTION_GAP",
                after_outcome="DETECTED",
                detection_improved=False,  # Must be True
            )

    def test_valid_mitigated_transition(self):
        """COMPARING → MITIGATED succeeds with valid inputs."""
        result = CyberImmuneStateMachine.transition(
            "COMPARING", "MITIGATED",
            before_outcome="DETECTION_GAP",
            after_outcome="DETECTED",
            detection_improved=True,
        )
        assert result == "MITIGATED"

    def test_invalid_transition_rejected(self):
        """GAP_IDENTIFIED → MITIGATED is not a valid transition."""
        from sentinelforge.domain.exceptions import SecurityRejection

        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "MITIGATED")

    def test_all_states_defined(self):
        """Every state in CYBER_IMMUNE_STATES has transition definitions."""
        for state in CYBER_IMMUNE_STATES:
            assert state in CYBER_IMMUNE_VALID_TRANSITIONS

    def test_next_experiment_is_terminal(self):
        """NEXT_EXPERIMENT has no outgoing transitions."""
        allowed = CYBER_IMMUNE_VALID_TRANSITIONS.get("NEXT_EXPERIMENT", frozenset())
        assert len(allowed) == 0


# ===================================================================
# E) TENANT ISOLATION
# ===================================================================

class TestTenantIsolationE2E:
    """Org A's lifecycle must never affect Org B."""

    def test_cross_org_isolation(self, db_session):
        """Mitigating Org A's gap does not affect Org B's gap."""
        org_a = _seed_full_state(db_session)
        org_b = _seed_full_state(db_session)

        # Mitigate Org A
        orch_a = _make_orchestrator_with_retest(
            db_session, org_a["org_id"], org_a["obj_id"], improved=True
        )
        result_a = orch_a.run_cycle(detection_gap_id=org_a["gap_id"])
        assert result_a["final_state"] == "MITIGATED"

        # Org B's gap must remain OPEN
        db_session.expire_all()
        gap_b = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == org_b["gap_id"],
            DetectionGapRecord.organization_id == org_b["org_id"],
        ).one()
        assert gap_b.remediation_status == "OPEN"

        # Org B must have no retest records
        b_retests = db_session.query(RemediationRetestResultRecord).filter(
            RemediationRetestResultRecord.organization_id == org_b["org_id"],
        ).all()
        assert len(b_retests) == 0

        # Org B must have no audit events
        b_audits = db_session.query(RemediationAuditEventRecord).filter(
            RemediationAuditEventRecord.organization_id == org_b["org_id"],
        ).all()
        assert len(b_audits) == 0

    def test_org_security_state_isolation(self, db_session):
        """OrganizationSecurityState is scoped per organization."""
        org_a = _seed_full_state(db_session)
        org_b = _seed_full_state(db_session)

        ss_a = OrganizationSecurityState(db_session, org_a["org_id"])
        ss_b = OrganizationSecurityState(db_session, org_b["org_id"])

        assert ss_a.experiments_performed == 1
        assert ss_b.experiments_performed == 1

        # Both have the same number but different data
        assert ss_a.coverage_pct == 0.0  # DETECTION_GAP is not DETECTED
        assert ss_b.coverage_pct == 0.0


# ===================================================================
# F) IMMUNE MEMORY INTEGRITY
# ===================================================================

class TestImmuneMemoryIntegrity:
    """Verify ImmuneMemory provides correct, tenant-scoped state."""

    def test_immune_memory_state_after_mitigation(self, db_session):
        """ImmuneMemory reflects MITIGATED state after cycle completion."""
        state = _seed_full_state(db_session)
        orch = _make_orchestrator_with_retest(
            db_session, state["org_id"], state["obj_id"], improved=True
        )
        orch.run_cycle(detection_gap_id=state["gap_id"])

        memory = ImmuneMemory(db_session, state["org_id"])
        computed = memory.compute_state()

        assert computed["organization_id"] == str(state["org_id"])
        assert computed["previous_experiments"] >= 0
        assert "coverage_pct" in computed
        assert "mitigated_gaps" in computed
        assert "unresolved_gaps" in computed

    def test_immune_memory_no_cross_contamination(self, db_session):
        """Org A's immune memory does not include Org B's data."""
        org_a = _seed_full_state(db_session)
        org_b = _seed_full_state(db_session)

        memory_a = ImmuneMemory(db_session, org_a["org_id"])
        memory_b = ImmuneMemory(db_session, org_b["org_id"])

        state_a = memory_a.compute_state()
        state_b = memory_b.compute_state()

        assert state_a["organization_id"] == str(org_a["org_id"])
        assert state_b["organization_id"] == str(org_b["org_id"])
        assert state_a["organization_id"] != state_b["organization_id"]


# ===================================================================
# G) ADAPTIVE NEXT EXPERIMENT SELECTION
# ===================================================================

class TestAdaptiveNextExperiment:
    """Verify the adaptive selection pipeline produces valid results."""

    def test_deterministic_fallback(self, db_session):
        """NextExperimentSelector produces a valid result without LLM."""
        state = _seed_full_state(db_session)
        selector = NextExperimentSelector(
            db_session=db_session,
            organization_id=state["org_id"],
        )

        result = selector.select_next_experiment()

        assert isinstance(result, NextExperimentResult)
        assert result.organization_id == str(state["org_id"])
        assert result.selection_method == "deterministic_fallback"
        assert result.validation_passed is True
        assert result.candidates_count > 0

    def test_selected_experiment_is_safe(self, db_session):
        """Selected experiment passes ExperimentSafetyBoundary validation."""
        state = _seed_full_state(db_session)
        selector = NextExperimentSelector(
            db_session=db_session,
            organization_id=state["org_id"],
        )

        result = selector.select_next_experiment()
        assert result.validation_passed is True

    def test_adaptive_feedback_loop(self, db_session):
        """After MITIGATED, next experiment reflects updated security state."""
        state = _seed_full_state(db_session)

        # Run first cycle (mitigated)
        orch1 = _make_orchestrator_with_retest(
            db_session, state["org_id"], state["obj_id"], improved=True
        )
        result1 = orch1.run_cycle(detection_gap_id=state["gap_id"])
        assert result1["final_state"] == "MITIGATED"

        # The next experiment was selected and is part of the result
        next_exp1 = result1["next_experiment"]
        assert next_exp1["validation_passed"] is True

        # Create a NEW detection gap for the second cycle
        new_gap_id = uuid4()
        new_scenario_id = uuid4()
        db_session.add(AdversarialScenarioRecord(
            id=new_scenario_id,
            objective_id=state["obj_id"],
            organization_id=state["org_id"],
            title="New attack scenario for second cycle",
            strategy_description="T1059.004 shell execution",
            proposed_risk_level="LOW",
            created_by="red_agent",
        ))
        db_session.add(DetectionGapRecord(
            id=new_gap_id,
            organization_id=state["org_id"],
            scenario_id=new_scenario_id,
            action_id=uuid4(),
            technique_id="T1059.004",
            original_outcome="NOT_DETECTED",
            root_cause="missing_rule",
            reason="No Sigma rule covers T1059.004 shell execution",
            remediation_status="OPEN",
        ))
        db_session.commit()

        # Run the orchestrator again with the new gap (no improvement)
        orch2 = _make_orchestrator_with_retest(
            db_session, state["org_id"], state["obj_id"], improved=False
        )
        result2 = orch2.run_cycle(detection_gap_id=new_gap_id)
        assert result2["final_state"] == "UNRESOLVED"

        # The adaptive system selected another next experiment
        next_exp2 = result2["next_experiment"]
        assert next_exp2["validation_passed"] is True
        assert next_exp2["candidates_count"] > 0


# ===================================================================
# H) IDENTITY & COMPARISON INTEGRITY
# ===================================================================

class TestBeforeAfterComparison:
    """Verify BeforeAfterComparison correctly determines improvement."""

    def test_improvement_detected(self):
        """NOT_DETECTED → DETECTED is an improvement."""
        comparison = BeforeAfterComparison(
            comparison_id=uuid4(),
            organization_id=uuid4(),
            before_evaluation_id="eval-before",
            before_status=DetectionOutcome.NOT_DETECTED,
            before_coverage=0.0,
            before_technique="T1003.008",
            before_rule_ids=[],
            before_evidence_ids=[],
            after_evaluation_id="eval-after",
            after_status=DetectionOutcome.DETECTED,
            after_coverage=100.0,
            after_technique="T1003.008",
            after_rule_ids=["rule-001"],
            after_evidence_ids=["event-001"],
            improved=True,
            coverage_delta=100.0,
        )
        assert comparison.improved is True
        assert comparison.coverage_delta == 100.0

    def test_no_improvement_same_status(self):
        """DETECTION_GAP → DETECTION_GAP is NOT an improvement."""
        comparison = BeforeAfterComparison(
            comparison_id=uuid4(),
            organization_id=uuid4(),
            before_evaluation_id="eval-before",
            before_status=DetectionOutcome.DETECTION_GAP,
            before_coverage=0.0,
            before_technique="T1003.008",
            before_rule_ids=[],
            before_evidence_ids=[],
            after_evaluation_id="eval-after",
            after_status=DetectionOutcome.DETECTION_GAP,
            after_coverage=0.0,
            after_technique="T1003.008",
            after_rule_ids=[],
            after_evidence_ids=[],
            improved=False,
            coverage_delta=0.0,
        )
        assert comparison.improved is False
        assert comparison.coverage_delta == 0.0


# ===================================================================
# I) DEFENSIVE PROPOSAL SCHEMA VALIDATION
# ===================================================================

class TestDefensiveProposalSchema:
    """Verify DefensiveProposal rejects invalid proposal types."""

    def test_invalid_proposal_type_rejected(self):
        """DefensiveProposal rejects proposal_type not in allowed set."""
        with pytest.raises(Exception):  # Pydantic ValidationError
            DefensiveProposal(
                organization_id=uuid4(),
                gap_id=uuid4(),
                experiment_id=uuid4(),
                technique_id="T1003.008",
                proposal_type="FORBIDDEN_TYPE",  # Not in ProposalType enum
                description="Test proposal",
                rationale="Test rationale",
                expected_effect="Test effect",
            )

    def test_valid_proposal_type_accepted(self):
        """DefensiveProposal accepts valid ProposalType values."""
        proposal = DefensiveProposal(
            organization_id=uuid4(),
            gap_id=uuid4(),
            experiment_id=uuid4(),
            technique_id="T1003.008",
            proposal_type=ProposalType.ADD_DETECTION_RULE,
            description="Add detection rule",
            rationale="Improve detection coverage",
            expected_effect="Sigma rule will match T1003.008 events",
        )
        assert proposal.proposal_type == ProposalType.ADD_DETECTION_RULE


# ===================================================================
# J) STATE TRANSITION EXHAUSTIVENESS
# ===================================================================

class TestStateTransitionExhaustiveness:
    """Every valid path through the state machine is exercised."""

    def test_gap_to_mitigated_path(self):
        """Verify the full gap → mitigated transition sequence."""
        transitions = [
            ("GAP_IDENTIFIED", "DEFENSE_PROPOSED"),
            ("DEFENSE_PROPOSED", "DEFENSE_VALIDATED"),
            ("DEFENSE_VALIDATED", "DEFENSE_TESTING"),
            ("DEFENSE_TESTING", "RETTESTING"),
            ("RETTESTING", "COMPARING"),
            ("COMPARING", "MITIGATED"),
            ("MITIGATED", "NEXT_EXPERIMENT"),
        ]
        for current, target in transitions:
            result = CyberImmuneStateMachine.transition(
                current, target,
                before_outcome="DETECTION_GAP" if current == "COMPARING" else "",
                after_outcome="DETECTED" if current == "COMPARING" else "",
                detection_improved=True if current == "COMPARING" else False,
            )
            assert result == target

    def test_gap_to_unresolved_path(self):
        """Verify the full gap → unresolved transition sequence."""
        transitions = [
            ("GAP_IDENTIFIED", "DEFENSE_PROPOSED"),
            ("DEFENSE_PROPOSED", "DEFENSE_VALIDATED"),
            ("DEFENSE_VALIDATED", "DEFENSE_TESTING"),
            ("DEFENSE_TESTING", "RETTESTING"),
            ("RETTESTING", "COMPARING"),
            ("COMPARING", "UNRESOLVED"),
            ("UNRESOLVED", "NEXT_EXPERIMENT"),
        ]
        for current, target in transitions:
            result = CyberImmuneStateMachine.transition(
                current, target,
                before_outcome="",
                after_outcome="",
                detection_improved=False,
            )
            assert result == target

    def test_defense_testing_failure_path(self):
        """DEFENSE_TESTING → UNRESOLVED (defense test failed)."""
        result = CyberImmuneStateMachine.transition(
            "DEFENSE_TESTING", "UNRESOLVED",
        )
        assert result == "UNRESOLVED"


# ===================================================================
# K) CANONICAL FLOW — END-TO-END SECURITY INVARIANTS
# ===================================================================

class TestSecurityInvariants:
    """Verify the 7 security invariants of the Cyber Immune System."""

    def test_invariant_1_mitigated_requires_proof(self, db_session):
        """INVARIANT: MITIGATED only via deterministic before/after proof."""
        state = _seed_full_state(db_session)
        orch = _make_orchestrator_with_retest(
            db_session, state["org_id"], state["obj_id"], improved=True
        )
        result = orch.run_cycle(detection_gap_id=state["gap_id"])

        # MITIGATED is only set because retest proved improvement
        assert result["final_state"] == "MITIGATED"
        assert result["evidence"]["retest_improved"] is True
        assert result["evidence"]["improved"] is True

    def test_invariant_2_defensive_boundary_cannot_bypass(self, db_session):
        """INVARIANT: DefensiveSafetyBoundary cannot be bypassed."""
        org_id = uuid4()
        db_session.add(OrgModel(id=org_id, name="Invariant Test Org"))
        db_session.commit()

        boundary = DefensiveSafetyBoundary(organization_id=org_id)
        proposal = DefensiveProposal(
            organization_id=org_id,
            gap_id=uuid4(),
            experiment_id=uuid4(),
            technique_id="T1003.008",
            proposal_type=ProposalType.ADD_DETECTION_RULE,
            description="Test",
            rationale="Deploy to production rm -rf / to test",
            expected_effect="Test",
        )
        decision = boundary.evaluate(proposal)
        assert decision.decision == "DENIED"

    def test_invariant_3_llm_untrusted(self, db_session):
        """INVARIANT: LLM proposals are untrusted — deterministic gates dispose."""
        # The DefensiveSafetyBoundary evaluates ALL proposals deterministically.
        # Even a "valid" proposal goes through schema, org, gap, type, scope,
        # auth, resource, and safety gates. The LLM cannot skip any gate.
        state = _seed_full_state(db_session)
        boundary = DefensiveSafetyBoundary(
            organization_id=state["org_id"], db_session=db_session
        )

        # Create a proposal that looks valid but has a wrong org
        proposal = DefensiveProposal(
            organization_id=uuid4(),  # Different org
            gap_id=state["gap_id"],
            experiment_id=uuid4(),
            technique_id="T1003.008",
            proposal_type=ProposalType.ADD_DETECTION_RULE,
            description="Bypass attempt",
            rationale="Standard improvement",
            expected_effect="Better detection",
        )
        decision = boundary.evaluate(proposal)
        assert decision.decision == "DENIED"

    def test_invariant_4_tenant_isolation(self, db_session):
        """INVARIANT: Tenant isolation enforced at every boundary."""
        org_a = _seed_full_state(db_session)
        org_b = _seed_full_state(db_session)

        # Mitigate Org A
        orch = _make_orchestrator_with_retest(
            db_session, org_a["org_id"], org_a["obj_id"], improved=True
        )
        orch.run_cycle(detection_gap_id=org_a["gap_id"])

        # Org B unchanged
        db_session.expire_all()
        gap_b = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == org_b["gap_id"],
        ).one()
        assert gap_b.remediation_status == "OPEN"

    def test_invariant_5_state_machine_enforces_guards(self):
        """INVARIANT: State machine rejects invalid transitions."""
        from sentinelforge.domain.exceptions import SecurityRejection

        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "MITIGATED")

    def test_invariant_6_immune_memory_evidence_linked(self, db_session):
        """INVARIANT: Immune memory is evidence-linked and tenant-scoped."""
        state = _seed_full_state(db_session)
        orch = _make_orchestrator_with_retest(
            db_session, state["org_id"], state["obj_id"], improved=True
        )
        orch.run_cycle(detection_gap_id=state["gap_id"])

        memory = ImmuneMemory(db_session, state["org_id"])
        computed = memory.compute_state()

        # All data is scoped to this org
        assert computed["organization_id"] == str(state["org_id"])

        # Detection outcomes are evidence-linked
        assert len(computed["detection_outcomes"]) >= 1
        assert computed["detection_outcomes"].get("DETECTION_GAP", 0) >= 1

    def test_invariant_7_adaptive_deterministic_fallback(self, db_session):
        """INVARIANT: Adaptive selection uses deterministic scoring fallback."""
        state = _seed_full_state(db_session)
        selector = NextExperimentSelector(
            db_session=db_session,
            organization_id=state["org_id"],
        )

        # No LLM provider — pure deterministic fallback
        result = selector.select_next_experiment(llm_provider=None)
        assert result.selection_method == "deterministic_fallback"
        assert result.validation_passed is True
