import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sentinelforge.domain.experiment import (
    SecurityObjective,
    AdversarialScenario,
    ExecutionPlan,
    ExperimentConstraints,
    RiskLevel,
    PolicyDecisionStatus,
)
from sentinelforge.domain.action_ir import ActionIR, ActionType
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary


def test_experiment_domain_models():
    org_id = uuid.uuid4()
    obj = SecurityObjective(
        organization_id=org_id,
        title="Credential Access Coverage",
        description="Verify detection of /etc/shadow access attempts",
    )
    assert obj.title == "Credential Access Coverage"
    assert obj.default_risk_level == RiskLevel.MEDIUM

    scenario = AdversarialScenario(
        objective_id=obj.objective_id,
        organization_id=org_id,
        title="Read Shadow File via Cat",
        strategy_description="Execute cat /etc/shadow in target container",
        technique_ids=["T1003.008"],
        proposed_risk_level=RiskLevel.MEDIUM,
    )
    assert scenario.proposed_risk_level == RiskLevel.MEDIUM
    assert "T1003.008" in scenario.technique_ids


def test_safety_boundary_scenario_evaluation():
    org_id = uuid.uuid4()
    boundary = ExperimentSafetyBoundary(
        constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM)
    )

    # Allowed scenario
    scenario_ok = AdversarialScenario(
        objective_id=uuid.uuid4(),
        organization_id=org_id,
        title="Low Risk Test",
        strategy_description="Read file",
        technique_ids=["T1059"],
        proposed_risk_level=RiskLevel.LOW,
    )
    decision_ok = boundary.evaluate_scenario(scenario_ok)
    assert decision_ok.status == PolicyDecisionStatus.ALLOWED

    # Denied scenario (risk too high)
    scenario_high = AdversarialScenario(
        objective_id=uuid.uuid4(),
        organization_id=org_id,
        title="High Risk Test",
        strategy_description="Critical test",
        technique_ids=["T1059"],
        proposed_risk_level=RiskLevel.HIGH,
    )
    decision_denied = boundary.evaluate_scenario(scenario_high)
    assert decision_denied.status == PolicyDecisionStatus.DENIED
    assert "exceeds maximum permitted risk" in decision_denied.reason


def test_safety_boundary_action_ir_evaluation():
    org_id = uuid.uuid4()
    boundary = ExperimentSafetyBoundary()

    now = datetime.now(timezone.utc)
    valid_ir = ActionIR(
        action_id=uuid.uuid4(),
        blueprint_id=uuid.uuid4(),
        technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        run_as_user="labuser",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    decision = boundary.evaluate_action_ir(valid_ir, org_id=org_id, current_time=now)
    assert decision.status == PolicyDecisionStatus.ALLOWED

    # Unauthorized target
    invalid_target_ir = ActionIR(
        action_id=uuid.uuid4(),
        blueprint_id=uuid.uuid4(),
        technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC,
        target="unauthorized-host",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        run_as_user="labuser",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    decision_target = boundary.evaluate_action_ir(invalid_target_ir, org_id=org_id, current_time=now)
    assert decision_target.status == PolicyDecisionStatus.DENIED
    assert "not in authorized targets list" in decision_target.reason


def test_action_ir_constraint_fields_and_signing():
    now = datetime.now(timezone.utc)
    ir = ActionIR(
        action_id=uuid.uuid4(),
        blueprint_id=uuid.uuid4(),
        technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        run_as_user="labuser",
        max_execution_seconds=45,
        max_stdout_bytes=32 * 1024,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    assert ir.max_execution_seconds == 45
    assert ir.max_stdout_bytes == 32 * 1024

    # Serialization / Deserialization round-trip
    data = ir.model_dump()
    reconstructed = ActionIR.model_validate(data)
    assert reconstructed.max_execution_seconds == 45
    assert reconstructed.max_stdout_bytes == 32 * 1024

    # Validation limits
    with pytest.raises(Exception):
        ActionIR(
            action_id=uuid.uuid4(),
            blueprint_id=uuid.uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            max_execution_seconds=9999,  # Exceeds max limit 300
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )

    # Blueprint HMAC signing compatibility
    from sentinelforge.policy.signing import BlueprintSigner
    signer = BlueprintSigner(key="testkey", key_id="key1")
    signed_bp = signer.sign(
        blueprint_id=ir.blueprint_id,
        action_id=ir.action_id,
        technique_id=ir.technique_id,
        target=ir.target,
        executable=ir.executable,
        arguments=ir.arguments,
        run_as_user=ir.run_as_user,
        issued_at=ir.issued_at,
        expires_at=ir.expires_at,
    )
    assert signer.verify(signed_bp) is True


def test_unicode_nfc_normalization_and_homoglyph_distinction():
    from sentinelforge.detection.normalizer import TelemetryNormalizer
    import unicodedata

    normalizer = TelemetryNormalizer()
    
    # 1. NFC normalization of combined accents (e.g. 'e' + combining acute accent -> 'é')
    decomposed = "e\u0301"  # 'e' + combining acute
    sanitized = normalizer._sanitize_string(decomposed)
    assert sanitized == "\u00e9"  # Precomposed 'é' (NFC)

    # 2. Security invariant check: NFC does NOT collapse cross-script homoglyphs
    latin_a = "a"         # Latin 'a' (U+0061)
    cyrillic_a = "\u0430"  # Cyrillic 'а' (U+0430)
    
    norm_latin = normalizer._sanitize_string(latin_a)
    norm_cyrillic = normalizer._sanitize_string(cyrillic_a)

    # Verifies NFC does NOT collapse distinct characters into each other
    assert norm_latin != norm_cyrillic
    assert norm_latin == "a"
    assert norm_cyrillic == "\u0430"
    assert ord(norm_latin) != ord(norm_cyrillic)


def test_container_adapter_cleanup():
    from sentinelforge.simulation.adapter import ContainerLinuxAdapter
    from unittest.mock import Mock

    mock_client = Mock()
    mock_client.execute_bounded.return_value = (0, b"", b"", False, False)
    adapter = ContainerLinuxAdapter(docker_client=mock_client)
    adapter.cleanup()

    mock_client.execute_bounded.assert_called_once_with(
        executable="/usr/bin/bash",
        arguments=["-c", "rm -rf /tmp/sentinelforge_* 2>/dev/null || true"],
        run_as_user="labuser",
        timeout=10,
    )


def test_policy_decision_and_detection_gap_persistence():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sentinelforge.db.models import Base, Organization, PolicyDecisionRecord, DetectionGapRecord, RetestResult
    from sentinelforge.domain.experiment import PolicyDecision, PolicyDecisionStatus

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()

    org_id = uuid.uuid4()
    org = Organization(id=org_id, name="TestOrg")
    s.add(org)
    s.commit()

    # PolicyDecisionRecord persistence
    boundary = ExperimentSafetyBoundary()
    dec = PolicyDecision(
        organization_id=org_id,
        scenario_id=uuid.uuid4(),
        status=PolicyDecisionStatus.ALLOWED,
        reason="Authorized by boundary",
    )
    rec = boundary.record_decision(s, dec)
    assert rec is not None
    assert s.query(PolicyDecisionRecord).count() == 1

    # DetectionGapRecord persistence
    gap_id = uuid.uuid4()
    scen_id = uuid.uuid4()
    act_id = uuid.uuid4()
    gap_rec = DetectionGapRecord(
        id=gap_id,
        organization_id=org_id,
        scenario_id=scen_id,
        action_id=act_id,
        technique_id="T1003.008",
        original_outcome="DETECTION_GAP",
        root_cause="NO_RULE_MATCH",
        reason="No rule matched",
    )
    s.add(gap_rec)
    s.commit()

    retrieved_gap = s.query(DetectionGapRecord).filter_by(id=gap_id).first()
    assert retrieved_gap is not None
    assert retrieved_gap.technique_id == "T1003.008"
    assert retrieved_gap.remediation_status == "OPEN"

    # RetestResult updated schema verification
    retest = RetestResult(
        organization_id=org_id,
        scenario_id=scen_id,
        before_outcome="DETECTION_GAP",
        after_outcome="DETECTED",
        detection_improved="True",
        validated_rule_ids='["rule1"]',
    )
    s.add(retest)
    s.commit()

    retrieved_retest = s.query(RetestResult).filter_by(organization_id=org_id).first()
    assert retrieved_retest is not None
    assert str(retrieved_retest.scenario_id) == str(scen_id)
    assert retrieved_retest.before_outcome == "DETECTION_GAP"

