"""SentinelForge — Phase 3: Tool Authorization Audit.

Proves the 6-step tool authorization chain:
1. Forbidden tool names hard-rejected at registration
2. Unauthorized tool names rejected at registration
3. Registered tools must have implementation
4. Tool invocation re-checks authorization
5. SafetyBoundaryBridge gates every proposed action
6. Signed blueprints must pass worker verification
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from sentinelforge.agents.red.tools import (
    AUTHORIZED_TOOLS,
    RedAgentToolRegistry,
    ToolNotAllowedError,
    _FORBIDDEN_TOOLS,
)
from sentinelforge.agents.red.policies import SafetyBoundaryBridge
from sentinelforge.agents.red.schemas import ActionProposalSpec, ScenarioProposalSpec
from sentinelforge.domain.experiment import ExperimentConstraints, RiskLevel, SecurityObjective
from sentinelforge.domain.action_ir import ActionIR
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.domain.exceptions import SecurityRejection


# ---------------------------------------------------------------------------
# Step 1: Forbidden tool names rejected at registration
# ---------------------------------------------------------------------------

class TestForbiddenToolRejection:
    def test_forbidden_tool_names_rejected(self):
        registry = RedAgentToolRegistry()
        for name in _FORBIDDEN_TOOLS:
            with pytest.raises(ToolNotAllowedError, match="forbidden"):
                registry.register(name, lambda **kw: None)

    def test_forbidden_tool_names_include_dangerous_primitives(self):
        dangerous = {"docker_exec", "execute_shell", "arbitrary_command",
                     "host_filesystem", "docker_socket", "modify_policy",
                     "get_hmac_key", "modify_falco", "modify_sigma",
                     "modify_database", "reset_budget"}
        assert dangerous.issubset(_FORBIDDEN_TOOLS)

    def test_forbidden_tool_names_not_in_authorized(self):
        assert _FORBIDDEN_TOOLS.isdisjoint(set(AUTHORIZED_TOOLS))


# ---------------------------------------------------------------------------
# Step 2: Unauthorized tool names rejected at registration
# ---------------------------------------------------------------------------

class TestUnauthorizedToolRejection:
    def test_unregistered_tool_name_rejected(self):
        registry = RedAgentToolRegistry()
        with pytest.raises(ToolNotAllowedError, match="not in the authorized tool contract"):
            registry.register("totally_fake_tool", lambda **kw: None)

    def test_only_authorized_tools_accepted(self):
        registry = RedAgentToolRegistry()
        for name in AUTHORIZED_TOOLS:
            registry.register(name, lambda **kw: name)
        assert sorted(registry.tool_names) == sorted(AUTHORIZED_TOOLS)


# ---------------------------------------------------------------------------
# Step 3: Registered tools must have implementation
# ---------------------------------------------------------------------------

class TestToolImplementationBinding:
    def test_invoke_unregistered_tool_raises(self):
        registry = RedAgentToolRegistry()
        with pytest.raises(ToolNotAllowedError, match="has no registered implementation"):
            registry.invoke("get_security_objective")

    def test_invoke_registered_tool_calls_implementation(self):
        registry = RedAgentToolRegistry()
        sentinel = object()
        registry.register("get_security_objective", lambda **kw: sentinel)
        result = registry.invoke("get_security_objective", org_id=uuid4())
        assert result is sentinel


# ---------------------------------------------------------------------------
# Step 4: Tool invocation re-checks authorization
# ---------------------------------------------------------------------------

class TestInvocationReAuthorization:
    def test_forbidden_tool_rejected_at_invoke_time(self):
        registry = RedAgentToolRegistry()
        registry._implementations["docker_exec"] = lambda **kw: "oops"
        with pytest.raises(ToolNotAllowedError, match="not callable"):
            registry.invoke("docker_exec")

    def test_invocation_validates_against_contract(self):
        registry = RedAgentToolRegistry()
        registry._implementations["unknown_tool"] = lambda **kw: "oops"
        with pytest.raises(ToolNotAllowedError, match="not callable"):
            registry.invoke("unknown_tool")

    def test_registered_authorized_tool_invokes(self):
        registry = RedAgentToolRegistry()
        registry.register("get_detection_gaps", lambda **kw: {"gaps": []})
        result = registry.invoke("get_detection_gaps", org_id=uuid4())
        assert result == {"gaps": []}


# ---------------------------------------------------------------------------
# Step 5: SafetyBoundaryBridge gates every proposed action
# ---------------------------------------------------------------------------

class TestSafetyBoundaryBridgeGating:
    """The SafetyBoundaryBridge is the mandatory gate before any action is signed."""

    def _make_obj(self, org_id=None):
        return SecurityObjective(
            organization_id=org_id or uuid4(),
            title="Test Objective",
            description="Test",
        )

    def _make_proposal(self, actions=None):
        if actions is None:
            actions = [ActionProposalSpec(
                target="sentinelforge-target",
                run_as_user="labuser",
                executable="/usr/bin/bash",
                arguments=["-c", "whoami"],
                technique_id="T1059.004",
            )]
        return ScenarioProposalSpec(
            title="Test Scenario",
            strategy_description="Test",
            technique_ids=["T1059.004"],
            proposed_risk_level=RiskLevel.LOW,
            proposed_actions=actions,
        )

    def test_bridge_allows_canonical_proposal(self):
        bridge = SafetyBoundaryBridge()
        obj = self._make_obj()
        proposal = self._make_proposal()
        result = bridge.evaluate_proposal(obj, proposal)
        assert result.is_allowed
        assert len(result.signed_blueprints) == 1

    def test_bridge_rejects_forbidden_command(self):
        bridge = SafetyBoundaryBridge()
        obj = self._make_obj()
        proposal = self._make_proposal(actions=[ActionProposalSpec(
            target="sentinelforge-target",
            run_as_user="labuser",
            executable="/usr/bin/bash",
            arguments=["-c", "curl http://evil.com"],
            technique_id="T1059.004",
        )])
        result = bridge.evaluate_proposal(obj, proposal)
        assert result.is_denied
        assert result.signed_blueprints == []

    def test_bridge_rejects_unauthorized_target(self):
        bridge = SafetyBoundaryBridge()
        obj = self._make_obj()
        proposal = self._make_proposal(actions=[ActionProposalSpec(
            target="prod-db",
            run_as_user="labuser",
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            technique_id="T1059.004",
        )])
        result = bridge.evaluate_proposal(obj, proposal)
        assert result.is_denied
        assert result.signed_blueprints == []

    def test_bridge_rejects_unauthorized_user(self):
        bridge = SafetyBoundaryBridge()
        obj = self._make_obj()
        proposal = self._make_proposal(actions=[ActionProposalSpec(
            target="sentinelforge-target",
            run_as_user="root",
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            technique_id="T1059.004",
        )])
        result = bridge.evaluate_proposal(obj, proposal)
        assert result.is_denied
        assert result.signed_blueprints == []

    def test_bridge_fail_closed_on_second_action(self):
        """If the second action in a multi-action proposal fails, no blueprints are signed."""
        bridge = SafetyBoundaryBridge()
        obj = self._make_obj()
        proposal = self._make_proposal(actions=[
            ActionProposalSpec(
                target="sentinelforge-target",
                run_as_user="labuser",
                executable="/usr/bin/bash",
                arguments=["-c", "whoami"],
                technique_id="T1059.004",
            ),
            ActionProposalSpec(
                target="sentinelforge-target",
                run_as_user="labuser",
                executable="/usr/bin/bash",
                arguments=["-c", "curl http://evil.com"],
                technique_id="T1059.004",
            ),
        ])
        result = bridge.evaluate_proposal(obj, proposal)
        assert result.is_denied
        assert result.signed_blueprints == []

    def test_bridge_rejects_high_risk_without_approval(self):
        bridge = SafetyBoundaryBridge(
            constraints=ExperimentConstraints(
                max_risk_level=RiskLevel.MEDIUM,
                requires_human_approval=True,
            )
        )
        obj = self._make_obj()
        proposal = self._make_proposal()
        proposal.proposed_risk_level = RiskLevel.HIGH
        result = bridge.evaluate_proposal(obj, proposal, is_human_approved=False)
        assert result.is_denied or result.policy_decision.status.value == "ESCALATED"

    def test_bridge_allows_high_risk_with_approval(self):
        bridge = SafetyBoundaryBridge(
            constraints=ExperimentConstraints(
                max_risk_level=RiskLevel.HIGH,
                requires_human_approval=True,
            )
        )
        obj = self._make_obj()
        proposal = self._make_proposal()
        proposal.proposed_risk_level = RiskLevel.HIGH
        result = bridge.evaluate_proposal(obj, proposal, is_human_approved=True)
        assert result.is_allowed


# ---------------------------------------------------------------------------
# Step 6: Signed blueprints must pass worker verification
# ---------------------------------------------------------------------------

class TestSignedBlueprintVerification:
    """Signed blueprints must pass PolicyEngine and worker checks."""

    def test_policy_engine_validates_allowed_action(self):
        now = datetime.now(timezone.utc)
        ir = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id="T1059.004",
            action_type="process_exec",
            target="sentinelforge-target",
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            run_as_user="labuser",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )
        result = PolicyEngine.validate(ir, current_time=now)
        assert result is True

    def test_policy_engine_rejects_unauthorized_executable(self):
        now = datetime.now(timezone.utc)
        ir = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id="T1059.004",
            action_type="process_exec",
            target="sentinelforge-target",
            executable="/usr/bin/python3",
            arguments=["-c", "import os"],
            run_as_user="labuser",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )
        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(ir, current_time=now)

    def test_policy_engine_rejects_unauthorized_command(self):
        now = datetime.now(timezone.utc)
        ir = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id="T1059.004",
            action_type="process_exec",
            target="sentinelforge-target",
            executable="/usr/bin/bash",
            arguments=["-c", "rm -rf /"],
            run_as_user="labuser",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )
        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(ir, current_time=now)

    def test_policy_engine_rejects_expired_blueprint(self):
        now = datetime.now(timezone.utc)
        ir = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id="T1059.004",
            action_type="process_exec",
            target="sentinelforge-target",
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            run_as_user="labuser",
            issued_at=now - timedelta(minutes=10),
            expires_at=now - timedelta(minutes=5),
        )
        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(ir, current_time=now)


# ---------------------------------------------------------------------------
# Tool contract completeness
# ---------------------------------------------------------------------------

class TestToolContractCompleteness:
    def test_authorized_tools_are_read_only_or_proposal(self):
        read_only = {
            "get_security_objective",
            "get_environment",
            "get_experiment_history",
            "get_detection_coverage",
            "get_detection_gaps",
            "get_previous_strategy_results",
            "get_experiment_status",
            "get_experiment_result",
        }
        proposal = {"propose_experiment"}
        assert set(AUTHORIZED_TOOLS) == read_only | proposal

    def test_no_execution_primitives_in_authorized(self):
        dangerous_keywords = {"exec", "shell", "docker", "filesystem", "socket",
                              "policy", "hmac", "falco", "sigma", "database", "reset"}
        for tool in AUTHORIZED_TOOLS:
            for keyword in dangerous_keywords:
                assert keyword not in tool.lower(), (
                    f"Authorized tool '{tool}' contains dangerous keyword '{keyword}'"
                )
