"""SentinelForge Phase 4 — Red Agent Objective-Driven Adversarial Scenario Planner & Safety Pipeline

Objective-driven adversarial planner that transforms a SecurityObjective into
AdversarialScenario, ExecutionPlan, and ActionIR representations, subjecting
every generated scenario and action to deterministic authorization via
ExperimentSafetyBoundary prior to blueprint signing.

CRITICAL SECURITY CONTROL:
The Red Agent AI / planning layer operates strictly ABOVE the deterministic safety boundary.
No SignedBlueprint can be generated or signed without passing through
ExperimentSafetyBoundary and PolicyEngine evaluation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from sentinelforge.domain.action_ir import ActionIR, ActionType
from sentinelforge.domain.blueprint import SignedBlueprint
from sentinelforge.domain.experiment import (
    AdversarialScenario,
    ExecutionPlan,
    ExperimentConstraints,
    PolicyDecision,
    PolicyDecisionStatus,
    RiskLevel,
    SecurityObjective,
)
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.policy.signing import BlueprintSigner


# Deterministic strategy catalog mapping objectives/strategies to constrained actions
STRATEGY_CATALOG: Dict[str, dict] = {
    "bash_exec_whoami": {
        "title": "Adversarial Reconnaissance via Shell Execution",
        "description": "Explores system environment by executing basic identity discovery.",
        "technique_ids": ["T1059.004"],  # Command and Scripting Interpreter: Unix Shell
        "proposed_risk_level": RiskLevel.LOW,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "whoami"],
                "technique_id": "T1059.004",
            }
        ],
    },
    "bash_exec_id": {
        "title": "User Context Discovery",
        "description": "Determines user ID and group memberships on the host.",
        "technique_ids": ["T1033", "T1059.004"],  # System Owner/User Discovery
        "proposed_risk_level": RiskLevel.LOW,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "id"],
                "technique_id": "T1033",
            }
        ],
    },
    "credential_dump_shadow": {
        "title": "OS Credential Access Attempt",
        "description": "Attempts unauthorized access to sensitive credential file.",
        "technique_ids": ["T1003.008"],  # OS Credential Dumping: /etc/shadow
        "proposed_risk_level": RiskLevel.HIGH,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "cat /etc/shadow"],
                "technique_id": "T1003.008",
            }
        ],
    },
    "file_cleanup": {
        "title": "Indicator Removal on Host",
        "description": "Cleans up temporary evidence log file.",
        "technique_ids": ["T1070.004"],  # File Deletion
        "proposed_risk_level": RiskLevel.LOW,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "rm /tmp/sentinelforge_test_evidence.log"],
                "technique_id": "T1070.004",
            }
        ],
    },
    "unauthorized_destructive_cmd": {
        "title": "Unauthorized Destructive Activity",
        "description": "Attempts catastrophic filesystem destruction.",
        "technique_ids": ["T1485"],  # Data Destruction
        "proposed_risk_level": RiskLevel.CRITICAL,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "rm -rf /"],
                "technique_id": "T1485",
            }
        ],
    },
    "multi_step_recon_and_dump": {
        "title": "Multi-Step Reconnaissance and Credential Access",
        "description": "Executes identity discovery followed by shadow file access attempt.",
        "technique_ids": ["T1059.004", "T1003.008"],
        "proposed_risk_level": RiskLevel.HIGH,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "whoami"],
                "technique_id": "T1059.004",
            },
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "cat /etc/shadow"],
                "technique_id": "T1003.008",
            },
        ],
    },
    "multi_step_with_one_unauthorized": {
        "title": "Multi-Step Plan with One Unauthorized Action",
        "description": "Valid identity check followed by unauthorized destructive command.",
        "technique_ids": ["T1059.004", "T1485"],
        "proposed_risk_level": RiskLevel.MEDIUM,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "whoami"],
                "technique_id": "T1059.004",
            },
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "rm -rf /"],
                "technique_id": "T1485",
            },
        ],
    },
    # --- Web Application Testing Strategies (Upgrade 5) ---
    "web_sql_injection_login": {
        "title": "SQL Injection via Login Form",
        "description": "Tests SQL injection vulnerability in the login endpoint of the controlled vulnerable web application.",
        "technique_ids": ["T1190"],  # Exploit Public-Facing Application
        "proposed_risk_level": RiskLevel.MEDIUM,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": [
                    "-c",
                    "curl -s -X POST http://vulnerable-app:5000/login -d \"username=admin&password=admin123\"",
                ],
                "technique_id": "T1190",
            }
        ],
    },
    "web_command_injection": {
        "title": "Command Injection via Ping Endpoint",
        "description": "Tests command injection vulnerability in the ping endpoint of the controlled vulnerable web application.",
        "technique_ids": ["T1059"],  # Command and Scripting Interpreter
        "proposed_risk_level": RiskLevel.MEDIUM,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": [
                    "-c",
                    "curl -s -X POST http://vulnerable-app:5000/api/ping -H Content-Type: application/json -d {\"host\":\"127.0.0.1\"}",
                ],
                "technique_id": "T1059",
            }
        ],
    },
    "web_path_traversal": {
        "title": "Path Traversal via File Read Endpoint",
        "description": "Tests path traversal vulnerability in the file read endpoint of the controlled vulnerable web application.",
        "technique_ids": ["T1083"],  # File and Directory Discovery
        "proposed_risk_level": RiskLevel.MEDIUM,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": [
                    "-c",
                    "curl -s -X POST http://vulnerable-app:5000/api/files/read -H Content-Type: application/json -d {\"path\":\"/etc/hostname\"}",
                ],
                "technique_id": "T1083",
            }
        ],
    },
    "web_search_sqli": {
        "title": "SQL Injection via Search API",
        "description": "Tests SQL injection vulnerability in the search endpoint of the controlled vulnerable web application.",
        "technique_ids": ["T1190"],
        "proposed_risk_level": RiskLevel.MEDIUM,
        "actions": [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": [
                    "-c",
                    "curl -s -X POST http://vulnerable-app:5000/api/search -H Content-Type: application/json -d {\"q\":\"test\"}",
                ],
                "technique_id": "T1190",
            }
        ],
    },
}


@dataclass
class PlanResult:
    """Result of an adversarial scenario planning and safety authorization pass."""
    scenario: AdversarialScenario
    execution_plan: ExecutionPlan
    actions: List[ActionIR] = field(default_factory=list)
    policy_decision: PolicyDecision = None
    signed_blueprints: List[SignedBlueprint] = field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        return self.policy_decision is not None and self.policy_decision.status == PolicyDecisionStatus.ALLOWED

    @property
    def action_ir(self) -> Optional[ActionIR]:
        return self.actions[0] if self.actions else None

    @property
    def signed_blueprint(self) -> Optional[SignedBlueprint]:
        return self.signed_blueprints[0] if self.signed_blueprints else None


class RedAgentPlanner:
    """Objective-Driven Red Agent Adversarial Scenario Planner.

    Generates structured scenarios from security objectives and validates
    all strategy actions through the deterministic ExperimentSafetyBoundary
    before producing signed blueprints.
    """

    def __init__(
        self,
        signer: Optional[BlueprintSigner] = None,
        safety_boundary: Optional[ExperimentSafetyBoundary] = None,
        signing_key: Optional[str] = None,
        key_id: str = "key1",
    ):
        from sentinelforge.agents.red.policies import _resolve_signing_key
        resolved_key = _resolve_signing_key(signing_key=signing_key, signer=signer)
        self.signer = signer or BlueprintSigner(key=resolved_key, key_id=key_id)
        self.default_safety_boundary = safety_boundary or ExperimentSafetyBoundary()

    def plan_scenario(
        self,
        objective: SecurityObjective,
        strategy_type: str = "bash_exec_whoami",
        constraints: Optional[ExperimentConstraints] = None,
        proposed_risk_level: Optional[RiskLevel] = None,
        is_human_approved: bool = False,
        custom_command: Optional[dict] = None,
    ) -> PlanResult:
        """Transform a SecurityObjective into a validated, signed experiment blueprint.

        Args:
            objective: High-level security objective defining target scope.
            strategy_type: Approved strategy name from STRATEGY_CATALOG.
            constraints: Custom experiment constraints overriding default safety boundary.
            proposed_risk_level: Override for scenario risk level.
            is_human_approved: Flag indicating whether human approval was granted.
            custom_command: Optional explicit command dictionary for testing custom vectors.

        Returns:
            PlanResult containing scenario, plan, actions, policy decision, and optional signed blueprints.
        """
        boundary = ExperimentSafetyBoundary(constraints) if constraints else self.default_safety_boundary

        # 1. Resolve strategy parameters from deterministic catalog
        if custom_command:
            strat_info = custom_command
            action_specs = [
                {
                    "target": custom_command.get("target", "sentinelforge-target"),
                    "run_as_user": custom_command.get("run_as_user", "labuser"),
                    "executable": custom_command.get("executable", "/usr/bin/bash"),
                    "arguments": custom_command.get("arguments", ["-c", custom_command.get("command", "whoami")]),
                    "technique_id": custom_command.get("technique_ids", ["T1059.004"])[0],
                }
            ]
        elif strategy_type in STRATEGY_CATALOG:
            strat_info = STRATEGY_CATALOG[strategy_type]
            action_specs = strat_info.get("actions", [])
        else:
            # Fallback constrained template for unlisted strategy_type
            strat_info = {
                "title": f"Custom Strategy: {strategy_type}",
                "description": f"Custom adversarial strategy for objective {objective.title}",
                "technique_ids": ["T1059.004"],
                "proposed_risk_level": proposed_risk_level or RiskLevel.MEDIUM,
            }
            target_host = boundary.constraints.allowed_targets[0] if boundary.constraints.allowed_targets else "sentinelforge-target"
            target_user = boundary.constraints.allowed_users[0] if boundary.constraints.allowed_users else "labuser"
            action_specs = [
                {
                    "target": target_host,
                    "run_as_user": target_user,
                    "executable": f"/usr/bin/{strategy_type}",
                    "arguments": [],
                    "technique_id": "T1059.004",
                }
            ]

        risk_lvl = proposed_risk_level or strat_info.get("proposed_risk_level", RiskLevel.MEDIUM)

        # 2. Build AdversarialScenario
        scenario = AdversarialScenario(
            scenario_id=uuid4(),
            objective_id=objective.objective_id,
            organization_id=objective.organization_id,
            title=strat_info.get("title", f"Scenario for {objective.title}"),
            strategy_description=strat_info.get("description", "Adversarial exploration strategy"),
            technique_ids=strat_info.get("technique_ids", ["T1059.004"]),
            proposed_risk_level=risk_lvl,
            created_by="red_agent_planner",
        )

        # 3. Evaluate Scenario against ExperimentSafetyBoundary
        scenario_decision = boundary.evaluate_scenario(scenario, is_human_approved=is_human_approved)
        if scenario_decision.status != PolicyDecisionStatus.ALLOWED:
            execution_plan = ExecutionPlan(
                scenario_id=scenario.scenario_id,
                organization_id=objective.organization_id,
                steps_description=f"REJECTED at scenario level: {scenario_decision.reason}",
                status="REJECTED",
            )
            return PlanResult(
                scenario=scenario,
                execution_plan=execution_plan,
                actions=[],
                policy_decision=scenario_decision,
                signed_blueprints=[],
            )

        # 4. Build Candidate ActionIR actions & ExecutionPlan
        now = datetime.now(timezone.utc)
        candidate_actions: List[ActionIR] = []
        steps_desc: List[str] = []

        for spec in action_specs:
            action_ir = ActionIR(
                action_id=uuid4(),
                blueprint_id=uuid4(),
                technique_id=spec.get("technique_id", scenario.technique_ids[0] if scenario.technique_ids else "T1059.004"),
                action_type=ActionType.PROCESS_EXEC,
                target=spec["target"],
                run_as_user=spec["run_as_user"],
                executable=spec["executable"],
                arguments=spec.get("arguments", []),
                max_execution_seconds=boundary.constraints.max_execution_seconds,
                max_stdout_bytes=boundary.constraints.max_stdout_bytes,
                issued_at=now,
                expires_at=now + timedelta(seconds=30),
            )
            candidate_actions.append(action_ir)
            cmd_repr = " ".join(action_ir.arguments) if action_ir.arguments else action_ir.executable
            steps_desc.append(f"Execute '{cmd_repr}' on {action_ir.target} as {action_ir.run_as_user}")

        execution_plan = ExecutionPlan(
            scenario_id=scenario.scenario_id,
            organization_id=objective.organization_id,
            steps_description="; ".join(steps_desc),
            status="DRAFT",
        )

        # 5. Evaluate ALL ActionIR actions against ExperimentSafetyBoundary and PolicyEngine
        for action_ir in candidate_actions:
            action_decision = boundary.evaluate_action_ir(action_ir, org_id=objective.organization_id, current_time=now)
            if action_decision.status != PolicyDecisionStatus.ALLOWED:
                execution_plan.status = "REJECTED"
                execution_plan.steps_description += f" | REJECTED at ActionIR level: {action_decision.reason}"
                return PlanResult(
                    scenario=scenario,
                    execution_plan=execution_plan,
                    actions=candidate_actions,
                    policy_decision=action_decision,
                    signed_blueprints=[],  # NONE signed if ANY action fails!
                )

        # 6. ALL actions ALLOWED -> Sign Blueprints
        signed_blueprints: List[SignedBlueprint] = []
        for action_ir in candidate_actions:
            signed_bp = self.signer.sign(
                blueprint_id=action_ir.blueprint_id,
                action_id=action_ir.action_id,
                technique_id=action_ir.technique_id,
                target=action_ir.target,
                executable=action_ir.executable,
                arguments=action_ir.arguments,
                run_as_user=action_ir.run_as_user,
                issued_at=action_ir.issued_at,
                expires_at=action_ir.expires_at,
            )
            signed_blueprints.append(signed_bp)

        execution_plan.status = "EXECUTED"

        return PlanResult(
            scenario=scenario,
            execution_plan=execution_plan,
            actions=candidate_actions,
            policy_decision=scenario_decision,
            signed_blueprints=signed_blueprints,
        )
