# SentinelForge — Red Agent V1 Implementation Plan

**Document Version**: 1.0.0  
**Status**: PROPOSED / AWAITING APPROVAL  
**Target Milestone**: Real LLM-Based Red Agent V1  

---

## Executive Summary

This document details the step-by-step implementation plan for transitioning SentinelForge from the initial deterministic catalog scaffolding (`STRATEGY_CATALOG`) to a fully functional, LLM-driven **Red Agent V1**.

The implementation preserves all existing security primitives, domain models, and authorization boundaries:
- `ExperimentSafetyBoundary`
- `PolicyEngine`
- `ActionIR`
- `BlueprintSigner` (HMAC-SHA256)
- `SimulationWorker` & `SimulationAdapter`
- `DetectionGapEvaluator`
- PostgreSQL tenant isolation and audit logging

---

## Existing Architecture Mapping

| Component | Existing File Location | Current Role | V1 Red Agent Integration Point |
| :--- | :--- | :--- | :--- |
| **Red Agent Scaffolding** | `backend/src/sentinelforge/agents/red_agent.py` | Deterministic `STRATEGY_CATALOG` planner | Re-exported entry point; delegates to new `agents/red/` package |
| **Domain Models** | `backend/src/sentinelforge/domain/experiment.py` | `SecurityObjective`, `AdversarialScenario`, `ExecutionPlan`, `PolicyDecision` | Reused directly by Red Agent schemas |
| **ActionIR** | `backend/src/sentinelforge/domain/action_ir.py` | Intermediate execution representation with bounds | Target schema for proposed LLM actions |
| **Safety Boundary** | `backend/src/sentinelforge/policy/safety_boundary.py` | Evaluates risk, approval, and target/user bounds | Mandatory gate for all Red Agent decisions |
| **Policy Engine** | `backend/src/sentinelforge/policy/engine.py` | Executable and argument allowlist verification | Low-level execution safety invariant check |
| **Blueprint Signing** | `backend/src/sentinelforge/policy/signing.py` | HMAC-SHA256 signature generator | Signed blueprints produced ONLY after Policy Engine ALLOWED decision |
| **Simulation Engine** | `backend/src/sentinelforge/simulation/worker.py` | Execution worker & replay protection | Receives signed blueprints for isolated execution |
| **Detection Evaluator** | `backend/src/sentinelforge/detection/evaluator.py` | Scenario detection gap correlator | Source of feedback for Red Agent learning loop |
| **Database Models** | `backend/src/sentinelforge/db/models.py` | PostgreSQL ORM tables | Extended with `RedAgentStrategyRecord` table |

---

## Proposed Directory & Package Structure

New package location: `backend/src/sentinelforge/agents/red/`

```
backend/src/sentinelforge/agents/red/
├── __init__.py          # Public exports (RedAgent, RedAgentConfig, RedAgentDecision)
├── agent.py             # Main RedAgent orchestrator & execution loop
├── context.py           # RedAgentContext builder & SQL history query engine
├── state.py             # RedAgentStateMachine state transitions & state guards
├── schemas.py           # Pydantic schemas (RedAgentDecision, ActionProposalSpec, etc.)
├── prompts.py           # System prompts, XML context formatting & prompt-injection defenses
├── tools.py             # Tool contracts & implementations (get_objective, propose_experiment, etc.)
├── memory.py            # PostgreSQL strategy memory storage & retrieval
├── planner.py           # LLM scenario planner (connects provider & prompt context)
├── novelty.py           # StrategyFingerprint generator & NoveltyEvaluator
├── evaluator.py         # Feedback bridge connecting DetectionGapEvaluator outcomes
├── provider.py          # LLMProvider abstract interface & vendor implementations
├── policies.py          # Bridge to ExperimentSafetyBoundary and PolicyEngine
└── exceptions.py        # Custom exception hierarchy (RedAgentException, SafetyViolationError, etc.)
```

---

## Detailed File Modifications & Implementations

### 1. `backend/src/sentinelforge/agents/red/exceptions.py` [NEW]
- **Purpose**: Define domain-specific exceptions for Red Agent operations.
- **Classes**:
  - `RedAgentException(Exception)`
  - `SchemaValidationError(RedAgentException)`
  - `SafetyRejectionError(RedAgentException)`
  - `NoveltyCheckError(RedAgentException)`
  - `BudgetExhaustedError(RedAgentException)`
  - `ProviderAPIError(RedAgentException)`

### 2. `backend/src/sentinelforge/agents/red/schemas.py` [NEW]
- **Purpose**: Formal Pydantic schemas for structured LLM interaction.
- **Classes**:
  - `ActionProposalSpec`: Proposed command executable, arguments, target, run_as_user, technique_id.
  - `ScenarioProposalSpec`: Title, strategy_description, technique_ids, proposed_risk_level, proposed_actions.
  - `ExpectedDetectionSpec`: `should_detect`, `expected_rule_category`, `reason`.
  - `NoveltyClaimSpec`: `category`, `differing_aspect`.
  - `RedAgentDecision`: `decision` ("PROPOSE_EXPERIMENT" | "TERMINATE_OBJECTIVE"), `hypothesis`, `scenario`, `reasoning_summary`, `expected_detection`, `novelty_claim`.
  - `RedAgentBudget`: `max_iterations`, `max_experiments`, `max_llm_calls`, `max_wall_time_seconds`.

### 3. `backend/src/sentinelforge/agents/red/provider.py` [NEW]
- **Purpose**: Model provider abstraction layer.
- **Classes**:
  - `LLMProvider(ABC)`: Abstract base class with `generate(prompt, system_prompt, response_schema)`.
  - `OpenAIProvider(LLMProvider)`: Driver for OpenAI API / SDK.
  - `AnthropicProvider(LLMProvider)`: Driver for Anthropic Claude API / SDK.
  - `GeminiProvider(LLMProvider)`: Driver for Google Gemini API / SDK.
  - `MockProvider(LLMProvider)`: Deterministic provider for unit tests without external API dependencies.

### 4. `backend/src/sentinelforge/agents/red/context.py` [NEW]
- **Purpose**: Build deterministic, tenant-isolated context objects for LLM prompting.
- **Classes**:
  - `RedAgentContext`: Data model holding objective, range capabilities, history, detection coverage, gaps, recent observations, and budget.
  - `ContextBuilder`: Interacts with SQLAlchemy `db_session` enforcing `organization_id` filters to assemble bounded `RedAgentContext`.

### 5. `backend/src/sentinelforge/agents/red/prompts.py` [NEW]
- **Purpose**: Centralized prompt templates with XML fencing and prompt-injection defenses.
- **Functions**:
  - `build_system_prompt()`: Core role, constraints, and structured decision rules.
  - `format_agent_context(context: RedAgentContext)`: Formats context into XML-tagged blocks (`<AGENT_ROLE>`, `<OBJECTIVE>`, `<UNTRUSTED_TELEMETRY>`, etc.).
  - `sanitize_untrusted_input(text: str)`: Strips null bytes, control characters, and closing tags (`</UNTRUSTED_TELEMETRY>`).

### 6. `backend/src/sentinelforge/agents/red/state.py` [NEW]
- **Purpose**: Explicit, deterministic state machine governing agent execution transitions.
- **Classes**:
  - `RedAgentState(str, Enum)`: `IDLE`, `OBJECTIVE_RECEIVED`, `CONTEXT_LOADING`, `ANALYZING`, `HYPOTHESIS_GENERATED`, `SCENARIO_GENERATED`, `NOVELTY_CHECK`, `SAFETY_SUBMITTED`, `DENIED`, `ESCALATED`, `ALLOWED`, `EXECUTING`, `OBSERVING`, `EVALUATING`, `LEARNING`, `CONTINUE`, `FINISHED`.
  - `RedAgentStateMachine`: Enforces strict state transitions and state guards.

### 7. `backend/src/sentinelforge/agents/red/novelty.py` [NEW]
- **Purpose**: Fingerprinting and deterministic strategy novelty evaluation.
- **Classes**:
  - `StrategyFingerprint`: Normalized command pattern, technique, executable, and SHA-256 hash.
  - `NoveltyStatus(str, Enum)`: `NOVEL`, `SIMILAR`, `DUPLICATE`.
  - `NoveltyEvaluator`: Compares candidate fingerprint against database history and returns `NoveltyEvaluation`.

### 8. `backend/src/sentinelforge/agents/red/tools.py` [NEW]
- **Purpose**: Safe application-level tool interfaces exposed to LLM function calls.
- **Classes**:
  - `RedAgentToolRegistry`: Manages allowed tools (`get_objective`, `get_history`, `propose_experiment`, etc.).
  - Rejects attempts to register or invoke unauthorized commands (shell, docker exec, file system).

### 9. `backend/src/sentinelforge/agents/red/policies.py` [NEW]
- **Purpose**: Bridge connecting Red Agent proposals to `ExperimentSafetyBoundary` and `PolicyEngine`.
- **Classes**:
  - `SafetyBoundaryBridge`: Converts `ScenarioProposalSpec` to `AdversarialScenario` and `ActionProposalSpec` to `ActionIR`, evaluates both through `ExperimentSafetyBoundary`, and generates `SignedBlueprint` list ONLY upon `ALLOWED` decision status.

### 10. `backend/src/sentinelforge/agents/red/memory.py` [NEW]
- **Purpose**: Manage PostgreSQL persistence for Red Agent strategy history.
- **Classes**:
  - `RedAgentMemoryStore`: Handles reading and recording experiment outcomes, strategy fingerprints, and detection outcomes scoped by `organization_id`.

### 11. `backend/src/sentinelforge/db/models.py` [MODIFY]
- **Purpose**: Add ORM table for persistent strategy fingerprint tracking.
- **Additions**:
  - `RedAgentStrategyRecord`: Table `red_agent_strategies` (`id`, `organization_id`, `objective_id`, `scenario_id`, `technique_id`, `fingerprint_hash`, `command_pattern`, `outcome`, `created_at`).

### 12. `backend/src/sentinelforge/agents/red/agent.py` [NEW]
- **Purpose**: Main Red Agent orchestrator loop.
- **Classes**:
  - `RedAgent`: Integrates `ContextBuilder`, `Planner`, `NoveltyEvaluator`, `SafetyBoundaryBridge`, `SimulationWorker`, `DetectionGapEvaluator`, and `MemoryStore` into a continuous exploration loop.

### 13. `backend/src/sentinelforge/agents/red_agent.py` [MODIFY]
- **Purpose**: Maintain backward compatibility.
- **Changes**: Re-exports `RedAgentPlanner` while providing optional delegation to the new `RedAgent` package.

---

## Verification & Testing Strategy

A dedicated test suite will be implemented in `backend/tests/test_llm_red_agent.py`:

1. **Unit Tests**:
   - Schema validation test for `RedAgentDecision`.
   - `LLMProvider` abstraction test with `MockProvider`.
   - Prompt formatting & injection defense sanitization test.
   - `StrategyFingerprint` hash consistency and `NoveltyEvaluator` classification test (`DUPLICATE`, `SIMILAR`, `NOVEL`).
   - `RedAgentStateMachine` state transition guard tests.
   - `RedAgentBudget` limit enforcement tests.

2. **Security Adversarial Tests**:
   - Attempted shell injection via telemetry string -> Verified sanitized & safety boundary enforced.
   - Attempted unauthorized target proposal -> Verified `DENIED` by `ExperimentSafetyBoundary`.
   - Attempted unauthorized command (`rm -rf /`) -> Verified `DENIED` by `PolicyEngine`.
   - Attempted budget reset -> Verified ignored by Python budget monitor.
   - Cross-tenant memory isolation -> Verified tenant query scoping.

3. **Integration Tests**:
   - End-to-end loop with `MockProvider`: `SecurityObjective` → Context → Plan → Novelty → Safety Gate → ActionIR → HMAC Signature → Simulation Worker → Falco Telemetry → Detection Evaluator → Memory Update.

---

## Phase Execution Checklist

- [ ] **Phase 1**: Core Schemas & Exceptions (`schemas.py`, `exceptions.py`, `models.py`).
- [ ] **Phase 2**: Provider Abstraction & Mock Driver (`provider.py`).
- [ ] **Phase 3**: Context Builder & Prompts (`context.py`, `prompts.py`).
- [ ] **Phase 4**: State Machine & Novelty Evaluator (`state.py`, `novelty.py`).
- [ ] **Phase 5**: Safety Boundary Bridge & Tools (`policies.py`, `tools.py`).
- [ ] **Phase 6**: Memory Store & Orchestrator Loop (`memory.py`, `agent.py`, `red_agent.py`).
- [ ] **Phase 7**: Comprehensive Test Suite (`tests/test_llm_red_agent.py`).
