# SentinelForge

Evidence-Driven Autonomous Security Validation Platform.

## Project Status

| Component / Subsystem | Status | Description |
|-------|--------|-------------|
| **Phase 1 Foundation** | ✅ COMPLETE | Core domain models (`ActionIR` with formal constraints), HMAC signing, replay protection, state machine, Policy Engine & Safety Boundary |
| **Phase 2 Simulation** | ✅ COMPLETE | Simulation Worker, `SimulationAdapter` abstraction, bounded container cleanup, Docker SDK integration, hardened target container, timeout enforcement |
| **Phase 3 Detection** | ✅ COMPLETE | Telemetry collection, Unicode NFC normalization, Falco rules, Sigma rule evaluation with built-in fallback, `DetectionGapEvaluator` |
| **Red Planner Scaffolding** | ✅ COMPLETE | Deterministic scenario planner (`RedAgentPlanner`), MITRE ATT&CK strategy catalog (scaffolding for future LLM Red Agent) |
| **Blue Analyst Scaffolding** | ✅ COMPLETE | Deterministic gap analyst (`BlueAgentAnalyst`), `CandidateSigmaRule` generation, `SigmaRuleValidator`, `RuleValidationSandbox`, `RetestOrchestrator` (scaffolding for future LLM Blue Agent) |
| **Reconciliation & Verification** | ✅ COMPLETE | PRD V2 architecture reconciliation: 75/75 unit + 34/34 integration tests passing with real Docker daemon, closed-loop remediation VERIFIED |

> [!NOTE]
> **Deterministic Scaffolding vs LLM AI Agents**: The current `RedAgentPlanner` and `BlueAgentAnalyst` are deterministic, catalog-based planners and rule generators. They establish the strict authorization pipeline and evidence validation loop. LLM-based agent integration will build upon this foundation in subsequent milestones.

## Continuous Red ↔ Blue Loop (PRD V2 Vision)

```
RED Agent (Objective + Strategy)
    ↓
Adversarial Scenario
    ↓
Experiment Safety / Authorization Boundary
    ↓
Simulation Engine (Pluggable Adapters)
    ↓
Target Sandbox Execution
    ↓
Runtime Telemetry (Falco eBPF)
    ↓
Detection Stack (Sigma Engine)
    ↓
DetectionGapEvaluator (DETECTED / DETECTION GAP)
    ↓
BLUE Agent (Gap Analysis & Remediation)
    ↓
Validation Sandbox (Malicious + Benign Tests)
    ↓
Empirical Retest
    ↓
ExerciseStateMachine (VERIFIED)
```

### Security Boundaries & Invariants

| Component | Trust Level | Role / Constraints |
|-----------|-------------|-------------------|
| Safety Boundary | Trusted deterministic control | Authorizes target, user, risk level, approvals, and allowlists |
| HMAC Signer | Trusted primitive | Proves blueprint integrity/authenticity |
| Simulation Worker | Conditionally trusted / privileged | Executes approved actions via pluggable adapter |
| Target Container | Hostile execution environment | `cap_drop=ALL`, `read_only`, `no-new-privileges`, non-root `labuser` |
| Raw Telemetry | Untrusted data | Bounded, sanitized, control-chars stripped, NFC-normalized |
| Red/Blue Agents | Untrusted LLMs | Generates scenarios/fixes; NEVER in direct execution path |

> [!IMPORTANT]
> **Unicode Normalization & Homoglyphs**: `TelemetryNormalizer` applies canonical Unicode NFC normalization to untrusted telemetry strings. NFC standardizes combined codepoints (e.g. accents), but **does NOT convert or eliminate cross-script homoglyphs/confusables** (e.g. Latin 'a' vs Cyrillic 'а'). Exact-match policy allowlists and canonical executable paths remain the authoritative security controls against homoglyph spoofing.

## Repository Structure

```
backend/
├── alembic.ini                # Alembic database migration config
├── alembic/                   # Database migration versions
│   └── versions/
│       └── 001_reconciliation_schema_update.py
├── requirements.txt
├── src/sentinelforge/
│   ├── agents/
│   │   ├── blue_agent.py      # BlueAgentAnalyst, SigmaRuleValidator, RuleValidationSandbox, RetestOrchestrator
│   │   └── red_agent.py       # RedAgentPlanner & STRATEGY_CATALOG
│   ├── db/
│   │   └── models.py          # SQLAlchemy ORM models (PolicyDecisionRecord, DetectionGapRecord, RetestResult, etc.)
│   ├── domain/
│   │   ├── action_ir.py       # ActionIR Pydantic schema (with max_execution_seconds & max_stdout_bytes bounds)
│   │   ├── blueprint.py       # SignedBlueprint schema
│   │   ├── exceptions.py      # SecurityRejection + SecurityRejectionCode
│   │   ├── experiment.py      # CandidateSigmaRule, RetestRequest, RetestResult, SecurityObjective, AdversarialScenario
│   │   ├── simulation.py      # SimulationRequest, SimulationExecution
│   │   └── state_machine.py   # ExerciseStateMachine transitions
│   ├── policy/
│   │   ├── allowlists.py      # Low-level exact-match bash command allowlist
│   │   ├── engine.py          # Low-level PolicyEngine
│   │   ├── safety_boundary.py # ExperimentSafetyBoundary authorization (with PolicyDecision database persistence)
│   │   └── signing.py         # HMAC-SHA256 BlueprintSigner
│   ├── simulation/
│   │   ├── adapter.py         # SimulationAdapter interface & ContainerLinuxAdapter (with bounded cleanup)
│   │   ├── docker_client.py   # SafeDockerClient wrapper
│   │   ├── replay.py          # SimulationRepository (atomic claim)
│   │   └── worker.py          # SimulationWorker orchestrator
│   └── detection/
│       ├── collector.py       # TelemetryCollector service
│       ├── evaluator.py       # DetectionGapEvaluator
│       ├── normalizer.py      # TelemetryNormalizer (NFC normalized, sanitized)
│       ├── sigma_engine.py    # SigmaEngine (pySigma + built-in fallback matcher)
│       └── rules/             # Sigma YAML detection rules
├── tests/
│   ├── test_security.py       # Phase 1 unit security tests (8 tests)
│   ├── test_experiment.py     # Domain, Safety Boundary, ActionIR, NFC & Persistence tests (7 tests)
│   ├── test_adapter.py        # SimulationAdapter tests (1 test)
│   ├── test_red_agent.py      # Red Agent Planner tests (12 tests)
│   ├── test_blue_agent.py     # Blue Agent Analyst tests (21 tests)
│   ├── detection/
│   │   ├── test_detection.py  # Phase 3 detection stack tests (9 tests)
│   │   └── test_gap_evaluator.py # DetectionGapEvaluator tests (17 tests)
│   └── integration/
│       ├── conftest.py        # Reusable docker_available & require_docker fixtures
│       ├── test_e2e_remediation.py # Full closed-loop E2E remediation test
│       ├── test_security_adversarial.py # Security attack & boundary tests
│       ├── test_concurrency_replay.py # Multithreaded claim atomicity & replay protection
│       ├── test_simulation.py # Phase 2 simulation tests (12 tests)
│       └── test_target.py     # Phase 2 target hardening tests (7 tests)
.github/
└── workflows/
    └── ci.yml                 # GitHub Actions CI/CD workflow (Unit & Docker Integration jobs)
target/
├── Dockerfile                 # Hardened target container definition
├── docker-compose.yml
├── falco.yaml                 # Falco telemetry sidecar config
└── rules.d/
    └── custom_rules.yaml      # Falco syscall rules
```

## Running Tests

```cmd
:: Unit & Security Tests (75 tests)
cmd /c "python -m pytest -o pythonpath=backend/src backend/tests --ignore=backend/tests/integration -v"

:: Integration Tests (34 tests — requires running sentinelforge-target container)
cmd /c "python -m pytest -o pythonpath=backend/src backend/tests/integration -v"
```

## Test Results

```
Unit Test Suite:        75 passed in 3.90s
Integration Test Suite: 34 passed in 7.50s (real Docker execution)
Total Verified Tests:   109 tests — 0 failed, 0 skipped
```
