# SentinelForge

Evidence-Driven Autonomous Security Validation Platform.

## Project Status

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ COMPLETE | Core domain models, HMAC signing, replay protection, state machine, Policy Engine & Safety Boundary |
| **Phase 2** | ✅ COMPLETE | Simulation Worker, `SimulationAdapter` abstraction, Docker SDK integration, hardened target container, timeout enforcement |
| **Phase 3** | ✅ COMPLETE | Telemetry collection, normalization, Falco rules, Sigma rule evaluation with built-in fallback, `DetectionGapEvaluator` |
| **Phase 4** | ✅ COMPLETE | Red Agent: objective-driven adversarial scenario planner (`RedAgentPlanner`), MITRE ATT&CK strategy catalog |
| **Phase 5** | ✅ COMPLETE | Blue Agent: `BlueAgentAnalyst` gap analysis, `CandidateSigmaRule` generation, `SigmaRuleValidator`, `RuleValidationSandbox`, `RetestOrchestrator` |
| **Phase 6** | ⚠️ PARTIALLY VERIFIED | GitHub Actions CI workflow configured (`.github/workflows/ci.yml`), 71 unit tests & 14 non-Docker integration tests passing; 20 Docker tests BLOCKED BY ENVIRONMENT locally (requires active Docker daemon on Linux runner) |

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

### Security Boundaries

| Component | Trust Level | Role / Constraints |
|-----------|-------------|-------------------|
| Safety Boundary | Trusted deterministic control | Authorizes target, user, risk level, approvals, and allowlists |
| HMAC Signer | Trusted primitive | Proves blueprint integrity/authenticity |
| Simulation Worker | Conditionally trusted / privileged | Executes approved actions via pluggable adapter |
| Target Container | Hostile execution environment | `cap_drop=ALL`, `read_only`, `no-new-privileges`, non-root `labuser` |
| Raw Telemetry | Untrusted data | Bounded, sanitized, control-chars stripped, NFC-normalized |
| Red/Blue Agents | Untrusted LLMs | Generates scenarios/fixes; NEVER in direct execution path |

## Repository Structure

```
backend/
├── requirements.txt
├── src/sentinelforge/
│   ├── agents/
│   │   ├── blue_agent.py      # BlueAgentAnalyst, SigmaRuleValidator, RuleValidationSandbox, RetestOrchestrator
│   │   └── red_agent.py       # RedAgentPlanner & STRATEGY_CATALOG
│   ├── db/
│   │   └── models.py          # SQLAlchemy models (Organization, Exercise, SecurityObjectiveRecord, etc.)
│   ├── domain/
│   │   ├── action_ir.py       # ActionIR Pydantic schema
│   │   ├── blueprint.py       # SignedBlueprint schema
│   │   ├── exceptions.py      # SecurityRejection + SecurityRejectionCode
│   │   ├── experiment.py      # CandidateSigmaRule, RetestRequest, RetestResult, SecurityObjective, AdversarialScenario
│   │   ├── simulation.py      # SimulationRequest, SimulationExecution
│   │   └── state_machine.py   # ExerciseStateMachine transitions
│   ├── policy/
│   │   ├── allowlists.py      # Low-level exact-match bash command allowlist
│   │   ├── engine.py          # Low-level PolicyEngine
│   │   ├── safety_boundary.py # ExperimentSafetyBoundary authorization
│   │   └── signing.py         # HMAC-SHA256 BlueprintSigner
│   ├── simulation/
│   │   ├── adapter.py         # SimulationAdapter interface & ContainerLinuxAdapter
│   │   ├── docker_client.py   # SafeDockerClient wrapper
│   │   ├── replay.py          # SimulationRepository (atomic claim)
│   │   └── worker.py          # SimulationWorker orchestrator
│   └── detection/
│       ├── collector.py       # TelemetryCollector service
│       ├── evaluator.py       # DetectionGapEvaluator
│       ├── normalizer.py      # TelemetryNormalizer (raw Falco → NormalizedEvent)
│       ├── sigma_engine.py    # SigmaEngine (pySigma + built-in fallback matcher)
│       └── rules/             # Sigma YAML detection rules
├── tests/
│   ├── test_security.py       # Phase 1 unit security tests (8 tests)
│   ├── test_experiment.py     # Domain & Safety Boundary tests (3 tests)
│   ├── test_adapter.py        # SimulationAdapter tests (1 test)
│   ├── test_red_agent.py      # Phase 4 Red Agent tests (12 tests)
│   ├── test_blue_agent.py     # Phase 5 Blue Agent tests (21 tests)
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
cmd /c "set PYTHONPATH=backend/src && python -m pytest backend/tests --ignore=backend/tests/integration"
cmd /c "set PYTHONPATH=backend/src && python -m pytest backend/tests/integration -v"
```

## Test Results

```
Unit Test Suite:        71 passed in 1.11s
Integration Test Suite: 14 passed, 20 skipped (Docker daemon offline locally)
Total Verified Tests:   85 tests (71 unit + 14 integration passed)
```

