# Next Steps — SentinelForge (PRD V2 Reconciled)

1. **Minimal Surgical Reconciliation Pass ✅ COMPLETE**:
   - Updated `ActionIR` schema with explicit `max_execution_seconds` & `max_stdout_bytes` Pydantic bounds.
   - Added Unicode NFC normalization to `TelemetryNormalizer` with explicit homoglyph non-collapse test.
   - Implemented `ContainerLinuxAdapter.cleanup()` for bounded target container cleanup.
   - Added `DetectionGapRecord` DB model and `PolicyDecisionRecord` database persistence.
   - Added Alembic migration framework (`001_reconciliation_schema_update.py`).
   - Verified 109/109 tests PASSING (75 unit + 34 integration).

2. **Next Milestone: Real LLM-Based Red Agent (PLANNED)**:
   - Build objective-driven LLM adversarial scenario planner (`agents/red_agent.py` LLM integration).
   - Input: `SecurityObjective`, authorized cyber range, past experiment history, current detection coverage.
   - Output: `AdversarialScenario` and `ExecutionPlan`.
   - Security Invariant: LLM output is UNTRUSTED. Must route strictly through `ExperimentSafetyBoundary` → `PolicyEngine` → `ActionIR` → HMAC `SignedBlueprint`.

3. **Subsequent Milestone: Real LLM-Based Blue Agent (PLANNED)**:
   - Build LLM-driven detection gap analyst (`agents/blue_agent.py` LLM integration).
   - Input: `DetectionGapRecord`, correlated telemetry evidence, existing rules.
   - Output: Candidate Sigma detection rules with immutable `x-sentinelforge` provenance.
   - Security Invariant: Candidate rules must pass `SigmaRuleValidator` and `RuleValidationSandbox` prior to `RetestOrchestrator`.

4. **Continuous Adaptive Loop & Dashboard (FUTURE)**:
   - Red AI adapts strategy upon Blue detection improvement.
   - React dashboard visualization & FastAPI REST endpoints.
