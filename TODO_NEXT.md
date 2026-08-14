# Next Steps

1. **Detection Gap Evaluator & Telemetry Correlator ✅ COMPLETE**:
   - Built scenario-level `DetectionGapEvaluator` connecting executed `ActionIR`/`AdversarialScenario` technique IDs with `NormalizedEvent` stream and `SigmaEngine` evaluation results.
   - Implemented `ActionDetectionOutcome` and `ScenarioDetectionOutcome` with scenario isolation, deduplication, and technique ID correlation.


2. **Phase 5: Blue Agent & Detection Gap Remediation ✅ COMPLETE**:
   - Implemented `BlueAgentAnalyst` to investigate `DETECTION_GAP` outcomes and classify evidence-backed root causes (`NO_TELEMETRY`, `NO_RULE_MATCH`, `UNRELATED_RULE_MATCH`, `INSUFFICIENT_TECHNIQUE_METADATA`, `INSUFFICIENT_RULE_COVERAGE`).
   - Derived evidence-backed `CandidateSigmaRule` with immutable `x-sentinelforge` provenance.
   - Built `SigmaRuleValidator` to enforce syntax, schema, technique matching, and broad-rule rejection.
   - Built `RuleValidationSandbox` to test malicious detection and benign false-positive immunity in-memory without executing commands.
   - Built `RetestOrchestrator` to execute authorized retests through existing `RedAgentPlanner` → `SafetyBoundary` → `PolicyEngine` → `SignedBlueprint` → `SimulationAdapter` → Telemetry → `DetectionGapEvaluator` architecture.
   - Updated `ExerciseStateMachine` to enforce that `VERIFIED` requires a valid, improved `RetestResult`.

3. **Phase 6: Native Linux/Docker E2E CI Verification ⚠️ PARTIALLY VERIFIED**:
   - Created GitHub Actions CI/CD pipeline workflow (`.github/workflows/ci.yml`) targeting Ubuntu Linux runner.
   - Enforced `conftest.py` fail-on-missing-Docker policy in CI environment.
   - Fixed SQLite in-memory threading connection lock issue in `test_concurrency_replay.py`.
   - Verified 71 unit tests PASSED locally.
   - Verified 14 non-Docker integration tests PASSED locally.
   - Remaining: Push commit to remote GitHub repository once git credentials / repository access is authorized to execute live Docker E2E tests on GitHub Actions runner.

4. **Phase 7: Dashboard, API Routing & Multi-Range Deployment**:
   - Build React dashboard for visual Red/Blue closed-loop simulation and detection coverage metrics.
   - Implement FastAPI web API routing layer.

