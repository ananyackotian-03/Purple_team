# SENTINELFORGE — TEST STATUS

**Last run**: 2026-08-19
**Total**: 394 passed, 33 skipped, 83 warnings

---

## Test Breakdown

| Category | Tests | Status |
|----------|-------|--------|
| Unit: Remediation models | 11 | PASS |
| Unit: Remediation policy | 11 | PASS |
| Unit: Clone manager | 8 | PASS |
| Unit: Provider factory | 9 | PASS |
| Unit: VulnerabilityBridge | 6 | PASS |
| Unit: Proposal generator | 3 | PASS |
| Unit: State transitions | 11 | PASS |
| Unit: Metadata sanitization | 4 | PASS |
| Unit: Finding persistence | 4 | PASS |
| Unit: Proposal persistence | 2 | PASS |
| Unit: Attempt persistence | 5 | PASS |
| Unit: Verification persistence | 2 | PASS |
| Unit: Audit event persistence | 4 | PASS |
| Unit: Idempotency | 3 | PASS |
| Security: Remediation policy | 6 | PASS |
| Security: Adversarial LLM | 14 | PASS |
| Security: Security matrix | 14 | PASS |
| Security: Tenant isolation (DB) | 4 | PASS |
| Integration: Remediation pipeline | 4 | PASS |
| Integration: E2E mock | 4 | PASS |
| Integration: Generalization | 9 | PASS |
| Integration: Orchestrator persistence | 3 | PASS |
| Integration: Failure recovery | 2 | PASS |
| Integration: E2E audit trail | 1 | PASS |
| Integration: E2E real LLM | 3 | SKIP (no API keys) |
| Integration: Docker E2E | 6 | BLOCKED (Docker daemon not running) |
| Integration: Docker failure | 3 | BLOCKED (Docker daemon not running) |
| Integration: Docker tenant | 1 | BLOCKED (Docker daemon not running) |
| Detection: Normalizer + Sigma | 8 | PASS |
| Detection: Gap evaluator | 16 | PASS |
| Detection: Telemetry collection | 27 | PASS |
| Red Agent: Schemas + provider | 38 | PASS |
| Red Agent: Orchestration | 77 | PASS |
| Blue Agent | 21 | PASS |
| Security: Adversarial inputs | 11 | PASS |
| Integration: Docker simulation | 8 | SKIP (no Docker) |
| Integration: Target hardening | 4 | SKIP (no Docker) |
| Integration: Concurrency | 2 | PASS |
| Experiment domain | 9 | PASS |
| Red Agent dispatch | 3 | PASS |

## Skipped Tests
- 3: Real LLM E2E (no API keys)
- 10: Docker E2E (Docker daemon not running)
- 5: Docker integration (no Docker daemon on Windows)
- 4: Target hardening (no Docker)
- 10: Other Docker-dependent tests
- 1: Docker clone real (may run if Docker Desktop is active)

## Warnings
- 83: `datetime.datetime.utcnow()` deprecation (SQLAlchemy internal)
