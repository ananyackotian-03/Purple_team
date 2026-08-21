# SentinelForge
Evidence-Driven Autonomous Security Validation Platform

## Status
- **IMPLEMENTED**: Phase 1 (Core Domain, Policy Engine, HMAC, DB Models, Security Boundaries), Phase 2 (Simulation Worker, Docker Integration, Target Hardening), Phase 3 (Telemetry, Falco).
- **IMPLEMENTED**: Red Agent V1 — full `agents/red/` package: strict schema validation, deterministic `NoveltyEvaluator`, `SafetyBoundaryBridge` (ExperimentSafetyBoundary + PolicyEngine), HMAC `BlueprintSigner`, budget enforcement, closed-loop orchestrator.
- **IMPLEMENTED (Step 1)**: Real LLM provider layer behind the `LLMProvider` abstraction:
  - `OpenAIProvider`, `AnthropicProvider`, `GeminiProvider` vendor drivers (lazy SDK loading, timeouts, error mapping, injectable clients for tests).
  - `OpenAICompatibleProvider` — local/free OpenAI Chat Completions-compatible endpoint (Ollama / LM Studio / vLLM) using only the standard library; no paid API required to develop or test.
  - `RetryableProvider` (exponential backoff 1s/2s/4s for infrastructure failures only), `FallbackProvider` (provider substitution), `ProviderRetryPolicy`.
- **SCAFFOLDING / EXPERIMENTAL**: Real-vendor calls are implemented but not live-verified (require SDKs + API keys at runtime); local-endpoint driver is wired but not yet exercised against a running model server.
- **PLANNED**: Step 2 — wire the end-to-end feedback loop (execute → collect telemetry → evaluate detection gaps → structured feedback), cross-session memory seeding, budget hardening polish. Blue LLM Agent. Dashboard, Kubernetes, AWS.
- **BLOCKED**: none in this environment (Docker daemon + target container running).

## Security model
The LLM is an untrusted proposal generator (Tier 1). Every proposal must pass, in order:
strict Pydantic schema validation → deterministic `NoveltyEvaluator` → `SafetyBoundaryBridge` (ExperimentSafetyBoundary + PolicyEngine) → HMAC `BlueprintSigner` before any execution. Retries/fallbacks never relax schema, safety, or policy checks.
