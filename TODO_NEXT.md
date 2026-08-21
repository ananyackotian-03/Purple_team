# SENTINELFORGE — TODO NEXT

## Current Milestone: COMPLETE
Real Docker Isolation + Clone-Only Remediation + E2E Security Validation

## Status: DOCKER-DAEMON-BLOCKED
- Docker E2E tests written and verified (correctly skip when daemon unavailable)
- All existing 394 tests passing
- Docker Desktop installed but daemon not started

## To Enable Docker E2E
1. Start Docker Desktop
2. Run: `pytest tests/integration/test_docker_e2e.py -v`
3. All 10 Docker tests should pass

## Remaining Work

### To Enable Live LLM
1. Install SDK: `pip install openai` or `pip install anthropic`
2. Set environment variable: `SENTINELFORGE_LLM_PROVIDER=openai`
3. Set API key: `OPENAI_API_KEY=sk-...`
4. Run: `pytest tests/integration/test_e2e_real_llm.py -v`

### Future Enhancements (Not in Current Scope)
- [ ] Falco/eBPF telemetry (requires Linux environment)
- [ ] Cross-session novelty seeding
- [ ] Production PostgreSQL deployment
- [ ] Blue LLM Agent
- [ ] Multi-vulnerability classes
- [ ] Dashboard/UI
- [ ] Production deployment
