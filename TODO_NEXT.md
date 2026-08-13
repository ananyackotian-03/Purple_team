# Next Steps

1. **Proceed to Phase 3**: Design and implement the Telemetry Collector (Falco eBPF sidecar).
2. **Sigma Rule Engine**: Integrate `pySigma` and `sigma-rule-matcher` for real-time detection evaluation over the telemetry stream.
3. **Queue Architecture**: Introduce Redis Streams (or equivalent) for queueing ActionIR blueprints to the Simulation Worker and routing Telemetry events to the Detection Engine.
4. **Agent Integration**: Following Phase 3, design the architecture for the Analyst and Planner LLM agents (Phase 4).
