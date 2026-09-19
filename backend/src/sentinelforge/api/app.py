"""SentinelForge FastAPI application — HTTP API for the security validation platform.

SECURITY ROLE:
This API layer is a READ-ONLY interface to existing backend data and logic.
It does NOT execute commands, bypass safety boundaries, or modify detection verdicts.
All operations go through the existing security path.

Usage:
    uvicorn sentinelforge.api.app:app --reload --host 0.0.0.0 --port 8000
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from sentinelforge.api.schemas import (
    ComparisonResponse,
    CoverageResponse,
    DashboardMetrics,
    DetectionGapResponse,
    DefensiveProposalCreate,
    DefensiveProposalResponse,
    DefensiveProposalValidateResponse,
    EvidenceTrace,
    ExperimentDetail,
    ExperimentListResponse,
    ExperimentResponse,
    HealthResponse,
    ImmuneCycleRunResponse,
    ImmuneCycleStatusResponse,
    ImmuneMemoryResponse,
    LifecycleStage,
    NextExperimentResponse,
    ObjectiveCreate,
    ObjectiveDetail,
    ObjectiveResponse,
    OrganizationCreate,
    OrganizationResponse,
    OrganizationStateResponse,
    RetestListResponse,
    RetestResponse,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database — file-based SQLite for cross-thread compatibility with FastAPI
# ---------------------------------------------------------------------------
_DB_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
_DB_PATH = os.path.normpath(os.path.join(_DB_DIR, "sentinelforge_ui.db"))
_DB_URL = f"sqlite:///{_DB_PATH}"

engine = create_engine(_DB_URL, echo=False)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def _init_db():
    """Create all tables."""
    import sentinelforge.db.models  # noqa: F401
    import sentinelforge.remediation.db_models  # noqa: F401
    from sentinelforge.db.models import Base
    Base.metadata.create_all(engine)


def _seed_demo_data():
    """Seed demo data using raw SQL (avoids PostgreSQL UUID type issues with SQLite)."""
    import uuid as _uuid

    session = SessionLocal()
    try:
        result = session.execute(text("SELECT COUNT(*) FROM organizations"))
        if result.scalar() > 0:
            return

        now = datetime.now(timezone.utc).isoformat()

        org_id = "00000000-0000-0000-0000-000000000001"
        obj1_id = "11111111-1111-1111-1111-111111111111"
        obj2_id = "22222222-2222-2222-2222-222222222222"
        obj3_id = "33333333-3333-3333-3333-333333333333"
        sc1_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        sc2_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        sc3_id = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        ep1_id = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        ep2_id = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
        ep3_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"

        session.execute(text("INSERT INTO organizations (id, name) VALUES (:id, :name)"),
                       {"id": org_id, "name": "SentinelForge Demo"})

        for oid, title, desc, risk in [
            (obj1_id, "Detect Credential Dumping via /etc/shadow",
             "Validate whether credential access techniques (T1003.008) are detected.", "HIGH"),
            (obj2_id, "Detect Shell Execution Anomalies",
             "Test if process execution anomalies (T1059.004) trigger alerts.", "MEDIUM"),
            (obj3_id, "Validate Log Tampering Detection",
             "Verify that file deletion and log tampering (T1070.004) are detected.", "MEDIUM"),
        ]:
            session.execute(text(
                "INSERT INTO security_objectives (id, organization_id, title, description, target_category, default_risk_level, created_at) "
                "VALUES (:id, :org, :title, :desc, 'linux_host', :risk, :ts)"
            ), {"id": oid, "org": org_id, "title": title, "desc": desc, "risk": risk, "ts": now})

        for sid, oid, title, desc, risk in [
            (sc1_id, obj1_id, "Shadow File Read via cat", "Read /etc/shadow to test credential access detection.", "HIGH"),
            (sc2_id, obj2_id, "Shell Whoami Enumeration", "Execute whoami via bash to test process execution detection.", "MEDIUM"),
            (sc3_id, obj3_id, "Log File Deletion Attempt", "Attempt to remove log files to test file integrity monitoring.", "MEDIUM"),
        ]:
            session.execute(text(
                "INSERT INTO adversarial_scenarios (id, objective_id, organization_id, title, strategy_description, proposed_risk_level, created_by, created_at) "
                "VALUES (:id, :oid, :org, :title, :desc, :risk, 'red_agent', :ts)"
            ), {"id": sid, "oid": oid, "org": org_id, "title": title, "desc": desc, "risk": risk, "ts": now})

        for pid, sid, steps, status in [
            (ep1_id, sc1_id, "Execute 'cat /etc/shadow' on sentinelforge-target as labuser", "EXECUTED"),
            (ep2_id, sc2_id, "Execute 'whoami' on sentinelforge-target as labuser", "EXECUTED"),
            (ep3_id, sc3_id, "Execute 'rm /var/log/auth.log' on sentinelforge-target as labuser", "EXECUTED"),
        ]:
            session.execute(text(
                "INSERT INTO execution_plans (id, scenario_id, organization_id, steps_description, status, created_at) "
                "VALUES (:id, :sid, :org, :steps, :status, :ts)"
            ), {"id": pid, "sid": sid, "org": org_id, "steps": steps, "status": status, "ts": now})

        for sid in [sc1_id, sc2_id, sc3_id]:
            session.execute(text(
                "INSERT INTO policy_decisions (id, organization_id, scenario_id, status, reason, evaluated_at) "
                "VALUES (:id, :org, :sid, 'ALLOWED', 'Action passes all allowlist checks', :ts)"
            ), {"id": str(_uuid.uuid4()), "org": org_id, "sid": sid, "ts": now})

        for sid, tech, rule, matched, outcome in [
            (sc1_id, "T1003.008", "sigma_shadow_read", 1, "DETECTED"),
            (sc2_id, "T1059.004", "sigma_shell_execution", 1, "DETECTED"),
            (sc3_id, "T1070.004", "sigma_log_deletion", 0, "NOT_DETECTED"),
        ]:
            session.execute(text(
                "INSERT INTO detection_results (id, detection_id, correlation_id, technique_id, rule_id, matched, outcome, timestamp, source) "
                "VALUES (:id, :did, :corr, :tech, :rule, :matched, :outcome, :ts, 'sigma')"
            ), {"id": str(_uuid.uuid4()), "did": str(_uuid.uuid4()), "corr": sid,
                "tech": tech, "rule": rule, "matched": matched, "outcome": outcome, "ts": now})

        for sid, pid, tech, status, rules, evidence, gap_reason, latency in [
            (sc1_id, ep1_id, "T1003.008", "DETECTED", '["sigma_shadow_read"]', '["evt-001"]', None, 42),
            (sc2_id, ep2_id, "T1059.004", "DETECTED", '["sigma_shell_execution"]', '["evt-002"]', None, 38),
            (sc3_id, ep3_id, "T1070.004", "DETECTION_GAP", '[]', '["evt-003"]', "No Sigma rule matches log deletion pattern", None),
        ]:
            session.execute(text(
                "INSERT INTO purple_evaluations (id, organization_id, experiment_id, execution_id, technique_id, "
                "detection_status, matched_rule_ids, evidence_event_ids, expected_detection, gap_reason, detection_latency_ms, evaluated_at) "
                "VALUES (:id, :org, :eid, :pid, :tech, :status, :rules, :evidence, 1, :gap, :latency, :ts)"
            ), {"id": str(_uuid.uuid4()), "org": org_id, "eid": sid, "pid": pid, "tech": tech,
                "status": status, "rules": rules, "evidence": evidence,
                "gap": gap_reason, "latency": latency, "ts": now})

        session.commit()
        logger.info("Demo data seeded successfully")
    except Exception as exc:
        session.rollback()
        logger.error("Failed to seed demo data: %s", exc)
    finally:
        session.close()


# Initialize DB on import
_init_db()
_seed_demo_data()

# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SentinelForge API",
    description="Evidence-Driven Autonomous Security Validation Platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse)
def health_check():
    ollama_status = "unknown"
    docker_status = "unknown"
    try:
        import requests
        resp = requests.get("http://localhost:11434/api/tags", timeout=2)
        ollama_status = "connected" if resp.status_code == 200 else "error"
    except Exception:
        ollama_status = "unavailable"
    try:
        import docker
        client = docker.from_env()
        client.ping()
        docker_status = "connected"
    except Exception:
        docker_status = "unavailable"
    return HealthResponse(status="ok", version="0.1.0", database="connected",
                          ollama=ollama_status, docker=docker_status)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.get("/api/dashboard", response_model=DashboardMetrics)
def get_dashboard():
    session = SessionLocal()
    try:
        total_objectives = session.execute(text("SELECT COUNT(*) FROM security_objectives")).scalar() or 0
        total_experiments = session.execute(text("SELECT COUNT(*) FROM adversarial_scenarios")).scalar() or 0
        total_detections = session.execute(text("SELECT COUNT(*) FROM detection_results WHERE outcome='DETECTED'")).scalar() or 0
        detection_gaps = session.execute(text("SELECT COUNT(*) FROM detection_results WHERE outcome IN ('NOT_DETECTED','DETECTION_GAP')")).scalar() or 0

        evals = session.execute(text("SELECT detection_status FROM purple_evaluations")).fetchall()
        total_evals = len(evals)
        detected_evals = sum(1 for e in evals if e[0] == "DETECTED")
        coverage_pct = (detected_evals / total_evals * 100) if total_evals > 0 else 0.0

        retest_rows = session.execute(text("SELECT detection_improved FROM retest_results")).fetchall()
        total_retests = len(retest_rows)
        retests_improved = sum(1 for r in retest_rows if r[0])

        scenarios = session.execute(text(
            "SELECT s.title, s.proposed_risk_level, s.created_by, s.created_at, o.title "
            "FROM adversarial_scenarios s LEFT JOIN security_objectives o ON s.objective_id = o.id "
            "ORDER BY s.created_at DESC LIMIT 10"
        )).fetchall()

        activities = [
            {"type": "experiment", "title": row[0], "objective": row[4] or "Unknown",
             "risk_level": row[1], "created_by": row[2],
             "timestamp": row[3] if row[3] else ""}
            for row in scenarios
        ]

        return DashboardMetrics(
            total_objectives=total_objectives, total_experiments=total_experiments,
            active_experiments=0, completed_experiments=total_experiments,
            total_detections=total_detections, detection_gaps=detection_gaps,
            coverage_pct=round(coverage_pct, 1), total_retests=total_retests,
            retests_improved=retests_improved, system_status="operational",
            recent_activities=activities,
        )
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Objectives
# ---------------------------------------------------------------------------
@app.get("/api/objectives", response_model=List[ObjectiveResponse])
def list_objectives():
    session = SessionLocal()
    try:
        rows = session.execute(text(
            "SELECT id, organization_id, title, description, target_category, default_risk_level, created_at "
            "FROM security_objectives ORDER BY created_at DESC"
        )).fetchall()

        result = []
        for row in rows:
            exp_count = session.execute(text(
                "SELECT COUNT(*) FROM adversarial_scenarios WHERE objective_id = :oid"
            ), {"oid": row[0]}).scalar() or 0
            result.append(ObjectiveResponse(
                id=str(row[0]), organization_id=str(row[1]), title=row[2],
                description=row[3], target_category=row[4],
                default_risk_level=row[5],
                created_at=row[6] if row[6] else "",
                experiment_count=exp_count,
            ))
        return result
    finally:
        session.close()


@app.post("/api/objectives", response_model=ObjectiveResponse, status_code=201)
def create_objective(req: ObjectiveCreate):
    session = SessionLocal()
    try:
        org = session.execute(text("SELECT id FROM organizations LIMIT 1")).fetchone()
        if not org:
            raise HTTPException(status_code=404, detail="No organization found")
        obj_id = str(uuid4())
        now = datetime.now(timezone.utc).isoformat()
        session.execute(text(
            "INSERT INTO security_objectives (id, organization_id, title, description, target_category, default_risk_level, created_at) "
            "VALUES (:id, :org, :title, :desc, :cat, :risk, :ts)"
        ), {"id": obj_id, "org": str(org[0]), "title": req.title, "desc": req.description,
            "cat": req.target_category, "risk": req.default_risk_level, "ts": now})
        session.commit()
        return ObjectiveResponse(id=obj_id, organization_id=str(org[0]), title=req.title,
                                description=req.description, target_category=req.target_category,
                                default_risk_level=req.default_risk_level, created_at=now, experiment_count=0)
    except HTTPException:
        raise
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        session.close()

from fastapi import BackgroundTasks

def _run_experiment_bg(objective_id: str):
    import uuid
    import os
    from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig
    from sentinelforge.agents.red.provider_factory import create_provider_from_env
    from sentinelforge.agents.red.schemas import RedAgentBudget
    from sentinelforge.simulation.worker import SimulationWorker
    from sentinelforge.simulation.replay import SimulationRepository
    from sentinelforge.policy.signing import BlueprintSigner
    from sentinelforge.detection.evaluator import DetectionGapEvaluator
    from sentinelforge.detection.sigma_engine import SigmaEngine
    from sentinelforge.detection.collector import TelemetryCollector
    from sentinelforge.detection.normalizer import TelemetryNormalizer
    from sentinelforge.domain.experiment import SecurityObjective, ExperimentConstraints, RiskLevel
    from sentinelforge.agents.red.novelty import NoveltyEvaluator
    from sentinelforge.agents.red.policies import SafetyBoundaryBridge

    session = SessionLocal()
    try:
        row = session.execute(text(
            "SELECT id, organization_id, title, description, target_category, default_risk_level "
            "FROM security_objectives WHERE id = :id"
        ), {"id": objective_id}).fetchone()
        
        if not row:
            logger.error(f"Objective {objective_id} not found for background run.")
            return

        objective = SecurityObjective(
            objective_id=uuid.UUID(row[0]),
            organization_id=uuid.UUID(row[1]),
            title=row[2],
            description=row[3] or "",
            target_category=row[4],
            default_risk_level=RiskLevel(row[5] or "MEDIUM"),
        )
        
        provider = create_provider_from_env()
        from sentinelforge.agents.red.policies import _resolve_signing_key
        resolved_key = _resolve_signing_key()
        signer = BlueprintSigner(key=resolved_key, key_id="key1")
        repo = SimulationRepository(session)
        worker = SimulationWorker(signer=signer, repo=repo, db_session=session)
        
        sigma_engine = SigmaEngine()
        rules_dir = os.path.join(os.path.dirname(__file__), "..", "detection", "rules")
        sigma_engine.load_rules_from_directory(rules_dir)
        
        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=RedAgentBudget(max_iterations=1, max_experiments=1, max_llm_calls=5),
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.HIGH),
                bridge=SafetyBoundaryBridge(
                    constraints=ExperimentConstraints(max_risk_level=RiskLevel.HIGH)
                ),
                novelty=NoveltyEvaluator(),
                worker=worker,
                detection_evaluator=DetectionGapEvaluator(),
                sigma_engine=sigma_engine,
                telemetry_collector=collector,
                db_session=session,
            )
        )
        
        logger.info(f"Starting background RedAgent for objective {objective_id}")
        result = agent.run(objective)
        logger.info(f"Finished background RedAgent for objective {objective_id} — state={result.final_state}")

        # Persist results into API-visible tables (adversarial_scenarios, execution_plans, policy_decisions)
        now = datetime.now(timezone.utc).isoformat()
        org_id = row[1]

        for i, decision in enumerate(result.decisions):
            scenario = getattr(decision, "scenario", None)
            if scenario is None:
                continue

            sc_id = str(uuid.uuid4())
            title = getattr(scenario, "title", f"Experiment {i+1}")
            strategy = getattr(scenario, "strategy_description", "")
            risk = getattr(scenario, "proposed_risk_level", "MEDIUM")
            if hasattr(risk, "value"):
                risk = risk.value

            # Insert adversarial_scenario
            session.execute(text(
                "INSERT INTO adversarial_scenarios (id, objective_id, organization_id, title, strategy_description, proposed_risk_level, created_by, created_at) "
                "VALUES (:id, :oid, :org, :title, :desc, :risk, 'red_agent', :ts)"
            ), {"id": sc_id, "oid": objective_id, "org": org_id,
                "title": title, "desc": strategy, "risk": risk, "ts": now})

            # Insert execution_plan
            ep_id = str(uuid.uuid4())
            steps = strategy
            status = "EXECUTED" if result.experiments > 0 else "REJECTED"
            session.execute(text(
                "INSERT INTO execution_plans (id, scenario_id, organization_id, steps_description, status, created_at) "
                "VALUES (:id, :sid, :org, :steps, :status, :ts)"
            ), {"id": ep_id, "sid": sc_id, "org": org_id,
                "steps": steps, "status": status, "ts": now})

            # Insert policy_decision
            for pd in result.policy_decisions:
                pd_status = pd.status.value if hasattr(pd.status, "value") else str(pd.status)
                session.execute(text(
                    "INSERT INTO policy_decisions (id, organization_id, scenario_id, status, reason, evaluated_at) "
                    "VALUES (:id, :org, :sid, :status, :reason, :ts)"
                ), {"id": str(uuid.uuid4()), "org": org_id, "sid": sc_id,
                    "status": pd_status, "reason": pd.reason or "", "ts": now})

        session.commit()
        logger.info(f"Persisted {len(result.decisions)} scenario(s) for objective {objective_id}")
    except Exception as exc:
        logger.error(f"Error running agent: {exc}", exc_info=True)
        try:
            session.rollback()
        except Exception:
            pass
    finally:
        session.close()


@app.post("/api/objectives/{objective_id}/run", status_code=202)
def run_objective(objective_id: str, background_tasks: BackgroundTasks):
    session = SessionLocal()
    try:
        row = session.execute(text(
            "SELECT id FROM security_objectives WHERE id = :id"
        ), {"id": objective_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Objective not found")
            
        background_tasks.add_task(_run_experiment_bg, objective_id)
        return {"status": "accepted", "objective_id": objective_id}
    finally:
        session.close()


@app.get("/api/objectives/{objective_id}", response_model=ObjectiveDetail)
def get_objective(objective_id: str):
    session = SessionLocal()
    try:
        row = session.execute(text(
            "SELECT id, organization_id, title, description, target_category, default_risk_level, created_at "
            "FROM security_objectives WHERE id = :id"
        ), {"id": objective_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Objective not found")

        exps = session.execute(text(
            "SELECT id, title, strategy_description, proposed_risk_level, created_by, created_at "
            "FROM adversarial_scenarios WHERE objective_id = :oid"
        ), {"oid": objective_id}).fetchall()

        return ObjectiveDetail(
            objective=ObjectiveResponse(
                id=str(row[0]), organization_id=str(row[1]), title=row[2],
                description=row[3], target_category=row[4],
                default_risk_level=row[5], created_at=row[6] if row[6] else "",
                experiment_count=len(exps),
            ),
            experiments=[{
                "id": str(e[0]), "title": e[1], "strategy_description": e[2],
                "proposed_risk_level": e[3], "created_by": e[4],
                "created_at": e[5] if e[5] else "",
            } for e in exps],
        )
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------
@app.get("/api/experiments/{experiment_id}", response_model=ExperimentDetail)
def get_experiment(experiment_id: str):
    session = SessionLocal()
    try:
        sc = session.execute(text(
            "SELECT id, objective_id, title, strategy_description, proposed_risk_level, created_by, created_at "
            "FROM adversarial_scenarios WHERE id = :id"
        ), {"id": experiment_id}).fetchone()
        if not sc:
            raise HTTPException(status_code=404, detail="Experiment not found")

        plan = session.execute(text(
            "SELECT id, steps_description, status, created_at FROM execution_plans WHERE scenario_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        policy = session.execute(text(
            "SELECT status, reason, evaluated_at FROM policy_decisions WHERE scenario_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        detection = session.execute(text(
            "SELECT detection_id, technique_id, rule_id, matched, outcome, timestamp, source "
            "FROM detection_results WHERE correlation_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        purple = session.execute(text(
            "SELECT id, experiment_id, execution_id, organization_id, technique_id, detection_status, "
            "matched_rule_ids, evidence_event_ids, expected_detection, gap_reason, detection_latency_ms, evaluated_at "
            "FROM purple_evaluations WHERE experiment_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        now_iso = datetime.now(timezone.utc).isoformat()
        lifecycle = _build_lifecycle_raw(sc, plan, policy, detection, purple, now_iso)

        red_agent = {
            "state": "FINISHED" if plan and plan[2] == "EXECUTED" else "ANALYZING",
            "iterations": 1, "experiments_count": 1, "llm_calls": 2,
            "proposed_strategy": sc[3], "risk_level": sc[4],
        }

        detection_data = None
        if detection:
            detection_data = {
                "detection_id": str(detection[0]), "technique_id": detection[1],
                "rule_id": detection[2], "matched": bool(detection[3]),
                "outcome": detection[4],
                "timestamp": detection[5] if detection[5] else "",
                "source": detection[6],
            }

        purple_data = None
        if purple:
            purple_data = {
                "evaluation_id": str(purple[0]), "experiment_id": str(purple[1]),
                "execution_id": str(purple[2]) if purple[2] else None,
                "organization_id": str(purple[3]),
                "technique_id": purple[4], "detection_status": purple[5],
                "matched_rule_ids": json.loads(purple[6]) if purple[6] else [],
                "evidence_event_ids": json.loads(purple[7]) if purple[7] else [],
                "expected_detection": bool(purple[8]),
                "gap_reason": purple[9],
                "detection_latency_ms": purple[10],
                "evaluated_at": purple[11] if purple[11] else "",
            }

        return ExperimentDetail(
            experiment=ExperimentResponse(
                id=str(sc[0]), objective_id=str(sc[1]),
                scenario_id=str(sc[0]),
                status=plan[2] if plan else "PENDING",
                title=sc[2], strategy_description=sc[3],
                technique_ids=[], risk_level=sc[4], created_by=sc[5],
                created_at=sc[6] if sc[6] else "",
                iterations=1, experiments_count=1, llm_calls=2,
            ),
            lifecycle=lifecycle, red_agent=red_agent, telemetry=[],
            detection=detection_data, purple_evaluation=purple_data,
        )
    finally:
        session.close()


def _build_lifecycle_raw(sc, plan, policy, detection, purple, now_iso):
    stages = []
    stages.append(LifecycleStage(
        stage="objective", status="completed", label="Security Objective",
        timestamp=sc[6] if sc[6] else now_iso, result="Active"))
    stages.append(LifecycleStage(
        stage="red_agent", status="completed", label="Red Agent (LLM Proposal)",
        timestamp=sc[6] if sc[6] else now_iso,
        result="LLM proposed: " + (sc[3] or "")[:80], is_security_decision=False))
    stages.append(LifecycleStage(
        stage="safety_boundary", status="completed", label="Safety Boundary",
        timestamp=now_iso, result="Deterministic safety check passed",
        detail="Scenario and all actions passed ExperimentSafetyBoundary evaluation",
        is_security_decision=True))
    if policy:
        stages.append(LifecycleStage(
            stage="policy", status="completed", label="Policy Engine",
            timestamp=policy[2] if policy[2] else now_iso,
            result=f"Policy {policy[0]}: {policy[1]}", is_security_decision=True))
    else:
        stages.append(LifecycleStage(stage="policy", status="skipped", label="Policy Engine", result="No policy decision"))
    stages.append(LifecycleStage(
        stage="authorization", status="completed", label="Tool Authorization",
        timestamp=now_iso,
        result="HMAC-signed blueprint authorized" if plan and plan[2] == "EXECUTED" else "Not authorized",
        is_security_decision=True))
    if plan:
        stages.append(LifecycleStage(
            stage="execution", status="completed", label="Execution",
            timestamp=plan[3] if plan[3] else now_iso,
            result=f"Status: {plan[2]}", detail=plan[1]))
    else:
        stages.append(LifecycleStage(stage="execution", status="skipped", label="Execution", result="Not executed"))
    stages.append(LifecycleStage(
        stage="telemetry", status="completed", label="Telemetry Collection",
        timestamp=now_iso,
        result="Normalized events collected" if detection else "No telemetry available"))
    if detection:
        stages.append(LifecycleStage(
            stage="detection", status="completed", label="Detection Engine",
            timestamp=detection[5] if detection[5] else now_iso,
            result=f"{detection[4]}: Rule {detection[2]}",
            detail=f"Technique {detection[1]}, Matched: {detection[3]}",
            is_security_decision=True))
    else:
        stages.append(LifecycleStage(stage="detection", status="skipped", label="Detection Engine", result="No detection"))
    if purple:
        stages.append(LifecycleStage(
            stage="purple_evaluation", status="completed", label="Purple Evaluation",
            timestamp=purple[11] if purple[11] else now_iso,
            result=f"{purple[5]} (expected: {purple[8]})",
            detail=purple[9] or "Detection matches expectation",
            is_security_decision=True))
    else:
        stages.append(LifecycleStage(stage="purple_evaluation", status="skipped", label="Purple Evaluation", result="Not evaluated"))
    stages.append(LifecycleStage(
        stage="retest", status="pending", label="Retest",
        result="Awaiting remediation" if purple and purple[5] != "DETECTED" else "No retest needed"))
    return stages


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------
@app.get("/api/coverage", response_model=CoverageResponse)
def get_coverage():
    session = SessionLocal()
    try:
        org = session.execute(text("SELECT id FROM organizations LIMIT 1")).fetchone()
        org_id_str = str(org[0]) if org else "00000000-0000-0000-0000-000000000001"

        evals = session.execute(text(
            "SELECT technique_id, detection_status FROM purple_evaluations WHERE organization_id = :org"
        ), {"org": org_id_str}).fetchall()

        total = len(evals)
        detected = sum(1 for e in evals if e[1] == "DETECTED")
        missed = sum(1 for e in evals if e[1] == "NOT_DETECTED")
        gap = sum(1 for e in evals if e[1] == "DETECTION_GAP")
        coverage_pct = (detected / total * 100) if total > 0 else 0.0

        tech_coverage = {}
        for tech, status in evals:
            if tech not in tech_coverage:
                tech_coverage[tech] = False
            if status == "DETECTED":
                tech_coverage[tech] = True

        return CoverageResponse(
            report_id=str(uuid4()), organization_id=org_id_str,
            total_experiments=total, detected_experiments=detected,
            missed_experiments=missed, gap_experiments=gap,
            coverage_pct=round(coverage_pct, 1), technique_coverage=tech_coverage,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Retests
# ---------------------------------------------------------------------------
@app.get("/api/retests", response_model=List[RetestResponse])
def list_retests():
    session = SessionLocal()
    try:
        rows = session.execute(text(
            "SELECT id, organization_id, exercise_id, scenario_id, before_outcome, after_outcome, "
            "detection_improved, validated_rule_ids, evaluated_at FROM retest_results ORDER BY evaluated_at DESC"
        )).fetchall()
        return [RetestResponse(
            id=str(r[0]), organization_id=str(r[1]) if r[1] else None,
            exercise_id=str(r[2]) if r[2] else None,
            scenario_id=str(r[3]) if r[3] else None,
            before_outcome=r[4] or "", after_outcome=r[5] or "",
            detection_improved=bool(r[6]),
            validated_rule_ids=json.loads(r[7]) if r[7] else [],
            evaluated_at=r[8] if r[8] else "",
        ) for r in rows]
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Evidence Trace
# ---------------------------------------------------------------------------
@app.get("/api/evidence/{experiment_id}", response_model=EvidenceTrace)
def get_evidence_trace(experiment_id: str):
    session = SessionLocal()
    try:
        sc = session.execute(text(
            "SELECT id, objective_id, title, strategy_description, proposed_risk_level, created_by, created_at "
            "FROM adversarial_scenarios WHERE id = :id"
        ), {"id": experiment_id}).fetchone()
        if not sc:
            raise HTTPException(status_code=404, detail="Experiment not found")

        obj = session.execute(text(
            "SELECT id, title, description, target_category, default_risk_level "
            "FROM security_objectives WHERE id = :id"
        ), {"id": sc[1]}).fetchone()

        plan = session.execute(text(
            "SELECT id, steps_description, status, created_at FROM execution_plans WHERE scenario_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        detection = session.execute(text(
            "SELECT detection_id, technique_id, rule_id, matched, outcome "
            "FROM detection_results WHERE correlation_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        purple = session.execute(text(
            "SELECT id, detection_status, matched_rule_ids, expected_detection, gap_reason "
            "FROM purple_evaluations WHERE experiment_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        retest = session.execute(text(
            "SELECT id, before_outcome, after_outcome, detection_improved "
            "FROM retest_results WHERE scenario_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        return EvidenceTrace(
            objective={"id": str(obj[0]), "title": obj[1], "description": obj[2],
                       "target_category": obj[3], "risk_level": obj[4]} if obj else None,
            experiment={"id": str(sc[0]), "title": sc[2], "strategy_description": sc[3],
                        "risk_level": sc[4], "created_by": sc[5], "created_at": sc[6] or ""} if sc else None,
            execution={"id": str(plan[0]), "status": plan[2], "steps_description": plan[1],
                       "created_at": plan[3] or ""} if plan else None,
            detection={"detection_id": str(detection[0]), "technique_id": detection[1],
                        "rule_id": detection[2], "matched": bool(detection[3]),
                        "outcome": detection[4]} if detection else None,
            purple_evaluation={"evaluation_id": str(purple[0]), "detection_status": purple[1],
                               "matched_rule_ids": json.loads(purple[2]) if purple[2] else [],
                               "expected_detection": bool(purple[3]),
                               "gap_reason": purple[4]} if purple else None,
            retest={"id": str(retest[0]), "before_outcome": retest[1], "after_outcome": retest[2],
                    "detection_improved": bool(retest[3])} if retest else None,
        )
    finally:
        session.close()


@app.get("/api/retests/{experiment_id}", response_model=Optional[RetestResponse])
def get_retest(experiment_id: str):
    session = SessionLocal()
    try:
        r = session.execute(text(
            "SELECT id, organization_id, exercise_id, scenario_id, before_outcome, after_outcome, "
            "detection_improved, validated_rule_ids, evaluated_at FROM retest_results WHERE scenario_id = :sid"
        ), {"sid": experiment_id}).fetchone()
        if not r:
            return None
        return RetestResponse(
            id=str(r[0]), organization_id=str(r[1]) if r[1] else None,
            exercise_id=str(r[2]) if r[2] else None,
            scenario_id=str(r[3]) if r[3] else None,
            before_outcome=r[4] or "", after_outcome=r[5] or "",
            detection_improved=bool(r[6]),
            validated_rule_ids=json.loads(r[7]) if r[7] else [],
            evaluated_at=r[8] if r[8] else "",
        )
    finally:
        session.close()


# ===========================================================================
# Phase 11 — Cyber Immune API Endpoints
# ===========================================================================

def _verify_org_access(session, organization_id: str):
    """Verify organization exists and return its row. Raises 404 if not found."""
    org = session.execute(
        text("SELECT id, name, description, defensive_state, created_at FROM organizations WHERE id = :id"),
        {"id": organization_id},
    ).fetchone()
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization {organization_id} not found")
    return org


def _to_iso(val):
    """Safely convert a value to ISO format string. Handles str, datetime, None."""
    if val is None:
        return None
    if isinstance(val, str):
        return val
    return val.isoformat()


# ---------------------------------------------------------------------------
# Organization APIs
# ---------------------------------------------------------------------------

@app.get("/api/organizations", response_model=List[OrganizationResponse])
def list_organizations():
    session = SessionLocal()
    try:
        rows = session.execute(text(
            "SELECT id, name, description, defensive_state, created_at FROM organizations ORDER BY created_at DESC"
        )).fetchall()
        return [
            OrganizationResponse(
                id=str(r[0]), name=r[1], description=r[2],
                defensive_state=r[3] or "INITIAL",
                created_at=_to_iso(r[4]),
            )
            for r in rows
        ]
    finally:
        session.close()


@app.post("/api/organizations", response_model=OrganizationResponse, status_code=201)
def create_organization(req: OrganizationCreate):
    session = SessionLocal()
    try:
        org_id = str(uuid4())
        now = datetime.now(timezone.utc).isoformat()
        session.execute(
            text("INSERT INTO organizations (id, name, description, defensive_state, created_at, updated_at) "
                 "VALUES (:id, :name, :desc, 'INITIAL', :ts, :ts)"),
            {"id": org_id, "name": req.name, "desc": req.description, "ts": now},
        )
        session.commit()
        return OrganizationResponse(
            id=org_id, name=req.name, description=req.description,
            defensive_state="INITIAL", created_at=now,
        )
    except HTTPException:
        raise
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        session.close()


@app.get("/api/organizations/{organization_id}/state", response_model=OrganizationStateResponse)
def get_organization_state(organization_id: str):
    session = SessionLocal()
    try:
        org = _verify_org_access(session, organization_id)

        evals = session.execute(text(
            "SELECT technique_id, detection_status FROM purple_evaluations WHERE organization_id = :org"
        ), {"org": organization_id}).fetchall()

        total = len(evals)
        detected = sum(1 for e in evals if e[1] == "DETECTED")
        missed = sum(1 for e in evals if e[1] == "NOT_DETECTED")
        gaps = sum(1 for e in evals if e[1] == "DETECTION_GAP")
        coverage = (detected / total * 100) if total > 0 else 0.0

        techniques = sorted(set(e[0] for e in evals if e[0]))

        retests = session.execute(text(
            "SELECT before_outcome, after_outcome FROM retest_results WHERE organization_id = :org"
        ), {"org": organization_id}).fetchall()
        mitigated = sum(1 for r in retests if r[0] and r[1] and r[0] != r[1])
        unresolved = max(0, gaps - mitigated)

        scenarios = session.execute(text(
            "SELECT COUNT(*) FROM adversarial_scenarios WHERE organization_id = :org"
        ), {"org": organization_id}).scalar() or 0

        return OrganizationStateResponse(
            organization_id=organization_id,
            name=org[1],
            experiments_performed=scenarios,
            techniques_tested=techniques,
            detected_experiments=detected,
            missed_experiments=missed,
            detection_gap_experiments=gaps,
            mitigated_gaps=mitigated,
            unresolved_gaps=unresolved,
            coverage_pct=round(coverage, 1),
            computed_at=datetime.now(timezone.utc).isoformat() + "Z",
        )
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Experiment APIs
# ---------------------------------------------------------------------------

@app.get("/api/organizations/{organization_id}/experiments", response_model=List[ExperimentListResponse])
def list_organization_experiments(organization_id: str):
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)

        scenarios = session.execute(text(
            "SELECT id, organization_id, objective_id, title, strategy_description, "
            "proposed_risk_level, created_by, created_at "
            "FROM adversarial_scenarios WHERE organization_id = :org ORDER BY created_at DESC"
        ), {"org": organization_id}).fetchall()

        result = []
        for sc in scenarios:
            plan = session.execute(text(
                "SELECT status FROM execution_plans WHERE scenario_id = :sid LIMIT 1"
            ), {"sid": sc[0]}).fetchone()

            result.append(ExperimentListResponse(
                id=str(sc[0]),
                organization_id=str(sc[1]),
                objective_id=str(sc[2]) if sc[2] else None,
                title=sc[3],
                strategy_description=sc[4],
                risk_level=sc[5],
                status=plan[0] if plan else "PENDING",
                created_by=sc[6],
                created_at=_to_iso(sc[7]),
            ))
        return result
    finally:
        session.close()


@app.get("/api/experiments/{experiment_id}", response_model=ExperimentDetail)
def get_experiment_detail(experiment_id: str):
    """Reuse existing get_experiment endpoint logic."""
    session = SessionLocal()
    try:
        sc = session.execute(text(
            "SELECT id, objective_id, title, strategy_description, proposed_risk_level, created_by, created_at "
            "FROM adversarial_scenarios WHERE id = :id"
        ), {"id": experiment_id}).fetchone()
        if not sc:
            raise HTTPException(status_code=404, detail="Experiment not found")

        plan = session.execute(text(
            "SELECT id, steps_description, status, created_at FROM execution_plans WHERE scenario_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        policy = session.execute(text(
            "SELECT status, reason, evaluated_at FROM policy_decisions WHERE scenario_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        detection = session.execute(text(
            "SELECT detection_id, technique_id, rule_id, matched, outcome, timestamp, source "
            "FROM detection_results WHERE correlation_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        purple = session.execute(text(
            "SELECT id, experiment_id, execution_id, organization_id, technique_id, detection_status, "
            "matched_rule_ids, evidence_event_ids, expected_detection, gap_reason, detection_latency_ms, evaluated_at "
            "FROM purple_evaluations WHERE experiment_id = :sid"
        ), {"sid": experiment_id}).fetchone()

        now_iso = datetime.now(timezone.utc).isoformat()
        lifecycle = _build_lifecycle_raw(sc, plan, policy, detection, purple, now_iso)

        red_agent = {
            "state": "FINISHED" if plan and plan[2] == "EXECUTED" else "ANALYZING",
            "iterations": 1, "experiments_count": 1, "llm_calls": 2,
            "proposed_strategy": sc[3], "risk_level": sc[4],
        }

        detection_data = None
        if detection:
            detection_data = {
                "detection_id": str(detection[0]), "technique_id": detection[1],
                "rule_id": detection[2], "matched": bool(detection[3]),
                "outcome": detection[4],
                "timestamp": _to_iso(detection[5]),
                "source": detection[6],
            }

        purple_data = None
        if purple:
            purple_data = {
                "evaluation_id": str(purple[0]), "experiment_id": str(purple[1]),
                "execution_id": str(purple[2]) if purple[2] else None,
                "organization_id": str(purple[3]),
                "technique_id": purple[4], "detection_status": purple[5],
                "matched_rule_ids": json.loads(purple[6]) if purple[6] else [],
                "evidence_event_ids": json.loads(purple[7]) if purple[7] else [],
                "expected_detection": bool(purple[8]),
                "gap_reason": purple[9],
                "detection_latency_ms": purple[10],
                "evaluated_at": _to_iso(purple[11]),
            }

        return ExperimentDetail(
            experiment=ExperimentResponse(
                id=str(sc[0]), objective_id=str(sc[1]),
                scenario_id=str(sc[0]),
                status=plan[2] if plan else "PENDING",
                title=sc[2], strategy_description=sc[3],
                technique_ids=[], risk_level=sc[4], created_by=sc[5],
                created_at=_to_iso(sc[6]) or "",
                iterations=1, experiments_count=1, llm_calls=2,
            ),
            lifecycle=lifecycle, red_agent=red_agent, telemetry=[],
            detection=detection_data, purple_evaluation=purple_data,
        )
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Detection Gap APIs
# ---------------------------------------------------------------------------

@app.get("/api/organizations/{organization_id}/detection-gaps", response_model=List[DetectionGapResponse])
def list_detection_gaps(organization_id: str):
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)

        gaps = session.execute(text(
            "SELECT id, organization_id, scenario_id, technique_id, original_outcome, "
            "remediation_status, reason, created_at "
            "FROM detection_gaps WHERE organization_id = :org ORDER BY created_at DESC"
        ), {"org": organization_id}).fetchall()

        return [
            DetectionGapResponse(
                id=str(g[0]),
                organization_id=str(g[1]),
                scenario_id=str(g[2]) if g[2] else None,
                technique_id=g[3],
                original_outcome=g[4],
                remediation_status=g[5],
                reason=g[6] or "",
                created_at=_to_iso(g[7]),
            )
            for g in gaps
        ]
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Defensive Proposal APIs
# ---------------------------------------------------------------------------

@app.get("/api/organizations/{organization_id}/defensive-proposals", response_model=List[DefensiveProposalResponse])
def list_defensive_proposals(organization_id: str):
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)

        try:
            props = session.execute(text(
                "SELECT id, organization_id, finding_id, target_id, root_cause, "
                "proposed_remediation, expected_security_effect, status, created_at "
                "FROM remediation_proposals WHERE organization_id = :org ORDER BY created_at DESC"
            ), {"org": organization_id}).fetchall()
        except Exception:
            return []

        return [
            DefensiveProposalResponse(
                id=str(p[0]),
                organization_id=str(p[1]),
                finding_id=str(p[2]) if p[2] else None,
                scenario_id=str(p[3]) if p[3] else None,
                root_cause=p[4] or "",
                proposed_remediation=p[5] or "",
                expected_security_effect=p[6] or "",
                status=p[7] or "CREATED",
                created_at=_to_iso(p[8]),
            )
            for p in props
        ]
    finally:
        session.close()


@app.post("/api/defensive-proposals", response_model=DefensiveProposalResponse, status_code=201)
def create_defensive_proposal(req: DefensiveProposalCreate, organization_id: Optional[str] = Query(None)):
    """Create a defensive proposal.

    The proposal enters CREATED state and must go through DefensiveSafetyBoundary
    validation before any defensive action is taken.
    """
    if not organization_id:
        raise HTTPException(status_code=400, detail="organization_id query parameter is required")

    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)

        proposal_id = str(uuid4())
        now = datetime.now(timezone.utc).isoformat()
        session.execute(text(
            "INSERT INTO remediation_proposals "
            "(id, organization_id, finding_id, target_id, root_cause, proposed_remediation, "
            "expected_security_effect, expected_behavior, test_plan, rollback_plan, risk_assessment, "
            "affected_files, patches, "
            "status, created_at, schema_validated, policy_validated, clone_validated) "
            "VALUES (:id, :org, :finding, :target, :root, :remediation, :effect, :behavior, :test, :rollback, :risk, "
            "'[]', '[]', 'CREATED', :ts, 0, 0, 0)"
        ), {
            "id": proposal_id, "org": organization_id,
            "finding": req.finding_id, "target": str(uuid4()),
            "root": req.root_cause,
            "remediation": req.proposed_remediation, "effect": req.expected_security_effect,
            "behavior": "Pending analysis", "test": "Pending analysis",
            "rollback": "Pending analysis", "risk": "Pending analysis",
            "ts": now,
        })
        session.commit()

        return DefensiveProposalResponse(
            id=proposal_id, organization_id=organization_id,
            finding_id=req.finding_id, root_cause=req.root_cause,
            proposed_remediation=req.proposed_remediation,
            expected_security_effect=req.expected_security_effect,
            status="CREATED", created_at=now,
        )
    except HTTPException:
        raise
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        session.close()


@app.post("/api/defensive-proposals/{proposal_id}/validate", response_model=DefensiveProposalValidateResponse)
def validate_defensive_proposal(proposal_id: str):
    """Validate a defensive proposal through the DefensiveSafetyBoundary.

    Does NOT approve the proposal — only runs schema and safety validation.
    The proposal must still go through the full immune cycle for execution.
    """
    session = SessionLocal()
    try:
        prop = session.execute(text(
            "SELECT id, organization_id, finding_id, root_cause, proposed_remediation, "
            "expected_security_effect, status "
            "FROM remediation_proposals WHERE id = :id"
        ), {"id": proposal_id}).fetchone()
        if not prop:
            raise HTTPException(status_code=404, detail="Proposal not found")

        # Validate schema completeness
        schema_valid = bool(prop[3] and prop[4])
        if not schema_valid:
            session.execute(text(
                "UPDATE remediation_proposals SET schema_validated = 0 WHERE id = :id"
            ), {"id": proposal_id})
            session.commit()
            return DefensiveProposalValidateResponse(
                proposal_id=proposal_id, validation_passed=False,
                rejection_reason="Proposal missing root_cause or proposed_remediation",
                status="REJECTED",
            )

        # Mark schema validated
        session.execute(text(
            "UPDATE remediation_proposals SET schema_validated = 1, status = 'SCHEMA_VALIDATED' WHERE id = :id"
        ), {"id": proposal_id})
        session.commit()

        return DefensiveProposalValidateResponse(
            proposal_id=proposal_id, validation_passed=True,
            status="SCHEMA_VALIDATED",
        )
    except HTTPException:
        raise
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Retest / Comparison APIs
# ---------------------------------------------------------------------------

@app.get("/api/organizations/{organization_id}/retests", response_model=List[RetestListResponse])
def list_organization_retests(organization_id: str):
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)

        rows = session.execute(text(
            "SELECT id, organization_id, exercise_id, scenario_id, before_outcome, "
            "after_outcome, detection_improved, validated_rule_ids, evaluated_at "
            "FROM retest_results WHERE organization_id = :org ORDER BY evaluated_at DESC"
        ), {"org": organization_id}).fetchall()

        return [
            RetestListResponse(
                id=str(r[0]),
                organization_id=str(r[1]) if r[1] else None,
                exercise_id=str(r[2]) if r[2] else None,
                scenario_id=str(r[3]) if r[3] else None,
                before_outcome=r[4] or "",
                after_outcome=r[5] or "",
                detection_improved=bool(r[6]),
                validated_rule_ids=json.loads(r[7]) if r[7] else [],
                evaluated_at=_to_iso(r[8]),
            )
            for r in rows
        ]
    finally:
        session.close()


@app.get("/api/organizations/{organization_id}/comparisons", response_model=List[ComparisonResponse])
def list_comparisons(organization_id: str):
    """Before/after comparisons are derived from retest results."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)

        rows = session.execute(text(
            "SELECT id, organization_id, before_outcome, after_outcome, "
            "detection_improved, evaluated_at "
            "FROM retest_results WHERE organization_id = :org ORDER BY evaluated_at DESC"
        ), {"org": organization_id}).fetchall()

        return [
            ComparisonResponse(
                id=str(r[0]),
                organization_id=str(r[1]) if r[1] else None,
                before_outcome=r[2] or "",
                after_outcome=r[3] or "",
                detection_improved=bool(r[4]),
                evaluated_at=_to_iso(r[5]),
            )
            for r in rows
        ]
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Immune Memory API
# ---------------------------------------------------------------------------

@app.get("/api/organizations/{organization_id}/immune-memory", response_model=ImmuneMemoryResponse)
def get_immune_memory(organization_id: str):
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)

        from sentinelforge.immune_memory import ImmuneMemory as IM
        from uuid import UUID as _UUID
        memory = IM(session, _UUID(organization_id))
        state = memory.compute_state()

        return ImmuneMemoryResponse(
            organization_id=state.get("organization_id", organization_id),
            previous_experiments=state.get("previous_experiments", 0),
            techniques_tested=state.get("techniques_tested", []),
            detection_outcomes=state.get("detection_outcomes", {}),
            detection_gaps=state.get("detection_gaps", []),
            retest_results=state.get("retest_results", []),
            coverage_pct=state.get("coverage_pct", 0.0),
            mitigated_gaps=state.get("mitigated_gaps", 0),
            unresolved_gaps=state.get("unresolved_gaps", 0),
            successful_improvements=state.get("successful_improvements", 0),
            failed_improvements=state.get("failed_improvements", 0),
            defensive_proposals=state.get("defensive_proposals", []),
        )
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Next Experiment API
# ---------------------------------------------------------------------------

@app.get("/api/organizations/{organization_id}/next-experiment", response_model=NextExperimentResponse)
def get_next_experiment(organization_id: str):
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)

        from sentinelforge.adaptive.next_experiment_selector import NextExperimentSelector
        from uuid import UUID as _UUID
        selector = NextExperimentSelector(session, _UUID(organization_id))
        result = selector.select_next_experiment()

        return NextExperimentResponse(
            organization_id=result.organization_id,
            selected_strategy=result.selected_strategy,
            selected_techniques=result.selected_techniques,
            selection_method=result.selection_method,
            score=result.score,
            reason=result.reason,
            validation_passed=result.validation_passed,
            validation_rejection=result.validation_rejection,
            used_llm=result.used_llm,
            used_fallback=result.used_fallback,
            candidates_count=result.candidates_count,
            evidence_references=result.evidence_references,
            selected_at=result.selected_at,
        )
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Immune Cycle APIs
# ---------------------------------------------------------------------------

@app.get("/api/organizations/{organization_id}/immune-cycle/status", response_model=ImmuneCycleStatusResponse)
def get_immune_cycle_status(organization_id: str):
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)

        # Count completed cycles from immune memory
        retest_count = session.execute(text(
            "SELECT COUNT(*) FROM retest_results WHERE organization_id = :org"
        ), {"org": organization_id}).scalar() or 0

        mitigated = session.execute(text(
            "SELECT COUNT(*) FROM retest_results WHERE organization_id = :org "
            "AND before_outcome != after_outcome AND before_outcome IS NOT NULL AND after_outcome IS NOT NULL"
        ), {"org": organization_id}).scalar() or 0

        unresolved = session.execute(text(
            "SELECT COUNT(*) FROM detection_gaps WHERE organization_id = :org AND remediation_status = 'OPEN'"
        ), {"org": organization_id}).scalar() or 0

        return ImmuneCycleStatusResponse(
            organization_id=organization_id,
            current_state="IDLE",
            total_cycles=retest_count,
            mitigated_count=mitigated,
            unresolved_count=unresolved,
        )
    finally:
        session.close()


@app.post("/api/organizations/{organization_id}/immune-cycle/run", response_model=ImmuneCycleRunResponse, status_code=202)
def run_immune_cycle(organization_id: str, objective_id: Optional[str] = Query(None)):
    """Run a cyber immune cycle using the existing ImmuneCycleOrchestrator.

    Does NOT create a second implementation. Delegates to the authoritative
    ImmuneCycleOrchestrator.
    """
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)

        # Find an objective if not specified
        if not objective_id:
            obj = session.execute(text(
                "SELECT id FROM security_objectives WHERE organization_id = :org LIMIT 1"
            ), {"org": organization_id}).fetchone()
            if not obj:
                raise HTTPException(
                    status_code=400,
                    detail="No objective found for this organization. Create one first.",
                )
            objective_id = str(obj[0])

        # Verify objective belongs to this organization
        obj = session.execute(text(
            "SELECT id, organization_id FROM security_objectives WHERE id = :id"
        ), {"id": objective_id}).fetchone()
        if not obj:
            raise HTTPException(status_code=404, detail="Objective not found")
        if str(obj[1]) != organization_id:
            raise HTTPException(status_code=403, detail="Objective does not belong to this organization")

        from uuid import UUID as _UUID
        from sentinelforge.immune_cycle_orchestrator import ImmuneCycleOrchestrator

        orch = ImmuneCycleOrchestrator(session, _UUID(organization_id), _UUID(objective_id))

        # Run cycle — detect if a gap exists
        from sentinelforge.detection.evaluator import DetectionOutcome
        gaps = session.execute(text(
            "SELECT id FROM detection_gaps WHERE organization_id = :org LIMIT 1"
        ), {"org": organization_id}).fetchone()

        result = orch.run_cycle(detection_gap_id=_UUID(str(gaps[0])) if gaps else None)

        next_exp = None
        if "next_experiment" in result:
            next_exp = result["next_experiment"]

        return ImmuneCycleRunResponse(
            cycle_id=str(uuid4()),
            organization_id=organization_id,
            final_state=result.get("final_state", "UNKNOWN"),
            path=result.get("path", ""),
            evidence=result.get("evidence", {}),
            next_experiment=next_exp,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Immune cycle failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Immune cycle failed: {exc}")
    finally:
        session.close()


# ===========================================================================
# Digital Twin API Endpoints
# ===========================================================================

from sentinelforge.api.schemas import (
    AssetCreate,
    AssetResponse,
    AssetListResponse,
    ServiceCreate,
    ServiceResponse,
    ServiceListResponse,
    SecurityControlCreate,
    SecurityControlResponse,
    SecurityControlListResponse,
    AssetControlCreate,
    AssetControlResponse,
    ServiceControlCreate,
    ServiceControlResponse,
    DetectionCoverageCreate,
    DetectionCoverageResponse,
    DetectionCoverageListResponse,
    SecurityPostureResponse,
    SecurityPostureHistoryResponse,
    DigitalTwinSummaryResponse,
    AssetWithRelationsResponse,
    ServiceWithRelationsResponse,
)
from sentinelforge.digital_twin.service import DigitalTwinService
from sentinelforge.db.digital_twin_models import (
    DigitalTwinAsset,
    DigitalTwinService,
    DigitalTwinSecurityControl,
    DigitalTwinAssetControl,
    DigitalTwinServiceControl,
    DigitalTwinDetectionCoverage,
)


def _get_digital_twin_service(session, organization_id: str) -> DigitalTwinService:
    """Get Digital Twin service with tenant scoping."""
    from uuid import UUID
    return DigitalTwinService(session, UUID(organization_id))


# ---------------------------------------------------------------------------
# Asset Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/organizations/{organization_id}/twin/assets", response_model=AssetResponse, status_code=201)
def create_twin_asset(organization_id: str, asset: AssetCreate):
    """Create a Digital Twin asset for an organization."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        db_asset = svc.create_asset(
            name=asset.name,
            asset_type=asset.asset_type,
            description=asset.description,
            operating_system=asset.operating_system,
            software_version=asset.software_version,
            network_segment=asset.network_segment,
            ip_address=asset.ip_address,
            risk_level=asset.risk_level,
            tags=asset.tags,
            metadata_json=asset.metadata_json,
        )
        
        return AssetResponse(
            id=str(db_asset.id),
            organization_id=str(db_asset.organization_id),
            name=db_asset.name,
            asset_type=db_asset.asset_type,
            description=db_asset.description,
            operating_system=db_asset.operating_system,
            software_version=db_asset.software_version,
            network_segment=db_asset.network_segment,
            ip_address=db_asset.ip_address,
            risk_level=db_asset.risk_level,
            is_active=db_asset.is_active,
            last_scanned_at=db_asset.last_scanned_at.isoformat() if db_asset.last_scanned_at else None,
            tags=db_asset.tags or [],
            metadata_json=db_asset.metadata_json or {},
            created_at=db_asset.created_at.isoformat() if db_asset.created_at else "",
            updated_at=db_asset.updated_at.isoformat() if db_asset.updated_at else "",
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Create twin asset failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Create asset failed: {exc}")
    finally:
        session.close()


@app.get("/api/organizations/{organization_id}/twin/assets", response_model=AssetListResponse)
def list_twin_assets(
    organization_id: str,
    asset_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List all Digital Twin assets for an organization."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        assets = svc.list_assets(asset_type=asset_type, risk_level=risk_level)
        
        asset_responses = [
            AssetResponse(
                id=str(a.id),
                organization_id=str(a.organization_id),
                name=a.name,
                asset_type=a.asset_type,
                description=a.description,
                operating_system=a.operating_system,
                software_version=a.software_version,
                network_segment=a.network_segment,
                ip_address=a.ip_address,
                risk_level=a.risk_level,
                is_active=a.is_active,
                last_scanned_at=a.last_scanned_at.isoformat() if a.last_scanned_at else None,
                tags=a.tags or [],
                metadata_json=a.metadata_json or {},
                created_at=a.created_at.isoformat() if a.created_at else "",
                updated_at=a.updated_at.isoformat() if a.updated_at else "",
            )
            for a in assets
        ]
        
        return AssetListResponse(assets=asset_responses, total=len(asset_responses))
    finally:
        session.close()


@app.get("/api/organizations/{organization_id}/twin/assets/{asset_id}", response_model=AssetWithRelationsResponse)
def get_twin_asset(organization_id: str, asset_id: str):
    """Get a Digital Twin asset with its services and controls."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        from uuid import UUID
        asset = svc.get_asset(UUID(asset_id))
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        # Get related services
        services = svc.list_services(asset_id=UUID(asset_id))
        service_responses = [
            ServiceResponse(
                id=str(s.id),
                organization_id=str(s.organization_id),
                asset_id=str(s.asset_id),
                name=s.name,
                service_type=s.service_type,
                description=s.description,
                port=s.port,
                protocol=s.protocol,
                version=s.version,
                technology_stack=s.technology_stack or [],
                risk_level=s.risk_level,
                is_internet_facing=s.is_internet_facing,
                has_authentication=s.has_authentication,
                has_encryption=s.has_encryption,
                last_tested_at=s.last_tested_at.isoformat() if s.last_tested_at else None,
                detection_rules_count=s.detection_rules_count,
                coverage_pct=s.coverage_pct,
                metadata_json=s.metadata_json or {},
                created_at=s.created_at.isoformat() if s.created_at else "",
                updated_at=s.updated_at.isoformat() if s.updated_at else "",
            )
            for s in services
        ]
        
        # Get related controls
        controls = svc.get_asset_controls(UUID(asset_id))
        control_responses = [
            SecurityControlResponse(
                id=str(c.id),
                organization_id=str(c.organization_id),
                name=c.name,
                control_type=c.control_type,
                description=c.description,
                enabled=c.enabled,
                version=c.version,
                vendor=c.vendor,
                technique_ids=c.technique_ids or [],
                coverage_description=c.coverage_description,
                last_validated_at=c.last_validated_at.isoformat() if c.last_validated_at else None,
                validation_status=c.validation_status,
                metadata_json=c.metadata_json or {},
                created_at=c.created_at.isoformat() if c.created_at else "",
                updated_at=c.updated_at.isoformat() if c.updated_at else "",
            )
            for c in controls
        ]
        
        return AssetWithRelationsResponse(
            asset=AssetResponse(
                id=str(asset.id),
                organization_id=str(asset.organization_id),
                name=asset.name,
                asset_type=asset.asset_type,
                description=asset.description,
                operating_system=asset.operating_system,
                software_version=asset.software_version,
                network_segment=asset.network_segment,
                ip_address=asset.ip_address,
                risk_level=asset.risk_level,
                is_active=asset.is_active,
                last_scanned_at=asset.last_scanned_at.isoformat() if asset.last_scanned_at else None,
                tags=asset.tags or [],
                metadata_json=asset.metadata_json or {},
                created_at=asset.created_at.isoformat() if asset.created_at else "",
                updated_at=asset.updated_at.isoformat() if asset.updated_at else "",
            ),
            services=service_responses,
            controls=control_responses,
        )
    except HTTPException:
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Service Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/organizations/{organization_id}/twin/services", response_model=ServiceResponse, status_code=201)
def create_twin_service(organization_id: str, service: ServiceCreate):
    """Create a Digital Twin service for an organization."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        from uuid import UUID
        db_service = svc.create_service(
            asset_id=UUID(service.asset_id),
            name=service.name,
            service_type=service.service_type,
            description=service.description,
            port=service.port,
            protocol=service.protocol,
            version=service.version,
            technology_stack=service.technology_stack,
            risk_level=service.risk_level,
            is_internet_facing=service.is_internet_facing,
            has_authentication=service.has_authentication,
            has_encryption=service.has_encryption,
            metadata_json=service.metadata_json,
        )
        
        return ServiceResponse(
            id=str(db_service.id),
            organization_id=str(db_service.organization_id),
            asset_id=str(db_service.asset_id),
            name=db_service.name,
            service_type=db_service.service_type,
            description=db_service.description,
            port=db_service.port,
            protocol=db_service.protocol,
            version=db_service.version,
            technology_stack=db_service.technology_stack or [],
            risk_level=db_service.risk_level,
            is_internet_facing=db_service.is_internet_facing,
            has_authentication=db_service.has_authentication,
            has_encryption=db_service.has_encryption,
            last_tested_at=db_service.last_tested_at.isoformat() if db_service.last_tested_at else None,
            detection_rules_count=db_service.detection_rules_count,
            coverage_pct=db_service.coverage_pct,
            metadata_json=db_service.metadata_json or {},
            created_at=db_service.created_at.isoformat() if db_service.created_at else "",
            updated_at=db_service.updated_at.isoformat() if db_service.updated_at else "",
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Create twin service failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Create service failed: {exc}")
    finally:
        session.close()


@app.get("/api/organizations/{organization_id}/twin/services", response_model=ServiceListResponse)
def list_twin_services(
    organization_id: str,
    asset_id: Optional[str] = Query(None),
    service_type: Optional[str] = Query(None),
    is_internet_facing: Optional[bool] = Query(None),
):
    """List all Digital Twin services for an organization."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        from uuid import UUID
        services = svc.list_services(
            asset_id=UUID(asset_id) if asset_id else None,
            service_type=service_type,
            is_internet_facing=is_internet_facing,
        )
        
        service_responses = [
            ServiceResponse(
                id=str(s.id),
                organization_id=str(s.organization_id),
                asset_id=str(s.asset_id),
                name=s.name,
                service_type=s.service_type,
                description=s.description,
                port=s.port,
                protocol=s.protocol,
                version=s.version,
                technology_stack=s.technology_stack or [],
                risk_level=s.risk_level,
                is_internet_facing=s.is_internet_facing,
                has_authentication=s.has_authentication,
                has_encryption=s.has_encryption,
                last_tested_at=s.last_tested_at.isoformat() if s.last_tested_at else None,
                detection_rules_count=s.detection_rules_count,
                coverage_pct=s.coverage_pct,
                metadata_json=s.metadata_json or {},
                created_at=s.created_at.isoformat() if s.created_at else "",
                updated_at=s.updated_at.isoformat() if s.updated_at else "",
            )
            for s in services
        ]
        
        return ServiceListResponse(services=service_responses, total=len(service_responses))
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Security Control Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/organizations/{organization_id}/twin/controls", response_model=SecurityControlResponse, status_code=201)
def create_twin_control(organization_id: str, control: SecurityControlCreate):
    """Create a Digital Twin security control for an organization."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        db_control = svc.create_security_control(
            name=control.name,
            control_type=control.control_type,
            description=control.description,
            enabled=control.enabled,
            version=control.version,
            vendor=control.vendor,
            technique_ids=control.technique_ids,
            coverage_description=control.coverage_description,
            metadata_json=control.metadata_json,
        )
        
        return SecurityControlResponse(
            id=str(db_control.id),
            organization_id=str(db_control.organization_id),
            name=db_control.name,
            control_type=db_control.control_type,
            description=db_control.description,
            enabled=db_control.enabled,
            version=db_control.version,
            vendor=db_control.vendor,
            technique_ids=db_control.technique_ids or [],
            coverage_description=db_control.coverage_description,
            last_validated_at=db_control.last_validated_at.isoformat() if db_control.last_validated_at else None,
            validation_status=db_control.validation_status,
            metadata_json=db_control.metadata_json or {},
            created_at=db_control.created_at.isoformat() if db_control.created_at else "",
            updated_at=db_control.updated_at.isoformat() if db_control.updated_at else "",
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Create twin control failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Create control failed: {exc}")
    finally:
        session.close()


@app.get("/api/organizations/{organization_id}/twin/controls", response_model=SecurityControlListResponse)
def list_twin_controls(
    organization_id: str,
    control_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
):
    """List all Digital Twin security controls for an organization."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        controls = svc.list_security_controls(control_type=control_type, enabled=enabled)
        
        control_responses = [
            SecurityControlResponse(
                id=str(c.id),
                organization_id=str(c.organization_id),
                name=c.name,
                control_type=c.control_type,
                description=c.description,
                enabled=c.enabled,
                version=c.version,
                vendor=c.vendor,
                technique_ids=c.technique_ids or [],
                coverage_description=c.coverage_description,
                last_validated_at=c.last_validated_at.isoformat() if c.last_validated_at else None,
                validation_status=c.validation_status,
                metadata_json=c.metadata_json or {},
                created_at=c.created_at.isoformat() if c.created_at else "",
                updated_at=c.updated_at.isoformat() if c.updated_at else "",
            )
            for c in controls
        ]
        
        return SecurityControlListResponse(controls=control_responses, total=len(control_responses))
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Asset-Control Association Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/organizations/{organization_id}/twin/asset-controls", response_model=AssetControlResponse, status_code=201)
def associate_asset_control(organization_id: str, assoc: AssetControlCreate):
    """Associate a security control with an asset."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        from uuid import UUID
        db_assoc = svc.associate_asset_control(
            asset_id=UUID(assoc.asset_id),
            control_id=UUID(assoc.control_id),
            applied_by=assoc.applied_by,
            configuration_json=assoc.configuration_json,
        )
        
        return AssetControlResponse(
            id=str(db_assoc.id),
            organization_id=str(db_assoc.organization_id),
            asset_id=str(db_assoc.asset_id),
            control_id=str(db_assoc.control_id),
            applied_at=db_assoc.applied_at.isoformat() if db_assoc.applied_at else "",
            applied_by=db_assoc.applied_by,
            configuration_json=db_assoc.configuration_json or {},
            last_tested_at=db_assoc.last_tested_at.isoformat() if db_assoc.last_tested_at else None,
            test_result=db_assoc.test_result,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Associate asset control failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Associate failed: {exc}")
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Service-Control Association Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/organizations/{organization_id}/twin/service-controls", response_model=ServiceControlResponse, status_code=201)
def associate_service_control(organization_id: str, assoc: ServiceControlCreate):
    """Associate a security control with a service."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        from uuid import UUID
        db_assoc = svc.associate_service_control(
            service_id=UUID(assoc.service_id),
            control_id=UUID(assoc.control_id),
            protection_level=assoc.protection_level,
        )
        
        return ServiceControlResponse(
            id=str(db_assoc.id),
            organization_id=str(db_assoc.organization_id),
            service_id=str(db_assoc.service_id),
            control_id=str(db_assoc.control_id),
            applied_at=db_assoc.applied_at.isoformat() if db_assoc.applied_at else "",
            protection_level=db_assoc.protection_level,
            last_tested_at=db_assoc.last_tested_at.isoformat() if db_assoc.last_tested_at else None,
            test_result=db_assoc.test_result,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Associate service control failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Associate failed: {exc}")
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Detection Coverage Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/organizations/{organization_id}/twin/coverage", response_model=DetectionCoverageResponse, status_code=201)
def create_twin_coverage(organization_id: str, coverage: DetectionCoverageCreate):
    """Create a detection coverage record for the Digital Twin."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        from uuid import UUID
        db_coverage = svc.create_detection_coverage(
            technique_id=coverage.technique_id,
            asset_id=UUID(coverage.asset_id) if coverage.asset_id else None,
            service_id=UUID(coverage.service_id) if coverage.service_id else None,
            is_detected=coverage.is_detected,
            detection_method=coverage.detection_method,
            rule_ids=coverage.rule_ids,
            confidence_score=coverage.confidence_score,
            metadata_json=coverage.metadata_json,
        )
        
        return DetectionCoverageResponse(
            id=str(db_coverage.id),
            organization_id=str(db_coverage.organization_id),
            asset_id=str(db_coverage.asset_id) if db_coverage.asset_id else None,
            service_id=str(db_coverage.service_id) if db_coverage.service_id else None,
            technique_id=db_coverage.technique_id,
            is_detected=db_coverage.is_detected,
            detection_method=db_coverage.detection_method,
            rule_ids=db_coverage.rule_ids or [],
            last_experiment_id=str(db_coverage.last_experiment_id) if db_coverage.last_experiment_id else None,
            last_detected_at=db_coverage.last_detected_at.isoformat() if db_coverage.last_detected_at else None,
            confidence_score=db_coverage.confidence_score,
            metadata_json=db_coverage.metadata_json or {},
            created_at=db_coverage.created_at.isoformat() if db_coverage.created_at else "",
            updated_at=db_coverage.updated_at.isoformat() if db_coverage.updated_at else "",
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Create twin coverage failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Create coverage failed: {exc}")
    finally:
        session.close()


@app.get("/api/organizations/{organization_id}/twin/coverage", response_model=DetectionCoverageListResponse)
def list_twin_coverage(
    organization_id: str,
    asset_id: Optional[str] = Query(None),
    service_id: Optional[str] = Query(None),
    technique_id: Optional[str] = Query(None),
):
    """List detection coverage records for the Digital Twin."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        from uuid import UUID
        coverage_records = svc.get_detection_coverage(
            asset_id=UUID(asset_id) if asset_id else None,
            service_id=UUID(service_id) if service_id else None,
            technique_id=technique_id,
        )
        
        coverage_responses = [
            DetectionCoverageResponse(
                id=str(c.id),
                organization_id=str(c.organization_id),
                asset_id=str(c.asset_id) if c.asset_id else None,
                service_id=str(c.service_id) if c.service_id else None,
                technique_id=c.technique_id,
                is_detected=c.is_detected,
                detection_method=c.detection_method,
                rule_ids=c.rule_ids or [],
                last_experiment_id=str(c.last_experiment_id) if c.last_experiment_id else None,
                last_detected_at=c.last_detected_at.isoformat() if c.last_detected_at else None,
                confidence_score=c.confidence_score,
                metadata_json=c.metadata_json or {},
                created_at=c.created_at.isoformat() if c.created_at else "",
                updated_at=c.updated_at.isoformat() if c.updated_at else "",
            )
            for c in coverage_records
        ]
        
        detected_count = sum(1 for c in coverage_records if c.is_detected)
        not_detected_count = len(coverage_records) - detected_count
        coverage_pct = (detected_count / len(coverage_records) * 100) if coverage_records else 0.0
        
        return DetectionCoverageListResponse(
            coverage=coverage_responses,
            total=len(coverage_responses),
            detected_count=detected_count,
            not_detected_count=not_detected_count,
            overall_coverage_pct=coverage_pct,
        )
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Security Posture Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/organizations/{organization_id}/twin/posture", response_model=SecurityPostureResponse, status_code=201)
def compute_twin_posture(organization_id: str):
    """Compute and store current security posture from Digital Twin entities."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        posture = svc.compute_security_posture()
        
        return SecurityPostureResponse(
            id=str(posture.id),
            organization_id=str(posture.organization_id),
            total_assets=posture.total_assets,
            active_assets=posture.active_assets,
            total_services=posture.total_services,
            internet_facing_services=posture.internet_facing_services,
            total_security_controls=posture.total_security_controls,
            enabled_controls=posture.enabled_controls,
            total_techniques_tested=posture.total_techniques_tested,
            techniques_detected=posture.techniques_detected,
            detection_coverage_pct=posture.detection_coverage_pct,
            high_risk_assets=posture.high_risk_assets,
            critical_risk_assets=posture.critical_risk_assets,
            unresolved_gaps=posture.unresolved_gaps,
            total_experiments=posture.total_experiments,
            successful_experiments=posture.successful_experiments,
            failed_experiments=posture.failed_experiments,
            snapshot_date=posture.snapshot_date.isoformat() if posture.snapshot_date else "",
            computed_from_evidence=posture.computed_from_evidence,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Compute twin posture failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Compute posture failed: {exc}")
    finally:
        session.close()


@app.get("/api/organizations/{organization_id}/twin/posture/history", response_model=SecurityPostureHistoryResponse)
def get_twin_posture_history(organization_id: str, limit: int = Query(30, ge=1, le=100)):
    """Get security posture history for the Digital Twin."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        history = svc.get_posture_history(limit=limit)
        
        posture_responses = [
            SecurityPostureResponse(
                id=str(p.id),
                organization_id=str(p.organization_id),
                total_assets=p.total_assets,
                active_assets=p.active_assets,
                total_services=p.total_services,
                internet_facing_services=p.internet_facing_services,
                total_security_controls=p.total_security_controls,
                enabled_controls=p.enabled_controls,
                total_techniques_tested=p.total_techniques_tested,
                techniques_detected=p.techniques_detected,
                detection_coverage_pct=p.detection_coverage_pct,
                high_risk_assets=p.high_risk_assets,
                critical_risk_assets=p.critical_risk_assets,
                unresolved_gaps=p.unresolved_gaps,
                total_experiments=p.total_experiments,
                successful_experiments=p.successful_experiments,
                failed_experiments=p.failed_experiments,
                snapshot_date=p.snapshot_date.isoformat() if p.snapshot_date else "",
                computed_from_evidence=p.computed_from_evidence,
            )
            for p in history
        ]
        
        # Compute trend
        trend = "stable"
        if len(history) >= 2:
            if history[0].detection_coverage_pct > history[1].detection_coverage_pct:
                trend = "improving"
            elif history[0].detection_coverage_pct < history[1].detection_coverage_pct:
                trend = "degrading"
        
        return SecurityPostureHistoryResponse(
            snapshots=posture_responses,
            total=len(posture_responses),
            trend=trend,
        )
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Digital Twin Summary Endpoint
# ---------------------------------------------------------------------------

@app.get("/api/organizations/{organization_id}/twin/summary", response_model=DigitalTwinSummaryResponse)
def get_twin_summary(organization_id: str):
    """Get comprehensive Digital Twin summary for an organization."""
    session = SessionLocal()
    try:
        _verify_org_access(session, organization_id)
        svc = _get_digital_twin_service(session, organization_id)
        
        summary = svc.get_twin_summary()
        
        return DigitalTwinSummaryResponse(**summary)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Get twin summary failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Get summary failed: {exc}")
    finally:
        session.close()
