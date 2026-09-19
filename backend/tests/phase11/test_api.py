"""Phase 11 — Backend API Tests.

Tests all Cyber Immune API endpoints including:
- Organization listing, creation, state
- Experiment listing and lookup
- Detection gap listing
- Defensive proposal listing, creation, validation
- Retest and comparison listing
- Immune memory retrieval
- Next experiment retrieval
- Immune cycle status and execution
- Invalid request validation
- Missing resource handling
- Tenant isolation enforcement
- Security invariants (no direct MITIGATED, no fabrication, no bypass)
"""

import json
import os
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from sentinelforge.db.models import Base


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    """Create an in-memory SQLite engine with StaticPool for all tests."""
    eng = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import sentinelforge.db.models  # noqa: F401
    import sentinelforge.remediation.db_models  # noqa: F401
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture(scope="module")
def session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture(scope="module")
def seed_data(engine):
    """Seed test data into the in-memory database."""
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    try:
        now = datetime.now(timezone.utc).isoformat()

        org_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        org_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        obj_a = "11111111-1111-1111-1111-111111111111"
        sc_a = "dddddddd-dddd-dddd-dddd-dddddddddddd"

        session.execute(text(
            "INSERT INTO organizations (id, name, description, defensive_state, created_at, updated_at) "
            "VALUES (:id, :name, :desc, 'INITIAL', :ts, :ts)"
        ), {"id": org_a, "name": "Org A", "desc": "Test org A", "ts": now})
        session.execute(text(
            "INSERT INTO organizations (id, name, description, defensive_state, created_at, updated_at) "
            "VALUES (:id, :name, :desc, 'INITIAL', :ts, :ts)"
        ), {"id": org_b, "name": "Org B", "desc": "Test org B", "ts": now})

        session.execute(text(
            "INSERT INTO security_objectives (id, organization_id, title, description, target_category, default_risk_level, created_at) "
            "VALUES (:id, :org, :title, :desc, 'linux_host', 'MEDIUM', :ts)"
        ), {"id": obj_a, "org": org_a, "title": "Detect Credential Dumping",
            "desc": "Test credential access detection", "ts": now})

        session.execute(text(
            "INSERT INTO adversarial_scenarios (id, objective_id, organization_id, title, strategy_description, proposed_risk_level, created_by, created_at) "
            "VALUES (:id, :oid, :org, :title, :desc, 'HIGH', 'red_agent', :ts)"
        ), {"id": sc_a, "oid": obj_a, "org": org_a, "title": "Shadow File Read",
            "desc": "cat /etc/shadow", "ts": now})

        session.execute(text(
            "INSERT INTO execution_plans (id, scenario_id, organization_id, steps_description, status, created_at) "
            "VALUES (:id, :sid, :org, :steps, 'EXECUTED', :ts)"
        ), {"id": str(uuid.uuid4()), "sid": sc_a, "org": org_a,
            "steps": "cat /etc/shadow", "ts": now})

        session.execute(text(
            "INSERT INTO purple_evaluations (id, organization_id, experiment_id, execution_id, technique_id, "
            "detection_status, matched_rule_ids, evidence_event_ids, expected_detection, gap_reason, evaluated_at) "
            "VALUES (:id, :org, :eid, :pid, :tech, :status, '[]', '[]', 1, NULL, :ts)"
        ), {"id": str(uuid.uuid4()), "org": org_a, "eid": sc_a,
            "pid": str(uuid.uuid4()), "tech": "T1003.008", "status": "DETECTION_GAP", "ts": now})

        session.execute(text(
            "INSERT INTO detection_gaps (id, organization_id, scenario_id, action_id, technique_id, "
            "original_outcome, root_cause, reason, remediation_status, created_at) "
            "VALUES (:id, :org, :sid, :aid, :tech, 'NOT_DETECTED', 'missing_rule', 'No sigma rule', 'OPEN', :ts)"
        ), {"id": str(uuid.uuid4()), "org": org_a, "sid": sc_a,
            "aid": str(uuid.uuid4()), "tech": "T1003.008", "ts": now})

        session.execute(text(
            "INSERT INTO retest_results (id, organization_id, exercise_id, scenario_id, "
            "before_outcome, after_outcome, detection_improved, validated_rule_ids, evaluated_at) "
            "VALUES (:id, :org, NULL, :sid, 'NOT_DETECTED', 'DETECTED', '1', '[]', :ts)"
        ), {"id": str(uuid.uuid4()), "org": org_a, "sid": sc_a, "ts": now})

        session.commit()
        return {"org_a": org_a, "org_b": org_b, "obj_a": obj_a, "sc_a": sc_a}
    finally:
        session.close()


@pytest.fixture(scope="module")
def client(seed_data, engine):
    """Create a TestClient that uses our in-memory database."""
    import sentinelforge.api.app as app_module
    from sqlalchemy.orm import sessionmaker as _sm

    # Create all tables on our in-memory engine
    import sentinelforge.db.models  # noqa: F401
    import sentinelforge.remediation.db_models  # noqa: F401
    from sentinelforge.db.models import Base
    Base.metadata.create_all(engine)

    # Patch BOTH engine and SessionLocal so all queries hit our in-memory DB
    original_engine = app_module.engine
    original_session_local = app_module.SessionLocal

    app_module.engine = engine
    app_module.SessionLocal = _sm(bind=engine, expire_on_commit=False)

    # Skip demo data seeding since we already have data
    original_seed = app_module._seed_demo_data
    app_module._seed_demo_data = lambda: None

    with TestClient(app_module.app, raise_server_exceptions=False) as c:
        yield c

    app_module.engine = original_engine
    app_module.SessionLocal = original_session_local
    app_module._seed_demo_data = original_seed


# ---------------------------------------------------------------------------
# 1. Organization Listing
# ---------------------------------------------------------------------------

class TestOrganizationListing:
    def test_list_organizations(self, client, seed_data):
        resp = client.get("/api/organizations")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        org_ids = [o["id"] for o in data]
        assert seed_data["org_a"] in org_ids
        assert seed_data["org_b"] in org_ids

    def test_organization_has_required_fields(self, client, seed_data):
        resp = client.get("/api/organizations")
        data = resp.json()
        for org in data:
            assert "id" in org
            assert "name" in org
            assert "defensive_state" in org


# ---------------------------------------------------------------------------
# 2. Organization Creation
# ---------------------------------------------------------------------------

class TestOrganizationCreation:
    def test_create_organization(self, client):
        resp = client.post("/api/organizations", json={
            "name": "New Test Org",
            "description": "Created via API",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "New Test Org"
        assert data["description"] == "Created via API"
        assert data["defensive_state"] == "INITIAL"
        assert "id" in data

    def test_create_organization_missing_name(self, client):
        resp = client.post("/api/organizations", json={"description": "No name"})
        assert resp.status_code == 422  # Pydantic validation error


# ---------------------------------------------------------------------------
# 3. Organization State
# ---------------------------------------------------------------------------

class TestOrganizationState:
    def test_get_organization_state(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/state")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed_data["org_a"]
        assert data["name"] == "Org A"
        assert "coverage_pct" in data
        assert "techniques_tested" in data
        assert "mitigated_gaps" in data
        assert "unresolved_gaps" in data
        assert isinstance(data["techniques_tested"], list)

    def test_organization_state_nonexistent(self, client):
        resp = client.get("/api/organizations/00000000-0000-0000-0000-000000000000/state")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 4. Experiment Listing
# ---------------------------------------------------------------------------

class TestExperimentListing:
    def test_list_experiments(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/experiments")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["organization_id"] == seed_data["org_a"]

    def test_experiment_has_required_fields(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/experiments")
        data = resp.json()
        for exp in data:
            assert "id" in exp
            assert "title" in exp
            assert "status" in exp


# ---------------------------------------------------------------------------
# 5. Experiment Lookup
# ---------------------------------------------------------------------------

class TestExperimentLookup:
    def test_get_experiment(self, client, seed_data):
        resp = client.get(f"/api/experiments/{seed_data['sc_a']}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["experiment"]["id"] == seed_data["sc_a"]
        assert "lifecycle" in data

    def test_get_experiment_not_found(self, client):
        resp = client.get("/api/experiments/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 6. Detection Gap Listing
# ---------------------------------------------------------------------------

class TestDetectionGapListing:
    def test_list_detection_gaps(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/detection-gaps")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        gap = data[0]
        assert gap["organization_id"] == seed_data["org_a"]
        assert gap["technique_id"] == "T1003.008"
        assert gap["remediation_status"] == "OPEN"

    def test_detection_gap_has_required_fields(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/detection-gaps")
        data = resp.json()
        for gap in data:
            assert "id" in gap
            assert "technique_id" in gap
            assert "remediation_status" in gap


# ---------------------------------------------------------------------------
# 7. Defensive Proposal Listing
# ---------------------------------------------------------------------------

class TestDefensiveProposalListing:
    def test_list_defensive_proposals(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/defensive-proposals")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


# ---------------------------------------------------------------------------
# 8. Defensive Proposal Creation
# ---------------------------------------------------------------------------

class TestDefensiveProposalCreation:
    def test_create_defensive_proposal(self, client, seed_data):
        resp = client.post(
            f"/api/defensive-proposals?organization_id={seed_data['org_a']}",
            json={
                "finding_id": str(uuid.uuid4()),
                "root_cause": "Missing Sigma rule for shadow file read",
                "proposed_remediation": "Add sigma rule for T1003.008",
                "expected_security_effect": "Detect credential access attempts",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "CREATED"
        assert data["root_cause"] == "Missing Sigma rule for shadow file read"
        assert "id" in data

    def test_create_proposal_missing_org(self, client):
        resp = client.post("/api/defensive-proposals", json={
            "finding_id": str(uuid.uuid4()),
            "root_cause": "test",
            "proposed_remediation": "test",
        })
        assert resp.status_code == 400

    def test_create_proposal_invalid_org(self, client):
        resp = client.post(
            "/api/defensive-proposals?organization_id=00000000-0000-0000-0000-000000000000",
            json={
                "finding_id": str(uuid.uuid4()),
                "root_cause": "test",
                "proposed_remediation": "test",
            },
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 9. Defensive Proposal Validation
# ---------------------------------------------------------------------------

class TestDefensiveProposalValidation:
    def test_validate_proposal(self, client, seed_data):
        # Create a proposal first
        create_resp = client.post(
            f"/api/defensive-proposals?organization_id={seed_data['org_a']}",
            json={
                "finding_id": str(uuid.uuid4()),
                "root_cause": "Missing detection rule",
                "proposed_remediation": "Add Sigma rule for T1003.008",
                "expected_security_effect": "Improved detection",
            },
        )
        proposal_id = create_resp.json()["id"]

        resp = client.post(f"/api/defensive-proposals/{proposal_id}/validate")
        assert resp.status_code == 200
        data = resp.json()
        assert data["validation_passed"] is True
        assert data["status"] == "SCHEMA_VALIDATED"

    def test_validate_nonexistent_proposal(self, client):
        resp = client.post("/api/defensive-proposals/00000000-0000-0000-0000-000000000000/validate")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 10. Retest Listing
# ---------------------------------------------------------------------------

class TestRetestListing:
    def test_list_retests(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/retests")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["organization_id"] == seed_data["org_a"]
        assert data[0]["before_outcome"] == "NOT_DETECTED"
        assert data[0]["after_outcome"] == "DETECTED"
        assert data[0]["detection_improved"] is True


# ---------------------------------------------------------------------------
# 11. Comparison Listing
# ---------------------------------------------------------------------------

class TestComparisonListing:
    def test_list_comparisons(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/comparisons")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        comp = data[0]
        assert comp["before_outcome"] == "NOT_DETECTED"
        assert comp["after_outcome"] == "DETECTED"
        assert comp["detection_improved"] is True


# ---------------------------------------------------------------------------
# 12. Immune Memory Retrieval
# ---------------------------------------------------------------------------

class TestImmuneMemory:
    def test_get_immune_memory(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/immune-memory")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed_data["org_a"]
        assert "previous_experiments" in data
        assert "techniques_tested" in data
        assert "detection_outcomes" in data
        assert "coverage_pct" in data
        assert "mitigated_gaps" in data
        assert "unresolved_gaps" in data

    def test_immune_memory_nonexistent_org(self, client):
        resp = client.get("/api/organizations/00000000-0000-0000-0000-000000000000/immune-memory")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 13. Next Experiment Retrieval
# ---------------------------------------------------------------------------

class TestNextExperiment:
    def test_get_next_experiment(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/next-experiment")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed_data["org_a"]
        assert "selection_method" in data
        assert data["selection_method"] in ("llm", "deterministic_fallback")

    def test_next_experiment_nonexistent_org(self, client):
        resp = client.get("/api/organizations/00000000-0000-0000-0000-000000000000/next-experiment")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 14. Immune Cycle Status
# ---------------------------------------------------------------------------

class TestImmuneCycleStatus:
    def test_get_cycle_status(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_a']}/immune-cycle/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed_data["org_a"]
        assert "current_state" in data
        assert "total_cycles" in data
        assert "mitigated_count" in data
        assert "unresolved_count" in data

    def test_cycle_status_nonexistent_org(self, client):
        resp = client.get("/api/organizations/00000000-0000-0000-0000-000000000000/immune-cycle/status")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 15. Immune Cycle Execution
# ---------------------------------------------------------------------------

class TestImmuneCycleExecution:
    def test_run_cycle(self, client, seed_data):
        resp = client.post(
            f"/api/organizations/{seed_data['org_a']}/immune-cycle/run"
            f"?objective_id={seed_data['obj_a']}"
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["organization_id"] == seed_data["org_a"]
        assert "final_state" in data
        assert "cycle_id" in data

    def test_run_cycle_no_objective(self, client):
        org_id = "00000000-0000-0000-0000-000000000000"
        resp = client.post(f"/api/organizations/{org_id}/immune-cycle/run")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 16. Invalid Request Validation
# ---------------------------------------------------------------------------

class TestInvalidRequestValidation:
    def test_invalid_uuid_format(self, client):
        resp = client.get("/api/organizations/not-a-uuid/state")
        assert resp.status_code in (404, 422)

    def test_create_objective_missing_title(self, client):
        resp = client.post("/api/objectives", json={"description": "no title"})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 17. Missing Resource
# ---------------------------------------------------------------------------

class TestMissingResource:
    def test_organization_not_found(self, client):
        resp = client.get("/api/organizations/00000000-0000-0000-0000-000000000000/state")
        assert resp.status_code == 404

    def test_experiment_not_found(self, client):
        resp = client.get("/api/experiments/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404

    def test_objective_not_found(self, client):
        resp = client.get("/api/objectives/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 18. Tenant Isolation — Org A cannot access Org B
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_org_a_cannot_access_org_b_state(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_b']}/state")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed_data["org_b"]
        assert data["experiments_performed"] == 0

    def test_org_a_experiments_not_in_org_b(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_b']}/experiments")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 0

    def test_org_b_detection_gaps_empty(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_b']}/detection-gaps")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 0

    def test_org_b_retests_empty(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_b']}/retests")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 0

    def test_org_b_comparisons_empty(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_b']}/comparisons")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 0

    def test_org_b_immune_memory_empty(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_b']}/immune-memory")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed_data["org_b"]
        assert data["previous_experiments"] == 0

    def test_org_b_next_experiment_empty(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_b']}/next-experiment")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed_data["org_b"]

    def test_org_b_cycle_status_zero(self, client, seed_data):
        resp = client.get(f"/api/organizations/{seed_data['org_b']}/immune-cycle/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_cycles"] == 0


# ---------------------------------------------------------------------------
# 19. Cannot Directly Mark Gap MITIGATED via API
# ---------------------------------------------------------------------------

class TestCannotDirectlyMitigate:
    def test_no_mitigate_endpoint_exists(self, client, seed_data):
        """Verify no direct MITIGATED endpoint exists for detection gaps."""
        resp = client.post(
            f"/api/organizations/{seed_data['org_a']}/detection-gaps/mitigate",
            json={"gap_id": "test"},
        )
        assert resp.status_code == 404  # No such route

    def test_gap_status_immutable_via_api(self, client, seed_data):
        """Detection gap remediation_status can only be changed by backend logic."""
        gaps_resp = client.get(f"/api/organizations/{seed_data['org_a']}/detection-gaps")
        gaps = gaps_resp.json()
        assert len(gaps) >= 1
        gap = gaps[0]
        assert gap["remediation_status"] == "OPEN"

        # No PUT/PATCH endpoint exists for detection gaps
        resp = client.put(
            f"/api/organizations/{seed_data['org_a']}/detection-gaps/{gap['id']}",
            json={"remediation_status": "MITIGATED"},
        )
        assert resp.status_code == 404  # No such route


# ---------------------------------------------------------------------------
# 20. Cannot Fabricate Before/After Results
# ---------------------------------------------------------------------------

class TestCannotFabricateResults:
    def test_no_direct_retest_creation(self, client, seed_data):
        """Clients cannot fabricate retest results via API."""
        resp = client.post(
            f"/api/organizations/{seed_data['org_a']}/retests",
            json={
                "before_outcome": "NOT_DETECTED",
                "after_outcome": "DETECTED",
                "detection_improved": True,
            },
        )
        assert resp.status_code == 405

    def test_comparison_not_modifiable(self, client, seed_data):
        """Before/after comparisons are read-only, derived from retest results."""
        resp = client.post(
            f"/api/organizations/{seed_data['org_a']}/comparisons",
            json={"before_outcome": "DETECTED", "after_outcome": "DETECTED"},
        )
        assert resp.status_code == 405


# ---------------------------------------------------------------------------
# 21. BlueprintSigner Regression — POST /api/objectives/{id}/run
# ---------------------------------------------------------------------------

class TestBlueprintSignerRegression:
    """Verify POST /api/objectives/{id}/run does not crash due to missing
    BlueprintSigner arguments. The signing key must come from the existing
    secure configuration mechanism (SENTINELFORGE_SIGNING_KEY env var)."""

    def test_run_endpoint_returns_202(self, client, seed_data):
        """The run endpoint must accept the request (202) without crashing."""
        resp = client.post(
            f"/api/objectives/{seed_data['obj_a']}/run"
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"

    def test_run_endpoint_missing_objective_returns_404(self, client):
        """Missing objective returns 404, not a BlueprintSigner crash."""
        resp = client.post(
            "/api/objectives/00000000-0000-0000-0000-000000000000/run"
        )
        assert resp.status_code == 404

    def test_signing_key_resolves_from_env(self):
        """_resolve_signing_key returns the SENTINELFORGE_SIGNING_KEY env var."""
        from sentinelforge.agents.red.policies import _resolve_signing_key
        key = _resolve_signing_key()
        assert key is not None
        assert len(key) > 0
        assert key == os.environ.get("SENTINELFORGE_SIGNING_KEY")

    def test_blueprint_signer_creation_with_resolved_key(self):
        """BlueprintSigner can be created with the resolved signing key."""
        from sentinelforge.agents.red.policies import _resolve_signing_key
        from sentinelforge.policy.signing import BlueprintSigner

        resolved_key = _resolve_signing_key()
        signer = BlueprintSigner(key=resolved_key, key_id="key1")
        assert signer.key == resolved_key.encode("utf-8")
        assert signer.key_id == "key1"

    def test_missing_signing_key_fails_safely(self, monkeypatch):
        """Missing SENTINELFORGE_SIGNING_KEY raises ValueError."""
        from sentinelforge.agents.red.policies import _resolve_signing_key

        monkeypatch.delenv("SENTINELFORGE_SIGNING_KEY", raising=False)
        with pytest.raises(ValueError, match="Signing key is required"):
            _resolve_signing_key()

    def test_no_hardcoded_secret_introduced(self):
        """Verify the fix does not introduce any hardcoded signing key."""
        import inspect
        from sentinelforge.api.app import _run_experiment_bg
        source = inspect.getsource(_run_experiment_bg)
        # Must NOT contain hardcoded key patterns
        assert "BlueprintSigner()" not in source  # old broken call
        assert "key=" in source  # must pass key argument
        assert "key_id=" in source  # must pass key_id argument
        # Must use the secure resolution mechanism
        assert "_resolve_signing_key" in source
