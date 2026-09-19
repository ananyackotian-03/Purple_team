"""Phase 12E — API Security.

Attack the Phase 11 APIs to bypass security.
"""

import pytest
from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import sentinelforge.api.app as app_module
from sentinelforge.db.models import Base

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)


@pytest.fixture(scope="module")
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import sentinelforge.db.models
    import sentinelforge.remediation.db_models
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture(scope="module")
def seed(engine):
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    s = Session()
    org_id = str(uuid4())
    now = "2024-01-01T00:00:00Z"
    s.execute(
        text("INSERT INTO organizations (id, name, defensive_state, created_at, updated_at) "
             "VALUES (:id, :name, 'INITIAL', :ts, :ts)"),
        {"id": org_id, "name": "TestOrg", "ts": now},
    )
    obj_id = str(uuid4())
    s.execute(
        text("INSERT INTO security_objectives (id, organization_id, title, description, target_category, default_risk_level, created_at) "
             "VALUES (:id, :org, 'Obj', 'desc', 'linux_host', 'LOW', :ts)"),
        {"id": obj_id, "org": org_id, "ts": now},
    )
    s.commit()
    s.close()
    return {"org": org_id, "obj": obj_id}


@pytest.fixture(scope="module")
def client(engine, seed):
    app_module.engine = engine
    app_module.SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    app_module._seed_demo_data = lambda: None
    with TestClient(app_module.app, raise_server_exceptions=False) as c:
        yield c


class TestMalformedUUID:
    def test_invalid_uuid_organization_state(self, client):
        resp = client.get("/api/organizations/not-a-uuid/state")
        assert resp.status_code in (404, 422)

    def test_invalid_uuid_experiments(self, client):
        resp = client.get("/api/organizations/not-a-uuid/experiments")
        assert resp.status_code in (404, 422)

    def test_invalid_uuid_detection_gaps(self, client):
        resp = client.get("/api/organizations/not-a-uuid/detection-gaps")
        assert resp.status_code in (404, 422)


class TestNonexistentResources:
    def test_nonexistent_organization_state(self, client):
        resp = client.get(f"/api/organizations/{uuid4()}/state")
        assert resp.status_code == 404

    def test_nonexistent_experiment(self, client):
        resp = client.get(f"/api/experiments/{uuid4()}")
        assert resp.status_code == 404

    def test_nonexistent_proposal_validation(self, client):
        resp = client.post(f"/api/defensive-proposals/{uuid4()}/validate")
        assert resp.status_code == 404


class TestMissingRequiredParams:
    def test_create_organization_missing_name(self, client):
        resp = client.post("/api/organizations", json={})
        assert resp.status_code == 422

    def test_create_objective_missing_title(self, client):
        resp = client.post("/api/objectives", json={"description": "no title"})
        assert resp.status_code == 422

    def test_create_proposal_missing_org(self, client):
        resp = client.post("/api/defensive-proposals", json={
            "finding_id": str(uuid4()),
            "root_cause": "test",
            "proposed_remediation": "test",
            "expected_security_effect": "test",
        })
        assert resp.status_code == 400

    def test_create_proposal_invalid_org(self, client):
        resp = client.post(
            f"/api/defensive-proposals?organization_id={uuid4()}",
            json={
                "finding_id": str(uuid4()),
                "root_cause": "test",
                "proposed_remediation": "test",
                "expected_security_effect": "test",
            },
        )
        assert resp.status_code == 404


class TestInvalidStateTransitions:
    def test_run_cycle_no_objective(self, client):
        resp = client.post(f"/api/organizations/{uuid4()}/immune-cycle/run")
        assert resp.status_code in (400, 404)


class TestDirectMitigationAttempt:
    def test_no_mitigate_endpoint(self, client, seed):
        resp = client.post(f"/api/organizations/{seed['org']}/detection-gaps/mitigate")
        assert resp.status_code == 404

    def test_no_direct_gap_status_change(self, client, seed):
        resp = client.put(
            f"/api/organizations/{seed['org']}/detection-gaps/{uuid4()}",
            json={"remediation_status": "MITIGATED"},
        )
        assert resp.status_code == 404


class TestFabricatedDataRejection:
    def test_no_direct_retest_creation(self, client, seed):
        resp = client.post(
            f"/api/organizations/{seed['org']}/retests",
            json={"before_outcome": "NOT_DETECTED", "after_outcome": "DETECTED"},
        )
        assert resp.status_code in (404, 405, 422)


class TestProposalIdempotency:
    def test_validate_nonexistent_proposal(self, client):
        resp = client.post(f"/api/defensive-proposals/{uuid4()}/validate")
        assert resp.status_code == 404

    def test_create_proposal_with_valid_org(self, client, seed):
        resp = client.post(
            f"/api/defensive-proposals?organization_id={seed['org']}",
            json={
                "finding_id": str(uuid4()),
                "root_cause": "Missing detection",
                "proposed_remediation": "Add rule",
                "expected_security_effect": "Improved detection",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "CREATED"


class TestNoStackTracesInErrors:
    def test_error_response_no_traceback(self, client, seed):
        resp = client.get(f"/api/organizations/{uuid4()}/state")
        if resp.status_code >= 400:
            body = resp.text
            assert "Traceback" not in body
            assert "File \"" not in body
            assert "line " not in body
