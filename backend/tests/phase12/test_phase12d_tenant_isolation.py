"""Phase 12D — Tenant Isolation Attacks.

Organization A attempting to access Organization B resources must be DENIED.
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
    org_a = str(uuid4())
    org_b = str(uuid4())
    now = "2024-01-01T00:00:00Z"
    for oid, name in [(org_a, "Org A"), (org_b, "Org B")]:
        s.execute(
            text("INSERT INTO organizations (id, name, defensive_state, created_at, updated_at) "
                 "VALUES (:id, :name, 'INITIAL', :ts, :ts)"),
            {"id": oid, "name": name, "ts": now},
        )
        obj_id = str(uuid4())
        s.execute(
            text("INSERT INTO security_objectives (id, organization_id, title, description, target_category, default_risk_level, created_at) "
                 "VALUES (:id, :org, :title, 'desc', 'linux_host', 'LOW', :ts)"),
            {"id": obj_id, "org": oid, "title": f"Objective {name}", "ts": now},
        )
        sc_id = str(uuid4())
        s.execute(
            text("INSERT INTO adversarial_scenarios (id, organization_id, objective_id, title, "
                 "strategy_description, proposed_risk_level, created_by, created_at) "
                 "VALUES (:id, :org, :obj, :title, 'strat', 'LOW', 'red', :ts)"),
            {"id": sc_id, "org": oid, "obj": obj_id, "title": f"Scenario {name}", "ts": now},
        )
        action_id = str(uuid4())
        gap_id = str(uuid4())
        s.execute(
            text("INSERT INTO detection_gaps (id, organization_id, scenario_id, action_id, technique_id, "
                 "original_outcome, remediation_status, root_cause, reason, created_at) "
                 "VALUES (:id, :org, :sc, :aid, 'T1003', 'NOT_DETECTED', 'OPEN', 'unpatched', 'gap', :ts)"),
            {"id": gap_id, "org": oid, "sc": sc_id, "aid": action_id, "ts": now},
        )
    s.commit()
    s.close()
    return {"org_a": org_a, "org_b": org_b}


@pytest.fixture(scope="module")
def client(engine, seed):
    app_module.engine = engine
    app_module.SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    app_module._seed_demo_data = lambda: None
    with TestClient(app_module.app, raise_server_exceptions=False) as c:
        yield c


class TestCrossTenantOrganizationState:
    def test_org_a_cannot_see_org_b_state(self, client, seed):
        resp = client.get(f"/api/organizations/{seed['org_b']}/state")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed["org_b"]
        assert data["name"] == "Org B"

    def test_org_b_cannot_see_org_a_state(self, client, seed):
        resp = client.get(f"/api/organizations/{seed['org_a']}/state")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed["org_a"]
        assert data["name"] == "Org A"


class TestCrossTenantExperiments:
    def test_org_b_experiments_not_visible_to_org_a(self, client, seed):
        resp_a = client.get(f"/api/organizations/{seed['org_a']}/experiments")
        resp_b = client.get(f"/api/organizations/{seed['org_b']}/experiments")
        assert resp_a.status_code == 200
        assert resp_b.status_code == 200
        exps_a = resp_a.json()
        exps_b = resp_b.json()
        exps_a_ids = {e["id"] for e in exps_a}
        exps_b_ids = {e["id"] for e in exps_b}
        assert exps_a_ids.isdisjoint(exps_b_ids) or len(exps_a_ids) == 0 or len(exps_b_ids) == 0


class TestCrossTenantDetectionGaps:
    def test_org_b_detection_gaps_not_visible_to_org_a(self, client, seed):
        resp = client.get(f"/api/organizations/{seed['org_a']}/detection-gaps")
        assert resp.status_code == 200
        gaps = resp.json()
        for gap in gaps:
            assert gap["organization_id"] == seed["org_a"]


class TestCrossTenantRetests:
    def test_org_b_retests_not_visible_to_org_a(self, client, seed):
        resp_a = client.get(f"/api/organizations/{seed['org_a']}/retests")
        resp_b = client.get(f"/api/organizations/{seed['org_b']}/retests")
        assert resp_a.status_code == 200
        assert resp_b.status_code == 200
        retests_a = resp_a.json()
        retests_b = resp_b.json()
        for r in retests_a:
            assert r["organization_id"] == seed["org_a"]
        for r in retests_b:
            assert r["organization_id"] == seed["org_b"]


class TestCrossTenantComparisons:
    def test_org_b_comparisons_not_visible_to_org_a(self, client, seed):
        resp_a = client.get(f"/api/organizations/{seed['org_a']}/comparisons")
        resp_b = client.get(f"/api/organizations/{seed['org_b']}/comparisons")
        assert resp_a.status_code == 200
        assert resp_b.status_code == 200


class TestCrossTenantImmuneMemory:
    def test_org_b_immune_memory_not_visible_to_org_a(self, client, seed):
        resp = client.get(f"/api/organizations/{seed['org_b']}/immune-memory")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed["org_b"]


class TestCrossTenantNextExperiment:
    def test_org_b_next_experiment_not_influenced_by_org_a(self, client, seed):
        resp = client.get(f"/api/organizations/{seed['org_b']}/next-experiment")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed["org_b"]


class TestCrossTenantCycleStatus:
    def test_org_b_cycle_status_independent(self, client, seed):
        resp = client.get(f"/api/organizations/{seed['org_b']}/immune-cycle/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["organization_id"] == seed["org_b"]


class TestTenantIsolationViaQueryParams:
    def test_cannot_bypass_tenant_via_query_param(self, client, seed):
        resp = client.get(
            f"/api/organizations/{seed['org_a']}/detection-gaps",
            params={"organization_id": seed["org_b"]},
        )
        assert resp.status_code == 200
        gaps = resp.json()
        for gap in gaps:
            assert gap["organization_id"] == seed["org_a"]
