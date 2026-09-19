"""Phase 12J — Idempotency / Replay."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from sentinelforge.domain.action_ir import ActionIR
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.domain.state_machine import CyberImmuneStateMachine


def _action():
    now = datetime.now(timezone.utc)
    return ActionIR(
        action_id=uuid4(), blueprint_id=uuid4(), technique_id="T1003",
        action_type="process_exec", target="sentinelforge-target",
        executable="/usr/bin/bash", arguments=["-c", "whoami"],
        run_as_user="labuser", max_execution_seconds=30,
        max_stdout_bytes=4096, issued_at=now,
        expires_at=now + timedelta(minutes=5))


class TestPolicyEngineIdempotency:
    def test_same_action_validated_multiple_times(self):
        action = _action()
        for _ in range(5):
            assert PolicyEngine.validate(action) is True


class TestStateMachineIdempotency:
    def test_same_valid_transition_repeated(self):
        for _ in range(3):
            result = CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "DEFENSE_PROPOSED")
            assert result == "DEFENSE_PROPOSED"

    def test_same_invalid_transition_always_rejected(self):
        for _ in range(3):
            with pytest.raises(Exception):
                CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "MITIGATED")


class TestAPIIdempotency:
    def test_create_same_objective_twice(self):
        from fastapi.testclient import TestClient
        from sqlalchemy import create_engine, text
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        import sentinelforge.api.app as app_module
        from sentinelforge.db.models import Base

        eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(eng)
        app_module.engine = eng
        app_module.SessionLocal = sessionmaker(bind=eng, expire_on_commit=False)
        app_module._seed_demo_data = lambda: None

        Session = sessionmaker(bind=eng, expire_on_commit=False)
        s = Session()
        org_id = str(uuid4())
        s.execute(
            text("INSERT INTO organizations (id, name, defensive_state, created_at, updated_at) "
                 "VALUES (:id, 'Org', 'INITIAL', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')"),
            {"id": org_id})
        s.commit()
        s.close()

        with TestClient(app_module.app, raise_server_exceptions=False) as c:
            resp1 = c.post("/api/objectives", json={"title": "Test", "description": "test", "organization_id": org_id})
            resp2 = c.post("/api/objectives", json={"title": "Test", "description": "test", "organization_id": org_id})
            assert resp1.status_code == 201
            assert resp2.status_code == 201
            assert resp1.json()["id"] != resp2.json()["id"]


class TestDefenseTestNotDuplicative:
    def test_defense_testing_to_unresolved_stays_unresolved(self):
        result = CyberImmuneStateMachine.transition("DEFENSE_TESTING", "UNRESOLVED")
        assert result == "UNRESOLVED"
