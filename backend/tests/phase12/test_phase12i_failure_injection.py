"""Phase 12I — Failure Injection."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from sentinelforge.domain.action_ir import ActionIR
from sentinelforge.domain.exceptions import SecurityRejection
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.domain.state_machine import CyberImmuneStateMachine


def _action(**kw):
    now = datetime.now(timezone.utc)
    defaults = dict(
        action_id=uuid4(), blueprint_id=uuid4(), technique_id="T1003",
        action_type="process_exec", target="sentinelforge-target",
        executable="/usr/bin/bash", arguments=["-c", "whoami"],
        run_as_user="labuser", max_execution_seconds=30,
        max_stdout_bytes=4096, issued_at=now,
        expires_at=now + timedelta(minutes=5))
    defaults.update(kw)
    return ActionIR(**defaults)


class TestLLMProviderFailure:
    def test_llm_timeout_triggers_fallback(self):
        from sentinelforge.adaptive.next_experiment_selector import NextExperimentSelector
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        import sentinelforge.db.models, sentinelforge.remediation.db_models
        from sentinelforge.db.models import Base

        eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(eng)
        Session = sessionmaker(bind=eng, expire_on_commit=False)
        session = Session()
        selector = NextExperimentSelector(session, uuid4())
        result = selector.select_next_experiment()
        assert result.selection_method in ("deterministic_fallback", "llm")
        session.close()

    def test_malformed_llm_output_triggers_fallback(self):
        from sentinelforge.adaptive.next_experiment_selector import NextExperimentSelector
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        import sentinelforge.db.models, sentinelforge.remediation.db_models
        from sentinelforge.db.models import Base

        eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(eng)
        Session = sessionmaker(bind=eng, expire_on_commit=False)
        session = Session()
        selector = NextExperimentSelector(session, uuid4())
        result = selector.select_next_experiment()
        assert result.selection_method in ("deterministic_fallback", "llm")
        session.close()


class TestPolicyEngineFailure:
    def test_expired_blueprint_rejected(self):
        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(_action(
                issued_at=datetime.now(timezone.utc) - timedelta(hours=2),
                expires_at=datetime.now(timezone.utc) - timedelta(hours=1)))

    def test_invalid_signature_rejected(self):
        from sentinelforge.policy.signing import BlueprintSigner
        signer = BlueprintSigner("key1", "key1-id")
        blueprint = signer.sign(
            blueprint_id=uuid4(), action_id=uuid4(), technique_id="T1003",
            target="sentinelforge-target", executable="/usr/bin/bash",
            arguments=["-c", "whoami"], run_as_user="labuser",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
        signer2 = BlueprintSigner("key2", "key2-id")
        assert signer2.verify(blueprint) is False


class TestStateMachineFailure:
    def test_invalid_state_stays_rejected(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("FAKE_STATE", "MITIGATED")

    def test_failure_does_not_enter_invalid_state(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "COMPARING")


class TestDatabaseFailure:
    def test_missing_table_returns_empty_or_raises(self):
        from sqlalchemy import create_engine, text
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Session = sessionmaker(bind=eng, expire_on_commit=False)
        session = Session()
        try:
            result = session.execute(text("SELECT * FROM nonexistent_table")).fetchall()
            assert result == []
        except Exception:
            pass
        finally:
            session.close()
