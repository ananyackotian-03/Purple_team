import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sentinelforge.db.models import Base, Organization
from sentinelforge.simulation.replay import SimulationRepository
from sentinelforge.domain.exceptions import SecurityRejection, SecurityRejectionCode
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.domain.action_ir import ActionIR, ActionType
from sentinelforge.policy.signing import BlueprintSigner
from sentinelforge.domain.state_machine import ExerciseStateMachine

@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    org = Organization(id=uuid.uuid4(), name="TestOrg")
    s.add(org)
    s.commit()
    return s, org

def create_ir(executable="/usr/bin/bash", arguments=None, issued_at=None, expires_at=None):
    now = datetime.now(timezone.utc)
    if arguments is None: arguments = ["-c", "whoami"]
    if issued_at is None: issued_at = now
    if expires_at is None: expires_at = now + timedelta(minutes=5)
    
    return ActionIR(
        action_id=uuid.uuid4(), blueprint_id=uuid.uuid4(), technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC, executable=executable, arguments=arguments,
        issued_at=issued_at, expires_at=expires_at
    )

def test_expired_blueprint():
    now = datetime.now(timezone.utc)
    ir = create_ir(issued_at=now - timedelta(minutes=10), expires_at=now - timedelta(minutes=5))
    with pytest.raises(SecurityRejection) as exc:
        PolicyEngine.validate(ir, current_time=now)
    assert exc.value.code == SecurityRejectionCode.EXPIRED_BLUEPRINT

def test_replayed_blueprint(session):
    s, org = session
    repo = SimulationRepository(s)
    bp_id = uuid.uuid4()
    repo.claim_blueprint(bp_id, uuid.uuid4(), org.id)
    with pytest.raises(SecurityRejection) as exc:
        repo.claim_blueprint(bp_id, uuid.uuid4(), org.id)
    assert exc.value.code == SecurityRejectionCode.REPLAY_DETECTED

def test_tampered_blueprint():
    signer = BlueprintSigner("secret", "key1")
    now = datetime.now(timezone.utc)
    bp = signer.sign(uuid.uuid4(), uuid.uuid4(), "T1059", "sentinelforge-target", "/usr/bin/bash", ["-c", "whoami"], "labuser", now, now + timedelta(minutes=5))
    bp.target = "hacked-target"
    assert not signer.verify(bp)

def test_bash_allowlist():
    assert PolicyEngine.validate(create_ir())
    malicious = ["whoami; cat /etc/passwd", "whoami && cat", "$(whoami)", "whoami "]
    for cmd in malicious:
        with pytest.raises(SecurityRejection) as exc:
            PolicyEngine.validate(create_ir(arguments=["-c", cmd]))
        assert exc.value.code == SecurityRejectionCode.POLICY_DENIED

def test_path_traversal():
    with pytest.raises(SecurityRejection) as exc:
        PolicyEngine.validate(create_ir(executable="/usr/bin/cat", arguments=["../../etc/passwd"]))
    assert exc.value.code == SecurityRejectionCode.POLICY_DENIED

def test_unauthorized_target():
    ir = create_ir()
    ir.target = "host"
    with pytest.raises(SecurityRejection) as exc:
        PolicyEngine.validate(ir)
    assert exc.value.code == SecurityRejectionCode.INVALID_TARGET

def test_unauthorized_user():
    ir = create_ir()
    ir.run_as_user = "root"
    with pytest.raises(SecurityRejection) as exc:
        PolicyEngine.validate(ir)
    assert exc.value.code == SecurityRejectionCode.UNAUTHORIZED_USER

def test_state_machine():
    assert ExerciseStateMachine.transition("CREATED", "PLANNING") == "PLANNING"
    with pytest.raises(SecurityRejection) as exc:
        ExerciseStateMachine.transition("CREATED", "COMPLETED")
    assert exc.value.code == SecurityRejectionCode.INVALID_STATE_TRANSITION
    with pytest.raises(SecurityRejection) as exc:
        ExerciseStateMachine.transition("RETESTING", "VERIFIED", has_retest_result=False)
    assert exc.value.code == SecurityRejectionCode.VERIFICATION_FAILED
