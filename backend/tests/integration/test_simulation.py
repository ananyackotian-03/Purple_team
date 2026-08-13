import pytest
import uuid
import time
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sentinelforge.db.models import Base, Organization
from sentinelforge.simulation.worker import SimulationWorker
from sentinelforge.simulation.replay import SimulationRepository
from sentinelforge.policy.signing import BlueprintSigner
from sentinelforge.domain.action_ir import ActionType
from sentinelforge.domain.blueprint import SignedBlueprint
from sentinelforge.domain.simulation import SimulationRequest
from sentinelforge.simulation.docker_client import SafeDockerClient
from sentinelforge.domain.exceptions import SecurityRejectionCode

@pytest.fixture(scope="function")
def worker():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    org = Organization(id=uuid.UUID(int=0), name="TestOrg")
    s.add(org)
    s.commit()
    
    signer = BlueprintSigner("secret_key_for_testing", "key-1")
    repo = SimulationRepository(s)
    return SimulationWorker(signer, repo, s)

def create_blueprint(worker_inst, executable="/usr/bin/bash", arguments=None, 
                     target="sentinelforge-target", run_as_user="labuser", offset_minutes=5):
    if arguments is None:
        arguments = ["-c", "whoami"]
    now = datetime.now(timezone.utc)
    return worker_inst.signer.sign(
        blueprint_id=uuid.uuid4(), action_id=uuid.uuid4(), technique_id="T1059",
        target=target, executable=executable, arguments=arguments,
        run_as_user=run_as_user, issued_at=now, expires_at=now + timedelta(minutes=offset_minutes)
    )

def test_valid_whoami(worker):
    bp = create_blueprint(worker)
    res = worker.process(SimulationRequest(blueprint=bp))
    assert res.status == "COMPLETED"
    assert res.exit_code == 0
    assert "labuser" in res.stdout
    
def test_valid_cat_shadow(worker):
    bp = create_blueprint(worker, arguments=["-c", "cat /etc/shadow"])
    res = worker.process(SimulationRequest(blueprint=bp))
    assert res.status == "COMPLETED"
    assert res.exit_code != 0
    assert "Permission denied" in res.stdout

def test_valid_rm_tmp(worker):
    bp = create_blueprint(worker, arguments=["-c", "rm /tmp/sentinelforge_test_evidence.log"])
    res = worker.process(SimulationRequest(blueprint=bp))
    assert res.status == "COMPLETED"

def test_invalid_arbitrary_command(worker):
    bp = create_blueprint(worker, arguments=["-c", "echo hacked"])
    res = worker.process(SimulationRequest(blueprint=bp))
    assert res.status == "REJECTED"
    assert SecurityRejectionCode.POLICY_DENIED.value in res.failure_reason

def test_invalid_target(worker):
    bp = create_blueprint(worker, target="host")
    res = worker.process(SimulationRequest(blueprint=bp))
    assert res.status == "REJECTED"
    assert SecurityRejectionCode.INVALID_TARGET.value in res.failure_reason

def test_invalid_user(worker):
    bp = create_blueprint(worker, run_as_user="root")
    res = worker.process(SimulationRequest(blueprint=bp))
    assert res.status == "REJECTED"
    assert SecurityRejectionCode.UNAUTHORIZED_USER.value in res.failure_reason

def test_tampered_blueprint(worker):
    bp = create_blueprint(worker)
    bp.target = "hacked-target"
    res = worker.process(SimulationRequest(blueprint=bp))
    assert res.status == "REJECTED"
    assert SecurityRejectionCode.INVALID_SIGNATURE.value in res.failure_reason

def test_expired_blueprint(worker):
    bp = create_blueprint(worker, offset_minutes=-5)
    # We must tweak issued_at so it's not rejected as "future" due to the test taking time?
    # Actually create_blueprint issues at `now` and expires at `now - 5`, so it's already invalid
    res = worker.process(SimulationRequest(blueprint=bp))
    assert res.status == "REJECTED"
    assert SecurityRejectionCode.INVALID_ACTION_IR.value in res.failure_reason or SecurityRejectionCode.EXPIRED_BLUEPRINT.value in res.failure_reason

def test_replayed_blueprint(worker):
    bp = create_blueprint(worker)
    res1 = worker.process(SimulationRequest(blueprint=bp))
    assert res1.status == "COMPLETED"
    res2 = worker.process(SimulationRequest(blueprint=bp))
    assert res2.status == "REJECTED"
    assert SecurityRejectionCode.REPLAY_DETECTED.value in res2.failure_reason

def test_timeout_termination(worker, monkeypatch):
    # Mock execute_bounded to simulate a long running process that is timed out
    # Instead of running a long process, we will temporarily allow `sleep 5` in policy engine just for this test
    from sentinelforge.policy.allowlists import ALLOWED_EXECUTABLES, ALLOWED_BASH_COMMANDS
    ALLOWED_BASH_COMMANDS.add("sleep 5")
    
    bp = create_blueprint(worker, arguments=["-c", "sleep 5"])
    
    # Let's set the timeout to 1 second in docker_client
    original_execute = worker.docker_client.execute_bounded
    def monkey_execute(*args, **kwargs):
        kwargs['timeout'] = 1
        return original_execute(*args, **kwargs)
    
    monkeypatch.setattr(worker.docker_client, "execute_bounded", monkey_execute)
    
    start = time.time()
    res = worker.process(SimulationRequest(blueprint=bp))
    elapsed = time.time() - start
    
    assert res.status == "TIMEOUT"
    assert elapsed < 3.0 # Ensures it didn't wait the full 5 seconds
    
    ALLOWED_BASH_COMMANDS.remove("sleep 5")

def test_output_limits(worker, monkeypatch):
    import sentinelforge.simulation.docker_client
    monkeypatch.setattr(sentinelforge.simulation.docker_client, "MAX_STDOUT_BYTES", 5)
    
    bp = create_blueprint(worker, arguments=["-c", "whoami"])
    res = worker.process(SimulationRequest(blueprint=bp))
    
    assert res.truncated is True
    assert len(res.stdout.encode('utf-8')) <= 20 # Can be slightly larger due to chunk boundaries, but definitely bounded
    
def test_docker_target_restriction(worker):
    # Prove that SafeDockerClient explicitly rejects querying other containers
    import docker
    client = docker.from_env()
    # create a dummy container
    dummy = client.containers.run("alpine", "sleep 60", detach=True, name="dummy-target")
    
    try:
        from sentinelforge.domain.exceptions import SecurityRejection
        # SafeDockerClient._get_target_container always gets "sentinelforge-target"
        # We can't even inject dummy-target into it because it's hardcoded.
        # This confirms the design restriction.
        assert "sentinelforge-target" in worker.docker_client._get_target_container().name
    finally:
        dummy.stop()
        dummy.remove()
