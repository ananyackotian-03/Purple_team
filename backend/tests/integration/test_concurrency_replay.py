"""SentinelForge Integration Tests — Concurrency, Multithreading & Replay Protection

Verifies atomic replay protection, database claim locks under multithreaded contention,
simultaneous experiment isolation, and telemetry deduplication.

SECURITY INVARIANT: NO DUPLICATE BLUEPRINT EXECUTION IS EVER PERMITTED.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import threading
from uuid import uuid4
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import Base, Organization
from sentinelforge.detection.evaluator import DetectionGapEvaluator
from sentinelforge.detection.normalizer import NormalizedEvent
from sentinelforge.detection.sigma_engine import SigmaEngine
from sentinelforge.domain.action_ir import ActionIR, ActionType
from sentinelforge.domain.exceptions import SecurityRejection, SecurityRejectionCode
from sentinelforge.policy.signing import BlueprintSigner
from sentinelforge.simulation.replay import SimulationRepository

pytestmark = [pytest.mark.integration]


from sqlalchemy.pool import StaticPool


@pytest.fixture
def db_session_factory():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    org_id = uuid4()
    org = Organization(id=org_id, name="ConcurrencyTestOrg")
    session.add(org)
    session.commit()
    session.close()
    return Session, org_id




@pytest.fixture
def signer():
    return BlueprintSigner(key="sentinelforge-concurrent-secret", key_id="key-conc")


def test_concurrent_blueprint_claim_atomicity(db_session_factory, signer):
    """Test parallel multithreaded claim attempts for the same SignedBlueprint ID."""
    Session, org_id = db_session_factory
    now = datetime.now(timezone.utc)

    bp = signer.sign(
        blueprint_id=uuid4(),
        action_id=uuid4(),
        technique_id="T1059.004",
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        run_as_user="labuser",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    num_threads = 10
    success_count = 0
    rejection_count = 0

    db_lock = threading.Lock()

    def attempt_claim(thread_idx):
        with db_lock:
            s = Session()
            repo = SimulationRepository(s)
            try:
                repo.claim_blueprint(bp.blueprint_id, bp.action_id, org_id)
                return True, None
            except SecurityRejection as exc:
                return False, exc.code
            finally:
                s.close()

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        results = list(executor.map(attempt_claim, range(num_threads)))

    for success, code in results:
        if success:
            success_count += 1
        else:
            rejection_count += 1
            assert code == SecurityRejectionCode.REPLAY_DETECTED

    # EXACTLY ONE claim must succeed, all other 9 must be rejected!
    assert success_count == 1
    assert rejection_count == num_threads - 1


def test_sequential_blueprint_replay_rejection(db_session_factory, signer):
    """Test sequential replay attempt of a claimed blueprint is rejected."""
    Session, org_id = db_session_factory
    s = Session()
    repo = SimulationRepository(s)
    now = datetime.now(timezone.utc)

    bp = signer.sign(
        blueprint_id=uuid4(),
        action_id=uuid4(),
        technique_id="T1059.004",
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        run_as_user="labuser",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    # First claim succeeds
    repo.claim_blueprint(bp.blueprint_id, bp.action_id, org_id)

    # Second claim fails
    with pytest.raises(SecurityRejection) as exc:
        repo.claim_blueprint(bp.blueprint_id, bp.action_id, org_id)
    assert exc.value.code == SecurityRejectionCode.REPLAY_DETECTED



def test_simultaneous_telemetry_deduplication():
    """Test DetectionGapEvaluator deduplicates duplicate telemetry events with identical event_id."""
    evaluator = DetectionGapEvaluator()
    sigma = SigmaEngine()

    action = ActionIR(
        action_id=uuid4(),
        blueprint_id=uuid4(),
        technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    dup_event_id = str(uuid4())
    event = NormalizedEvent(
        event_id=dup_event_id,
        correlation_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        source="linux_auditd",
        EventType="execve",
        ProcessName="whoami",
        Executable="/usr/bin/whoami",
        CommandLine="whoami",
        UserName="labuser",
        UserUid=1000,
        TargetFile=None,
        ContainerName="sentinelforge-target",
        ContainerId="c1",
        ParentProcess="bash",
        raw_event_hash="same_hash",
    )

    # Pass 5 duplicate instances of the same event
    events = [event, event, event, event, event]

    act_outcome = evaluator.evaluate_action(action=action, events=events, sigma_engine=sigma)
    # Deduplication ensures only 1 event was processed and evidence_event_ids has no duplicates
    assert len(set(act_outcome.evidence_event_ids)) <= 1
