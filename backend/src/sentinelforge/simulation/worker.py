import uuid
from datetime import datetime, timezone
from ..domain.simulation import SimulationRequest, SimulationExecution
from ..policy.engine import PolicyEngine
from ..policy.signing import BlueprintSigner
from .replay import SimulationRepository
from .docker_client import SafeDockerClient
from .adapter import SimulationAdapter, ContainerLinuxAdapter
from ..db.models import AuditLog
from ..domain.exceptions import SecurityRejection, SecurityRejectionCode

class SimulationWorker:
    def __init__(
        self,
        signer: BlueprintSigner,
        repo: SimulationRepository,
        db_session,
        adapter: SimulationAdapter | SafeDockerClient | None = None,
    ):
        self.signer = signer
        self.repo = repo
        self.db = db_session

        if isinstance(adapter, SimulationAdapter):
            self.adapter = adapter
        elif isinstance(adapter, SafeDockerClient):
            self.adapter = ContainerLinuxAdapter(docker_client=adapter)
        else:
            self.adapter = ContainerLinuxAdapter()

        # Retain backward-compatible property reference
        self.docker_client = (
            self.adapter._docker
            if isinstance(self.adapter, ContainerLinuxAdapter)
            else None
        )
        
    def _audit(self, action: str, bp_id: uuid.UUID = None):
        org_id = uuid.UUID(int=0)
        log = AuditLog(organization_id=org_id, action=action, blueprint_id=bp_id)
        self.db.add(log)
        self.db.commit()

    def process(self, req: SimulationRequest):
        bp = req.blueprint
        execution = SimulationExecution(
            simulation_id=uuid.uuid4(),
            blueprint_id=bp.blueprint_id,
            status="VALIDATING"
        )
        self._audit("VALIDATION_STARTED", bp.blueprint_id)
        
        try:
            if not self.signer.verify(bp):
                raise SecurityRejection(SecurityRejectionCode.INVALID_SIGNATURE, "Signature mismatch")
                
            from ..domain.action_ir import ActionIR, ActionType
            ir = ActionIR(
                action_id=bp.action_id, blueprint_id=bp.blueprint_id, technique_id=bp.technique_id,
                action_type=ActionType.PROCESS_EXEC, target=bp.target, executable=bp.executable,
                arguments=bp.arguments, run_as_user=bp.run_as_user, issued_at=bp.issued_at, expires_at=bp.expires_at
            )
            PolicyEngine.validate(ir)
            
            org_id = uuid.UUID(int=0)
            self.repo.claim_blueprint(bp.blueprint_id, bp.action_id, org_id)
            
            execution.status = "APPROVED"
            self._audit("BLUEPRINT_VERIFIED", bp.blueprint_id)
            
            execution.status = "RUNNING"
            execution.started_at = datetime.now(timezone.utc)
            self._audit("EXECUTION_STARTED", bp.blueprint_id)
            
            exit_code, stdout, stderr, truncated, timed_out = self.adapter.execute_bounded(
                executable=bp.executable, arguments=bp.arguments, run_as_user=bp.run_as_user
            )
            
            execution.completed_at = datetime.now(timezone.utc)
            
            if timed_out:
                execution.status = "TIMEOUT"
                execution.failure_reason = "Execution timed out and was terminated"
                self._audit("EXECUTION_TIMED_OUT", bp.blueprint_id)
            else:
                execution.exit_code = exit_code
                execution.stdout = stdout.decode('utf-8', errors='replace')
                execution.stderr = stderr.decode('utf-8', errors='replace')
                execution.truncated = truncated
                execution.status = "COMPLETED"
                self._audit("EXECUTION_COMPLETED", bp.blueprint_id)
                
            return execution
            
        except SecurityRejection as e:
            execution.status = "REJECTED"
            execution.failure_reason = str(e)
            self._audit(f"VALIDATION_REJECTED: {e.code.value}", bp.blueprint_id)
            return execution
        except Exception as e:
            execution.status = "FAILED"
            execution.failure_reason = str(e)
            self._audit("EXECUTION_FAILED", bp.blueprint_id)
            return execution
