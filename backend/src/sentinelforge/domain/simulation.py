from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional
from .action_ir import ActionIR
from .blueprint import SignedBlueprint

class SimulationRequest(BaseModel):
    blueprint: SignedBlueprint

class SimulationExecution(BaseModel):
    simulation_id: UUID
    blueprint_id: UUID
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    failure_reason: Optional[str] = None
    truncated: bool = False
