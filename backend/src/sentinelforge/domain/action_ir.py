from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from enum import Enum

class ActionType(str, Enum):
    PROCESS_EXEC = "process_exec"

class ActionIR(BaseModel):
    action_id: UUID
    blueprint_id: UUID
    technique_id: str
    action_type: ActionType
    target: str = "sentinelforge-target"
    executable: str
    arguments: list[str]
    run_as_user: str = "labuser"
    issued_at: datetime
    expires_at: datetime
