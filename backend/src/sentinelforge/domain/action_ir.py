from pydantic import BaseModel, Field
from uuid import UUID
from datetime import datetime
from enum import Enum
from typing import Optional

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
    max_execution_seconds: Optional[int] = Field(default=30, ge=1, le=300)
    max_stdout_bytes: Optional[int] = Field(default=64 * 1024, ge=1024, le=1048576)
    issued_at: datetime
    expires_at: datetime

