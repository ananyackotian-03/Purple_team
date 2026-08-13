from pydantic import BaseModel
from uuid import UUID
from datetime import datetime

class SignedBlueprint(BaseModel):
    blueprint_id: UUID
    action_id: UUID
    technique_id: str
    target: str
    executable: str
    arguments: list[str]
    run_as_user: str
    issued_at: datetime
    expires_at: datetime
    hmac_signature: str
    signing_key_id: str
