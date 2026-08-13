from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from ..db.models import SimulationResult
from ..domain.exceptions import SecurityRejection, SecurityRejectionCode
import uuid

class SimulationRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def claim_blueprint(self, blueprint_id: uuid.UUID, action_id: uuid.UUID, org_id: uuid.UUID):
        try:
            claim = SimulationResult(
                blueprint_id=blueprint_id, action_id=action_id, organization_id=org_id, status="CLAIMED"
            )
            self.session.add(claim)
            self.session.commit()
            return claim
        except IntegrityError:
            self.session.rollback()
            raise SecurityRejection(SecurityRejectionCode.REPLAY_DETECTED, "Blueprint has already been claimed", str(blueprint_id))
