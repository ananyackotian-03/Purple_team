import hmac
import hashlib
import json
from ..domain.blueprint import SignedBlueprint

class BlueprintSigner:
    def __init__(self, key: str, key_id: str):
        self.key = key.encode('utf-8')
        self.key_id = key_id
        
    def _get_payload_bytes(self, **kwargs):
        payload = json.dumps(kwargs, sort_keys=True, default=str)
        return payload.encode('utf-8')

    def sign(self, blueprint_id, action_id, technique_id, target, executable, arguments, run_as_user, issued_at, expires_at):
        payload_bytes = self._get_payload_bytes(
            blueprint_id=blueprint_id, action_id=action_id, technique_id=technique_id,
            target=target, executable=executable, arguments=arguments,
            run_as_user=run_as_user, issued_at=issued_at, expires_at=expires_at
        )
        sig = hmac.new(self.key, payload_bytes, hashlib.sha256).hexdigest()
        return SignedBlueprint(
            blueprint_id=blueprint_id, action_id=action_id, technique_id=technique_id,
            target=target, executable=executable, arguments=arguments,
            run_as_user=run_as_user, issued_at=issued_at, expires_at=expires_at,
            hmac_signature=sig, signing_key_id=self.key_id
        )
        
    def verify(self, blueprint: SignedBlueprint):
        payload_bytes = self._get_payload_bytes(
            blueprint_id=blueprint.blueprint_id, action_id=blueprint.action_id, technique_id=blueprint.technique_id,
            target=blueprint.target, executable=blueprint.executable, arguments=blueprint.arguments,
            run_as_user=blueprint.run_as_user, issued_at=blueprint.issued_at, expires_at=blueprint.expires_at
        )
        expected_sig = hmac.new(self.key, payload_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, blueprint.hmac_signature)
