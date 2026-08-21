"""RedAgentMemoryStore — PostgreSQL strategy memory for the Red Agent.

SECURITY ROLE:
Memory is partitioned by `organization_id`. Every read and write is scoped to
the caller's tenant; no query may cross organizational boundaries (T-07).
Without a database session the store degrades gracefully (no-ops / empty
reads) so unit tests never touch a live database.
"""

from typing import Any, List, Optional
from uuid import UUID

from sentinelforge.agents.red.novelty import StrategyFingerprint


class RedAgentMemoryStore:
    """Persists and reads tenant-scoped strategy fingerprints and outcomes."""

    def __init__(self, db_session: Optional[Any] = None):
        self._db = db_session

    def record_strategy(
        self,
        *,
        organization_id: UUID,
        objective_id: UUID,
        scenario_id: UUID,
        fingerprint: StrategyFingerprint,
        outcome: Optional[str] = None,
    ) -> Optional[Any]:
        """Persist a strategy fingerprint, scoped to `organization_id`."""
        if self._db is None:
            return None
        from sentinelforge.db.models import RedAgentStrategyRecord

        record = RedAgentStrategyRecord(
            organization_id=organization_id,
            objective_id=objective_id,
            scenario_id=scenario_id,
            technique_id=fingerprint.primary_technique,
            fingerprint_hash=fingerprint.composite_hash,
            command_pattern=fingerprint.normalized_command_pattern,
            outcome=outcome,
        )
        self._db.add(record)
        self._db.commit()
        return record

    def load_fingerprints(self, organization_id: UUID) -> List[StrategyFingerprint]:
        """Load all strategy fingerprints for a tenant as StrategyFingerprint objects."""
        if self._db is None:
            return []
        from sentinelforge.db.models import RedAgentStrategyRecord

        records = (
            self._db.query(RedAgentStrategyRecord)
            .filter(RedAgentStrategyRecord.organization_id == organization_id)
            .all()
        )
        fingerprints = []
        for rec in records:
            try:
                fingerprints.append(
                    StrategyFingerprint(
                        objective_id=rec.objective_id,
                        primary_technique=rec.technique_id,
                        normalized_executable=rec.command_pattern.split(":", 1)[0]
                        if ":" in rec.command_pattern
                        else "unknown",
                        normalized_command_pattern=rec.command_pattern,
                        action_types=["process_exec"],
                        target_resource="sentinelforge-target",
                        observable_classes=["process_creation"],
                        composite_hash=rec.fingerprint_hash,
                    )
                )
            except Exception:
                continue
        return fingerprints

    def load_strategy_outcomes(self, organization_id: UUID, limit: int = 10) -> List[dict]:
        """Load recent strategy outcomes for a tenant (bounded)."""
        if self._db is None:
            return []
        from sentinelforge.db.models import RedAgentStrategyRecord

        records = (
            self._db.query(RedAgentStrategyRecord)
            .filter(RedAgentStrategyRecord.organization_id == organization_id)
            .order_by(RedAgentStrategyRecord.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "technique_id": rec.technique_id,
                "fingerprint_hash": rec.fingerprint_hash,
                "command_pattern": rec.command_pattern,
                "outcome": rec.outcome,
            }
            for rec in records
        ]

    def update_outcome(
        self,
        organization_id: UUID,
        fingerprint_hash: str,
        outcome: str,
    ) -> bool:
        """Update the outcome of a tenant's strategy by fingerprint hash."""
        if self._db is None:
            return False
        from sentinelforge.db.models import RedAgentStrategyRecord

        record = (
            self._db.query(RedAgentStrategyRecord)
            .filter(
                RedAgentStrategyRecord.organization_id == organization_id,
                RedAgentStrategyRecord.fingerprint_hash == fingerprint_hash,
            )
            .first()
        )
        if record is None:
            return False
        record.outcome = outcome
        self._db.commit()
        return True

    def strategy_count(self, organization_id: UUID) -> int:
        """Count strategies recorded for a tenant."""
        if self._db is None:
            return 0
        from sentinelforge.db.models import RedAgentStrategyRecord

        return (
            self._db.query(RedAgentStrategyRecord)
            .filter(RedAgentStrategyRecord.organization_id == organization_id)
            .count()
        )