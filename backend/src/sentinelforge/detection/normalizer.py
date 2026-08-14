"""
SentinelForge Phase 3 — Telemetry Normalizer

Transforms raw Falco JSON events into flat NormalizedEvent objects
suitable for deterministic Sigma rule evaluation.

SECURITY: All telemetry strings are UNTRUSTED DATA.
"""

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

MAX_RAW_EVENT_BYTES = 65536   # 64KB max raw event size
MAX_FIELD_LENGTH = 4096       # 4KB max per string field


@dataclass
class NormalizedEvent:
    """Flat-field normalized telemetry event for Sigma evaluation.

    Field names are intentionally flat (no dots) because
    sigma-rule-matcher uses get_by_dots() which splits on '.'
    for nested dict lookup.
    """
    event_id: str
    correlation_id: Optional[str]
    timestamp: str
    source: str
    # Flat fields for Sigma matching
    EventType: str
    ProcessName: str
    Executable: Optional[str]
    CommandLine: str
    UserName: str
    UserUid: int
    TargetFile: Optional[str]
    ContainerName: str
    ContainerId: Optional[str]
    ParentProcess: Optional[str]
    raw_event_hash: str

    def to_dict(self) -> dict:
        """Convert to dict for Sigma evaluation and serialization."""
        return asdict(self)

    def to_sigma_dict(self) -> dict:
        """Return only the flat fields relevant for Sigma matching."""
        return {
            "EventType": self.EventType,
            "ProcessName": self.ProcessName,
            "Executable": self.Executable,
            "CommandLine": self.CommandLine,
            "UserName": self.UserName,
            "UserUid": self.UserUid,
            "TargetFile": self.TargetFile,
            "ContainerName": self.ContainerName,
            "ContainerId": self.ContainerId,
            "ParentProcess": self.ParentProcess,
        }


class TelemetryNormalizer:
    """Transforms raw Falco JSON into NormalizedEvent objects.

    Security invariants:
    - All string fields are sanitized (null bytes stripped, length bounded).
    - Oversized raw events are rejected.
    - Malformed JSON is rejected gracefully (returns None).
    - correlation_id is always None; correlation is resolved externally.
    """

    def normalize(self, raw_falco_json: str) -> Optional[NormalizedEvent]:
        """Parse and normalize a single raw Falco JSON event.

        Returns None if the event is malformed, oversized, or missing
        required fields.
        """
        # Bound raw event size
        if len(raw_falco_json.encode("utf-8", errors="replace")) > MAX_RAW_EVENT_BYTES:
            logger.warning("Rejected oversized raw event (%d bytes)", len(raw_falco_json))
            return None

        # Parse JSON
        try:
            raw = json.loads(raw_falco_json)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Rejected malformed JSON: %s", exc)
            return None

        if not isinstance(raw, dict):
            logger.warning("Rejected non-dict JSON payload")
            return None

        # Compute raw event hash
        raw_hash = hashlib.sha256(
            raw_falco_json.encode("utf-8", errors="replace")
        ).hexdigest()

        # Extract output_fields (Falco's enriched event payload)
        fields = raw.get("output_fields", {})
        if not isinstance(fields, dict):
            logger.warning("Missing or invalid output_fields in Falco event")
            return None

        # Map Falco dot-fields to flat NormalizedEvent fields
        event_type = self._sanitize_string(str(fields.get("evt.type", "")))
        process_name = self._sanitize_string(str(fields.get("proc.name", "")))
        command_line = self._sanitize_string(str(fields.get("proc.cmdline", "")))
        user_name = self._sanitize_string(str(fields.get("user.name", "")))

        # Validate required fields
        if not event_type or not process_name or not command_line or not user_name:
            logger.warning("Rejected event with missing required fields")
            return None

        # Parse user UID safely
        try:
            user_uid = int(fields.get("user.uid", -1))
        except (ValueError, TypeError):
            user_uid = -1

        # Extract timestamp from Falco event or use current time
        ts = raw.get("time", datetime.now(timezone.utc).isoformat())

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            correlation_id=None,
            timestamp=str(ts),
            source="falco",
            EventType=event_type,
            ProcessName=process_name,
            Executable=self._sanitize_string(str(fields.get("proc.exe", "") or "")),
            CommandLine=command_line,
            UserName=user_name,
            UserUid=user_uid,
            TargetFile=self._sanitize_string(str(fields.get("fd.name", "") or "")),
            ContainerName=self._sanitize_string(str(fields.get("container.name", "") or "")),
            ContainerId=self._sanitize_string(str(fields.get("container.id", "") or "")),
            ParentProcess=self._sanitize_string(str(fields.get("proc.pname", "") or "")),
            raw_event_hash=raw_hash,
        )

    def _sanitize_string(self, value: str) -> str:
        """Strip null bytes, control characters, and enforce length limit."""
        # Remove null bytes
        value = value.replace("\x00", "")
        # Remove other dangerous control characters (keep newlines/tabs)
        value = "".join(
            ch for ch in value
            if ch in ("\n", "\t", "\r") or (ord(ch) >= 32)
        )
        # Truncate to max field length
        if len(value) > MAX_FIELD_LENGTH:
            value = value[:MAX_FIELD_LENGTH]
        return value
