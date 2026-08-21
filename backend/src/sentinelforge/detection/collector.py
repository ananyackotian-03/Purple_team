"""
SentinelForge Phase 3 — Telemetry Collector

Reads raw Falco JSON events, normalizes them, evaluates against
Sigma rules, and publishes DetectionResults to Redis Streams.

SECURITY:
- The Collector is an UNPRIVILEGED APPLICATION.
- It does NOT have Docker socket access.
- All telemetry is treated as UNTRUSTED DATA.
- Redis delivery is at-least-once; PostgreSQL writes are idempotent
  via unique event_id / detection_id constraints.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Optional, Callable

from sentinelforge.detection.normalizer import TelemetryNormalizer, NormalizedEvent
from sentinelforge.detection.sigma_engine import SigmaEngine, DetectionResult, DetectionOutcome

logger = logging.getLogger(__name__)

# Redis stream configuration
REDIS_STREAM = "sentinelforge:telemetry:detections"
REDIS_CONSUMER_GROUP = "engine_group"
MAX_REDIS_MESSAGE_BYTES = 65536


class TelemetryCollector:
    """Orchestrates the telemetry pipeline:
    Raw Falco JSON -> Normalize -> Detect -> Publish.

    The collector does not contain detection-specific logic;
    it delegates to TelemetryNormalizer and SigmaEngine.
    """

    def __init__(self, normalizer: TelemetryNormalizer, engine: SigmaEngine,
                 redis_client=None):
        self.normalizer = normalizer
        self.engine = engine
        self.redis = redis_client
        self._ensure_consumer_group()

    def _ensure_consumer_group(self):
        """Create the Redis consumer group if Redis is available."""
        if self.redis is None:
            return
        try:
            self.redis.xgroup_create(
                REDIS_STREAM, REDIS_CONSUMER_GROUP,
                id="0", mkstream=True
            )
        except Exception:
            # Group already exists
            pass

    def process_event(self, raw_falco_json: str,
                      correlation_id: Optional[str] = None) -> list[DetectionResult]:
        """Process a single raw Falco JSON event through the full pipeline.

        Returns list of DetectionResult objects (one per rule evaluated).
        Returns empty list if the event is rejected during normalization.
        """
        # Step 1: Normalize
        event = self.normalizer.normalize(raw_falco_json)
        if event is None:
            return []

        # Apply external correlation if provided
        if correlation_id is not None:
            event.correlation_id = correlation_id

        # Step 2: Evaluate against Sigma rules
        sigma_dict = event.to_sigma_dict()
        results = self.engine.evaluate(
            sigma_dict,
            event_id=event.event_id,
            correlation_id=event.correlation_id,
        )

        # Step 3: Publish to Redis
        for result in results:
            self._publish_to_redis(result)

        return results

    def collect(self, raw_falco_json: str,
                correlation_id: Optional[str] = None) -> Optional[NormalizedEvent]:
        """Collect a single raw Falco JSON event through the telemetry transport.

        Transport-only leg of the pipeline (Step 2B):
        Raw Falco JSON -> TelemetryNormalizer -> NormalizedEvent -> Redis stream.

        This performs NO detection decisions; it only normalizes and publishes
        to the existing telemetry stream. Returns the NormalizedEvent (the
        hand-off object for the detection/evaluation boundary) or None when the
        event is rejected (malformed, oversized, missing required fields).

        Redis is transport only and at-least-once: publish failures are logged
        and never raised, so collection never blocks or crashes the caller.
        A malformed/oversized event is rejected BEFORE publish, so the stream
        never carries un-processable payloads (a precondition for
        acknowledge-after-processing consumers).
        """
        event = self.normalizer.normalize(raw_falco_json)
        if event is None:
            return None

        if correlation_id is not None:
            event.correlation_id = correlation_id

        self._publish_event_to_redis(event)
        return event

    def _publish_event_to_redis(self, event: NormalizedEvent):
        """Publish a NormalizedEvent to the telemetry stream (transport only).

        Uses the same stream and message shape as the detection path, tagged
        with `kind: telemetry` so consumers can distinguish raw telemetry from
        DetectionResult payloads without a second stream.
        """
        if self.redis is None:
            return

        try:
            payload = json.dumps({"kind": "telemetry", "data": event.to_dict()})
            if len(payload.encode("utf-8")) > MAX_REDIS_MESSAGE_BYTES:
                logger.warning(
                    "Skipping oversized telemetry message for event %s",
                    event.event_id,
                )
                return

            self.redis.xadd(REDIS_STREAM, {"data": payload})
        except Exception as exc:
            logger.error("Failed to publish telemetry to Redis: %s", exc)

    def process_stream(self, lines_iterator, correlation_id: Optional[str] = None,
                       on_result: Optional[Callable] = None) -> dict:
        """Process multiple raw Falco JSON lines from an iterator.

        Returns summary statistics.
        """
        stats = {
            "events_processed": 0,
            "events_rejected": 0,
            "detections": 0,
            "no_match": 0,
        }

        for line in lines_iterator:
            line = line.strip()
            if not line:
                continue

            results = self.process_event(line, correlation_id=correlation_id)
            if not results:
                stats["events_rejected"] += 1
                continue

            stats["events_processed"] += 1
            for r in results:
                if r.matched:
                    stats["detections"] += 1
                else:
                    stats["no_match"] += 1

                if on_result:
                    on_result(r)

        return stats

    def _publish_to_redis(self, result: DetectionResult):
        """Publish a DetectionResult to the Redis stream.

        Message is bounded to MAX_REDIS_MESSAGE_BYTES.
        """
        if self.redis is None:
            return

        try:
            payload = json.dumps(result.to_dict())
            if len(payload.encode("utf-8")) > MAX_REDIS_MESSAGE_BYTES:
                logger.warning(
                    "Skipping oversized Redis message for detection %s",
                    result.detection_id
                )
                return

            self.redis.xadd(REDIS_STREAM, {"data": payload})
        except Exception as exc:
            logger.error("Failed to publish to Redis: %s", exc)
