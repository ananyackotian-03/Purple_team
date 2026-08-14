"""
SentinelForge Phase 3 — Sigma Detection Engine

Evaluates NormalizedEvent dictionaries against loaded Sigma rules.
Supports both pySigma + sigma-rule-matcher (when installed) and a built-in
deterministic field-matching fallback engine.

The engine does NOT know about Docker or collection logic.
It operates purely on dictionaries.
"""

import logging
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any

import yaml

logger = logging.getLogger(__name__)

# Check pySigma availability
try:
    from sigma.rule import SigmaRule
    from sigma_rule_matcher import RuleMatcher
    HAS_PYSIGMA = True
except ImportError:
    HAS_PYSIGMA = False
    SigmaRule = Any
    RuleMatcher = Any


class DetectionOutcome(str, Enum):
    """Possible outcomes of a detection evaluation."""
    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    DETECTION_GAP = "DETECTION_GAP"
    EVENT_NO_MATCH = "EVENT_NO_MATCH"


@dataclass
class DetectionResult:
    """Result of evaluating a single Sigma rule against a single event."""
    detection_id: str
    correlation_id: Optional[str]
    simulation_id: Optional[str]
    action_id: Optional[str]
    exercise_id: Optional[str]
    technique_id: str
    rule_id: str
    matched: bool
    outcome: DetectionOutcome
    evidence_event_ids: list = field(default_factory=list)
    timestamp: str = ""
    source: str = "sigma"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        return d


class SigmaEngine:
    """Loads Sigma rules and evaluates events against them.

    Each rule is stored with its rule_id and technique_id extracted
    from the x-sentinelforge metadata block in the YAML file.
    """

    def __init__(self):
        self._rules: list[tuple[str, str, dict, Any, Any]] = []

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def load_rule_from_yaml(self, rule_yaml: str, rule_id: str, technique_id: str) -> None:
        """Parse a Sigma YAML string and register it."""
        try:
            parsed = yaml.safe_load(rule_yaml) or {}
            sigma_rule = None
            matcher = None

            if HAS_PYSIGMA:
                try:
                    sigma_rule = SigmaRule.from_yaml(rule_yaml)
                    matcher = RuleMatcher(sigma_rule)
                except Exception as exc:
                    logger.debug("pySigma parse failed (%s), using built-in matcher: %s", rule_id, exc)

            self._rules.append((rule_id, technique_id, parsed, sigma_rule, matcher))
            logger.info("Loaded Sigma rule: %s (%s)", rule_id, technique_id)
        except Exception as exc:
            logger.warning("Failed to load Sigma rule '%s': %s", rule_id, exc)

    def load_rules_from_directory(self, directory: str) -> int:
        """Walk a directory and load all .yml/.yaml Sigma rule files."""
        loaded = 0
        if not os.path.isdir(directory):
            logger.warning("Rules directory does not exist: %s", directory)
            return 0

        for filename in sorted(os.listdir(directory)):
            if not filename.endswith((".yml", ".yaml")):
                continue
            filepath = os.path.join(directory, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                parsed = yaml.safe_load(content) or {}
                meta = parsed.get("x-sentinelforge", {})
                rule_id = meta.get("rule_id", parsed.get("id", filename))
                technique_id = meta.get("technique_id", "unknown")

                self.load_rule_from_yaml(content, str(rule_id), str(technique_id))
                loaded += 1
            except Exception as exc:
                logger.warning("Skipping rule file '%s': %s", filename, exc)
        return loaded

    def evaluate(self, event_dict: dict, event_id: str = "",
                 correlation_id: Optional[str] = None) -> list[DetectionResult]:
        """Evaluate event_dict against ALL loaded rules."""
        results = []
        ts = datetime.now(timezone.utc).isoformat() + "Z"

        for rule_id, technique_id, parsed, sigma_rule, matcher in self._rules:
            matched = False

            if matcher is not None:
                try:
                    matched = matcher.match(event_dict)
                except Exception as exc:
                    logger.warning("pySigma rule '%s' error, falling back: %s", rule_id, exc)
                    matched = self._builtin_match(event_dict, parsed)
            else:
                matched = self._builtin_match(event_dict, parsed)

            outcome = DetectionOutcome.DETECTED if matched else DetectionOutcome.EVENT_NO_MATCH

            results.append(DetectionResult(
                detection_id=str(uuid.uuid4()),
                correlation_id=correlation_id,
                simulation_id=None,
                action_id=None,
                exercise_id=None,
                technique_id=technique_id,
                rule_id=rule_id,
                matched=matched,
                outcome=outcome,
                evidence_event_ids=[event_id] if event_id else [],
                timestamp=ts,
                source="sigma",
            ))

        return results

    def _builtin_match(self, event_dict: dict, parsed_yaml: dict) -> bool:
        """Deterministic field matching fallback."""
        detection = parsed_yaml.get("detection", {})
        if not detection:
            return False

        # Simple single or multi-selection match
        selections = [v for k, v in detection.items() if k != "condition" and isinstance(v, dict)]
        if not selections:
            return False

        for sel in selections:
            sel_match = True
            for key, expected in sel.items():
                field_name, _, modifier = key.partition("|")
                actual_val = str(event_dict.get(field_name, "") or "")
                
                if modifier == "endswith":
                    if not actual_val.endswith(str(expected)):
                        sel_match = False
                        break
                elif modifier == "contains":
                    if str(expected).lower() not in actual_val.lower():
                        sel_match = False
                        break
                else:
                    if actual_val.lower() != str(expected).lower():
                        sel_match = False
                        break
            if sel_match:
                return True

        return False
