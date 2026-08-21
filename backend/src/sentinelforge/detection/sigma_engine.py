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
        """Parse a Sigma YAML string and register it.

        Malformed rules are rejected safely (logged, never registered, never
        raise). A rule that parses to a non-mapping (e.g. a bare string or
        list) is rejected here so it can never crash later evaluation.
        """
        is_valid, reason = self.validate_rule(rule_yaml)
        if not is_valid:
            logger.warning("Rejected Sigma rule '%s': %s", rule_id, reason)
            return

        try:
            parsed = yaml.safe_load(rule_yaml)
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

    def validate_rule(self, rule_yaml: str) -> tuple[bool, str]:
        """Validate that a Sigma YAML rule is loadable and safe to evaluate.

        Returns (is_valid, reason). Never raises; malformed input fails
        closed (False) instead of producing a rule that could crash or be
        mis-evaluated downstream.
        """
        if not rule_yaml or not rule_yaml.strip():
            return False, "Empty or whitespace-only Sigma rule"
        try:
            parsed = yaml.safe_load(rule_yaml)
        except Exception as exc:
            return False, f"Malformed YAML syntax: {exc}"
        if not isinstance(parsed, dict):
            return False, "Sigma rule must be a YAML mapping"
        detection = parsed.get("detection")
        if not isinstance(detection, dict):
            return False, "Missing or invalid 'detection' block"
        condition = detection.get("condition")
        if not condition or not str(condition).strip():
            return False, "Missing 'condition' in detection block"
        selections = [
            v for k, v in detection.items()
            if k != "condition" and isinstance(v, dict)
        ]
        if not selections:
            return False, "Detection block requires at least one selection"
        return True, "OK"

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
                try:
                    matched = self._builtin_match(event_dict, parsed)
                except Exception as exc:
                    logger.warning(
                        "Built-in Sigma rule '%s' evaluation error (fail-safe): %s",
                        rule_id, exc,
                    )
                    matched = False

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
        """Deterministic field matching fallback.

        Supports Sigma equality, `contains`, `startswith`, `endswith`
        modifiers, list values (OR over elements), and named-selection
        conditions (`sel`, `sel1 and sel2`, `sel1 or sel2`, `not`,
        parentheses, and `N/all/any of them`). Unsupported constructs
        (e.g. the `re` modifier or an unparseable condition) fail closed
        (non-match + log), never raising.
        """
        if not isinstance(parsed_yaml, dict):
            return False
        detection = parsed_yaml.get("detection")
        if not isinstance(detection, dict):
            return False
        selections = {
            str(k): v
            for k, v in detection.items()
            if k != "condition" and isinstance(v, dict)
        }
        if not selections:
            return False

        condition = detection.get("condition")
        if not isinstance(condition, str) or not condition.strip():
            # Legacy default: any single selection matching yields a match.
            for sel in selections.values():
                if self._match_selection(sel, event_dict):
                    return True
            return False

        try:
            tokens = _tokenize_condition(condition)
            node = _parse_condition(tokens)
            return _eval_condition_node(node, selections, event_dict, self._match_selection)
        except Exception as exc:
            logger.warning(
                "Unparseable Sigma condition '%s' (fail-safe): %s", condition, exc
            )
            return False

    def _match_selection(self, selection: dict, event_dict: dict) -> bool:
        """Match a single named selection: all field criteria must hold."""
        for key, expected in selection.items():
            field_name, *modifiers = str(key).split("|")
            actual_val = event_dict.get(field_name)
            if actual_val is None:
                actual_val = ""
            if not self._match_field(str(actual_val), expected, modifiers, field_name):
                return False
        return True

    def _match_field(self, actual_str: str, expected, modifiers: list, field_name: str) -> bool:
        """Match one field criterion against one event field value."""
        if isinstance(expected, list):
            # List values are OR-ed: any element matching is sufficient.
            for item in expected:
                if self._match_field(actual_str, item, modifiers, field_name):
                    return True
            return False

        exp = str(expected)
        if len(modifiers) > 1:
            # Compound modifier chains (e.g. contains|all) are unsupported
            # in the built-in engine; fail closed rather than mis-match.
            logger.warning(
                "Unsupported Sigma modifier chain on '%s' (fail-safe): %s",
                field_name, "|".join(modifiers),
            )
            return False

        mod = modifiers[0] if modifiers else ""
        if mod == "contains":
            return exp.lower() in actual_str.lower()
        if mod == "startswith":
            return actual_str.startswith(exp)
        if mod == "endswith":
            return actual_str.endswith(exp)
        if mod == "re":
            logger.warning(
                "Sigma 're' modifier unsupported in built-in engine (fail-safe): %s",
                field_name,
            )
            return False
        if mod:
            logger.warning(
                "Unsupported Sigma modifier '%s' on '%s' (fail-safe)", mod, field_name
            )
            return False
        return actual_str.lower() == exp.lower()


def _tokenize_condition(expr: str) -> list:
    """Tokenize a Sigma `condition` expression.

    Supports identifiers (named selections), `and`, `or`, `not`,
    parentheses, integers, and the keywords `of` / `them`. Whitespace
    between keywords is required (Sigma syntax). Raises ValueError on
    unexpected characters; callers treat that as fail-safe non-match.
    """
    tokens = []
    i = 0
    n = len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            tokens.append(("LPAREN", "("))
            i += 1
            continue
        if c == ")":
            tokens.append(("RPAREN", ")"))
            i += 1
            continue
        if not (c.isalnum() or c == "_"):
            raise ValueError(f"Unexpected character {c!r} in condition")
        j = i
        while j < n and (expr[j].isalnum() or expr[j] == "_"):
            j += 1
        word = expr[i:j]
        i = j
        low = word.lower()
        if low in ("and", "or", "not", "of", "them"):
            tokens.append((low.upper(), word))
        elif word.isdigit():
            tokens.append(("NUMBER", int(word)))
        else:
            tokens.append(("IDENT", word))
    tokens.append(("EOF", ""))
    return tokens


def _parse_condition(tokens: list):
    """Parse tokenized Sigma condition into an AST.

    Grammar (subset of Sigma):
        expr    := or_expr
        or_expr := and_expr ('or' and_expr)*
        and_expr:= unary ('and' unary)*
        unary   := 'not' unary | primary
        primary := '(' expr ')' | 'all' 'of' 'them'
                 | 'any' 'of' 'them' | <int> 'of' 'them' | IDENT
    Raises ValueError on any malformed construct (fail-safe downstream).
    """
    pos = 0

    def peek():
        return tokens[pos]

    def advance():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or():
        node = parse_and()
        while peek()[0] == "OR":
            advance()
            node = ("or", node, parse_and())
        return node

    def parse_and():
        node = parse_unary()
        while peek()[0] == "AND":
            advance()
            node = ("and", node, parse_unary())
        return node

    def parse_unary():
        if peek()[0] == "NOT":
            advance()
            return ("not", parse_unary())
        return parse_primary()

    def parse_primary():
        tok = peek()
        kind = tok[0]
        if kind == "LPAREN":
            advance()
            node = parse_or()
            if peek()[0] != "RPAREN":
                raise ValueError("Missing ')' in Sigma condition")
            advance()
            return node
        if kind == "NUMBER":
            count = tok[1]
            advance()
            if peek()[0] != "OF":
                raise ValueError("Expected 'of' after number")
            advance()
            if peek()[0] != "THEM":
                raise ValueError("Expected 'them' after 'of'")
            advance()
            return ("count", count)
        if kind == "IDENT":
            word = tok[1]
            advance()
            low = word.lower()
            if low in ("all", "any"):
                if peek()[0] != "OF":
                    raise ValueError(f"Expected 'of' after {word!r}")
                advance()
                if peek()[0] != "THEM":
                    raise ValueError("Expected 'them' after 'of'")
                advance()
                return ("all",) if low == "all" else ("any",)
            return ("sel", word)
        raise ValueError(f"Unexpected token {tok[1]!r} in Sigma condition")

    node = parse_or()
    if peek()[0] != "EOF":
        raise ValueError(f"Unexpected trailing tokens in Sigma condition: {peek()[1]!r}")
    return node


def _eval_condition_node(node, selections: dict, event_dict: dict, match_selection) -> bool:
    """Deterministically evaluate a parsed Sigma condition AST."""
    kind = node[0]
    if kind == "sel":
        sel = selections.get(node[1])
        if sel is None:
            # Unknown named selection fails closed (never matches).
            return False
        return bool(match_selection(sel, event_dict))
    if kind == "and":
        return _eval_condition_node(node[1], selections, event_dict, match_selection) and \
            _eval_condition_node(node[2], selections, event_dict, match_selection)
    if kind == "or":
        return _eval_condition_node(node[1], selections, event_dict, match_selection) or \
            _eval_condition_node(node[2], selections, event_dict, match_selection)
    if kind == "not":
        return not _eval_condition_node(node[1], selections, event_dict, match_selection)
    if kind == "all":
        return all(
            match_selection(sel, event_dict) for sel in selections.values()
        )
    if kind == "any":
        return any(
            match_selection(sel, event_dict) for sel in selections.values()
        )
    if kind == "count":
        matched = sum(
            1 for sel in selections.values()
            if match_selection(sel, event_dict)
        )
        return matched >= node[1]
    return False
