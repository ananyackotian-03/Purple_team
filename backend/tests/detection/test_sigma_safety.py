"""
SentinelForge Telemetry & Detection — Sigma Rule Safety & Built-in Matcher.

Covers the milestone's required "malformed Sigma rule" and deterministic
detection areas:

- Malformed Sigma rules fail safely at load time (never registered).
- Malformed rules can never crash the detection pipeline.
- The deterministic built-in matcher honors named-selection `condition`
  expressions (and / or / not / parentheses / `all|any|N of them`),
  list values, and contains/startswith/endswith modifiers.
- Unsupported constructs (e.g. `re` modifier) fail closed, never raise.

Every test is deterministic and requires no network, no Docker, no LLM.
Rules omit the `id` field so pySigma rejects them and the built-in
fallback matcher is exercised deterministically.
"""

import json

import pytest
import yaml

from sentinelforge.detection.sigma_engine import SigmaEngine, DetectionOutcome


def _no_id_rule(detection_block: str) -> str:
    """A Sigma rule that pySigma rejects (no `id`) so the built-in
    deterministic matcher is exercised via the public API."""
    return f"""title: Built-in Matcher Rule
detection:
{detection_block}
"""


def _evaluate_match(rule_yaml: str, event_dict: dict) -> list:
    engine = SigmaEngine()
    engine.load_rule_from_yaml(rule_yaml, "rule-under-test", "T9999")
    assert engine.rule_count == 1
    results = engine.evaluate(event_dict, event_id="ev-1")
    return [r.rule_id for r in results if r.matched]


# ---------------------------------------------------------------------------
# Malformed Sigma rule: safe load / never crashes
# ---------------------------------------------------------------------------

class TestMalformedSigmaRuleSafety:
    def test_empty_rule_rejected(self):
        engine = SigmaEngine()
        engine.load_rule_from_yaml("", "rule-empty", "T9999")
        assert engine.rule_count == 0

    def test_whitespace_rule_rejected(self):
        engine = SigmaEngine()
        engine.load_rule_from_yaml("   \n  ", "rule-ws", "T9999")
        assert engine.rule_count == 0

    def test_malformed_yaml_rejected(self):
        engine = SigmaEngine()
        engine.load_rule_from_yaml("title: [unclosed", "rule-bad-yaml", "T9999")
        assert engine.rule_count == 0

    def test_non_mapping_yaml_string_rejected(self):
        """YAML that parses but is a plain string must be rejected at load."""
        engine = SigmaEngine()
        engine.load_rule_from_yaml("just a plain string", "rule-non-dict", "T9999")
        assert engine.rule_count == 0

    def test_non_mapping_yaml_list_rejected(self):
        engine = SigmaEngine()
        engine.load_rule_from_yaml("- item1\n- item2", "rule-list", "T9999")
        assert engine.rule_count == 0

    def test_missing_detection_block_rejected(self):
        engine = SigmaEngine()
        engine.load_rule_from_yaml("title: No Detection", "rule-no-det", "T9999")
        assert engine.rule_count == 0

    def test_missing_condition_rejected(self):
        engine = SigmaEngine()
        rule = _no_id_rule("    sel:\n        ProcessName: bash\n")
        engine.load_rule_from_yaml(rule, "rule-no-cond", "T9999")
        assert engine.rule_count == 0

    def test_no_selection_rejected(self):
        engine = SigmaEngine()
        rule = _no_id_rule("    condition: selection\n")
        engine.load_rule_from_yaml(rule, "rule-no-sel", "T9999")
        assert engine.rule_count == 0

    def test_validate_rule_returns_reason_never_raises(self):
        engine = SigmaEngine()
        for bad in ("", "  ", "{unclosed", "a plain string", "[]", "title: x"):
            ok, reason = engine.validate_rule(bad)
            assert ok is False
            assert isinstance(reason, str) and reason

    def test_malformed_rules_cannot_crash_evaluation(self):
        """Even if a malformed rule is somehow present, evaluate() is safe."""
        engine = SigmaEngine()
        engine.load_rule_from_yaml("{bad", "rule-a", "T9999")
        engine.load_rule_from_yaml("a string", "rule-b", "T9999")
        engine.load_rule_from_yaml("- list", "rule-c", "T9999")
        # A valid rule still evaluates.
        valid = _no_id_rule("    sel:\n        ProcessName: bash\n    condition: sel\n")
        engine.load_rule_from_yaml(valid, "rule-good", "T9999")
        assert engine.rule_count == 1

        results = engine.evaluate({"ProcessName": "bash"}, event_id="ev-1")
        matched = [r.rule_id for r in results if r.matched]
        assert matched == ["rule-good"]
        for r in results:
            assert r.outcome in (DetectionOutcome.DETECTED, DetectionOutcome.EVENT_NO_MATCH)

    def test_bad_condition_fails_closed(self):
        rule = _no_id_rule("    sel_a:\n        EventType: execve\n    condition: sel_a and\n")
        assert _evaluate_match(rule, {"EventType": "execve"}) == []

    def test_unknown_selection_fails_closed(self):
        rule = _no_id_rule("    sel_a:\n        EventType: execve\n    condition: sel_zzz\n")
        assert _evaluate_match(rule, {"EventType": "execve"}) == []

    def test_re_modifier_fails_closed(self):
        rule = _no_id_rule("    sel:\n        CommandLine|re: whoami\n    condition: sel\n")
        matched = _evaluate_match(rule, {"CommandLine": "bash -c whoami"})
        assert matched == []


# ---------------------------------------------------------------------------
# Built-in matcher: condition semantics (deterministic)
# ---------------------------------------------------------------------------

class TestBuiltinConditionMatching:
    def test_single_selection_equality(self):
        rule = _no_id_rule("    sel:\n        EventType: execve\n    condition: sel\n")
        assert _evaluate_match(rule, {"EventType": "execve"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"EventType": "openat"}) == []

    def test_and_condition_requires_all(self):
        rule = _no_id_rule(
            "    sel_a:\n        EventType: execve\n"
            "    sel_b:\n        CommandLine|contains: whoami\n"
            "    condition: sel_a and sel_b\n"
        )
        # Partial evidence must NOT match (true AND semantics).
        assert _evaluate_match(rule, {"EventType": "execve", "CommandLine": "bash -c ls"}) == []
        assert _evaluate_match(rule, {"CommandLine": "bash -c whoami"}) == []
        # Full evidence matches.
        assert _evaluate_match(rule, {"EventType": "execve", "CommandLine": "bash -c whoami"}) == ["rule-under-test"]

    def test_or_condition_matches_any(self):
        rule = _no_id_rule(
            "    sel_bash:\n        ProcessName: bash\n"
            "    sel_sh:\n        ProcessName: sh\n"
            "    condition: sel_bash or sel_sh\n"
        )
        assert _evaluate_match(rule, {"ProcessName": "bash"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"ProcessName": "sh"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"ProcessName": "zsh"}) == []

    def test_not_condition(self):
        rule = _no_id_rule("    sel_bash:\n        ProcessName: bash\n    condition: not sel_bash\n")
        assert _evaluate_match(rule, {"ProcessName": "zsh"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"ProcessName": "bash"}) == []

    def test_parenthesized_condition(self):
        rule = _no_id_rule(
            "    sel_a:\n        EventType: execve\n"
            "    sel_b:\n        ProcessName: bash\n"
            "    sel_c:\n        ProcessName: sh\n"
            "    condition: sel_a and (sel_b or sel_c)\n"
        )
        assert _evaluate_match(rule, {"EventType": "execve", "ProcessName": "bash"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"EventType": "execve", "ProcessName": "zsh"}) == []
        assert _evaluate_match(rule, {"ProcessName": "bash"}) == []

    def test_all_of_them(self):
        rule = _no_id_rule(
            "    sel_a:\n        EventType: execve\n"
            "    sel_b:\n        ProcessName: bash\n"
            "    condition: all of them\n"
        )
        assert _evaluate_match(rule, {"EventType": "execve", "ProcessName": "bash"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"EventType": "execve", "ProcessName": "zsh"}) == []

    def test_any_of_them(self):
        rule = _no_id_rule(
            "    sel_a:\n        EventType: execve\n"
            "    sel_b:\n        ProcessName: bash\n"
            "    condition: any of them\n"
        )
        assert _evaluate_match(rule, {"EventType": "openat", "ProcessName": "bash"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"EventType": "openat", "ProcessName": "zsh"}) == []

    def test_n_of_them(self):
        rule = _no_id_rule(
            "    sel_a:\n        EventType: execve\n"
            "    sel_b:\n        ProcessName: bash\n"
            "    sel_c:\n        UserName: labuser\n"
            "    condition: 2 of them\n"
        )
        ev_full = {"EventType": "execve", "ProcessName": "bash", "UserName": "labuser"}
        assert _evaluate_match(rule, ev_full) == ["rule-under-test"]
        ev_partial = {"EventType": "execve", "ProcessName": "bash"}
        assert _evaluate_match(rule, ev_partial) == ["rule-under-test"]
        ev_weak = {"EventType": "execve"}
        assert _evaluate_match(rule, ev_weak) == []


# ---------------------------------------------------------------------------
# Built-in matcher: list values and modifiers
# ---------------------------------------------------------------------------

class TestBuiltinFieldMatching:
    def test_list_value_equality(self):
        rule = _no_id_rule("    sel:\n        ProcessName: [bash, sh]\n    condition: sel\n")
        assert _evaluate_match(rule, {"ProcessName": "bash"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"ProcessName": "sh"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"ProcessName": "zsh"}) == []

    def test_contains_modifier(self):
        rule = _no_id_rule("    sel:\n        CommandLine|contains: whoami\n    condition: sel\n")
        assert _evaluate_match(rule, {"CommandLine": "bash -c whoami -a"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"CommandLine": "bash -c id"}) == []

    def test_startswith_modifier(self):
        rule = _no_id_rule("    sel:\n        CommandLine|startswith: bash -c\n    condition: sel\n")
        assert _evaluate_match(rule, {"CommandLine": "bash -c whoami"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"CommandLine": "xterm bash -c whoami"}) == []

    def test_endswith_modifier(self):
        rule = _no_id_rule("    sel:\n        TargetFile|endswith: /shadow\n    condition: sel\n")
        assert _evaluate_match(rule, {"TargetFile": "/etc/shadow"}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"TargetFile": "/etc/passwd"}) == []

    def test_case_insensitive_equality(self):
        rule = _no_id_rule("    sel:\n        ProcessName: Bash\n    condition: sel\n")
        assert _evaluate_match(rule, {"ProcessName": "bash"}) == ["rule-under-test"]

    def test_missing_event_field_does_not_match(self):
        rule = _no_id_rule("    sel:\n        ProcessName: bash\n    condition: sel\n")
        assert _evaluate_match(rule, {}) == []
        assert _evaluate_match(rule, {"ProcessName": None}) == []

    def test_non_string_event_value(self):
        rule = _no_id_rule("    sel:\n        UserUid: 1000\n    condition: sel\n")
        assert _evaluate_match(rule, {"UserUid": 1000}) == ["rule-under-test"]
        assert _evaluate_match(rule, {"UserUid": 2000}) == []


# ---------------------------------------------------------------------------
# End-to-end: malformed rules never break the canonical pipeline
# ---------------------------------------------------------------------------

class TestPipelineResilience:
    def test_malformed_rules_mixed_with_canonical_rules(self):
        """A rules directory containing malformed rules still detects."""
        engine = SigmaEngine()
        engine.load_rule_from_yaml("garbage not yaml", "bad-1", "T9999")
        engine.load_rule_from_yaml("- list\n- of\n- things", "bad-2", "T9999")
        engine.load_rule_from_yaml(
            """title: Shell Execution
detection:
    sel:
        ProcessName: bash
    condition: sel
""",
            "sentinelforge-shell-execution",
            "T1059.004",
        )
        assert engine.rule_count == 1

        results = engine.evaluate(
            {"EventType": "execve", "ProcessName": "bash", "CommandLine": "bash -c whoami"},
            event_id="ev-1",
        )
        matched = [r.rule_id for r in results if r.matched]
        assert "sentinelforge-shell-execution" in matched

    def test_malformed_telemetry_and_rules_together_safe(self):
        """Malformed telemetry + malformed rules: detection still deterministic."""
        from sentinelforge.detection.normalizer import TelemetryNormalizer
        from sentinelforge.detection.collector import TelemetryCollector

        engine = SigmaEngine()
        engine.load_rule_from_yaml("{broken", "bad", "T9999")
        engine.load_rule_from_yaml(
            """title: Shell Execution
detection:
    sel:
        ProcessName: bash
    condition: sel
""",
            "sentinelforge-shell-execution",
            "T1059.004",
        )

        collector = TelemetryCollector(TelemetryNormalizer(), engine, redis_client=None)
        assert collector.process_event("{not valid json") == []

        valid = json.dumps({
            "time": "2026-08-14T10:00:00Z",
            "output_fields": {
                "evt.type": "execve",
                "proc.name": "bash",
                "proc.cmdline": "bash -c whoami",
                "user.name": "labuser",
            },
        })
        results = collector.process_event(valid, correlation_id="exp-1")
        assert any(r.matched and r.rule_id == "sentinelforge-shell-execution" for r in results)

    def test_detection_gap_evaluator_with_malformed_rules(self):
        """DetectionGapEvaluator never crashes on malformed Sigma rules."""
        from datetime import datetime, timezone
        from uuid import uuid4
        from sentinelforge.domain.action_ir import ActionIR, ActionType
        from sentinelforge.detection.evaluator import DetectionGapEvaluator
        from sentinelforge.detection.normalizer import NormalizedEvent

        engine = SigmaEngine()
        engine.load_rule_from_yaml("junk", "bad", "T9999")
        engine.load_rule_from_yaml(
            """title: Shell Execution
detection:
    sel:
        ProcessName: bash
    condition: sel
""",
            "sentinelforge-shell-execution",
            "T1059.004",
        )

        ev = NormalizedEvent(
            event_id="ev-1",
            correlation_id="scenario-1",
            timestamp="2026-08-14T10:00:00Z",
            source="falco",
            EventType="execve",
            ProcessName="bash",
            Executable="/usr/bin/bash",
            CommandLine="bash -c whoami",
            UserName="labuser",
            UserUid=1000,
            TargetFile=None,
            ContainerName="sentinelforge-target",
            ContainerId="c1",
            ParentProcess=None,
            raw_event_hash="h",
        )
        action = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            target="sentinelforge-target",
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            run_as_user="labuser",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
        )
        evaluator = DetectionGapEvaluator()
        outcome = evaluator.evaluate_action(
            action, [ev], engine, correlation_id="scenario-1"
        )
        assert outcome.outcome == DetectionOutcome.DETECTED
        assert "sentinelforge-shell-execution" in outcome.matched_rule_ids