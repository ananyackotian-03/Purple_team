import json
import os
import pytest
from sentinelforge.detection.normalizer import TelemetryNormalizer, NormalizedEvent, MAX_RAW_EVENT_BYTES
from sentinelforge.detection.sigma_engine import SigmaEngine, DetectionOutcome
from sentinelforge.detection.collector import TelemetryCollector


VALID_FALCO_SHELL_JSON = json.dumps({
    "time": "2026-08-14T10:00:00Z",
    "rule": "SentinelForge Telemetry Syscalls",
    "priority": "WARNING",
    "output": "Syscall event in target container",
    "output_fields": {
        "evt.type": "execve",
        "evt.hostname": "sentinelforge-host",
        "container.id": "abc123container",
        "container.name": "sentinelforge-target",
        "proc.name": "bash",
        "proc.exe": "/usr/bin/bash",
        "proc.cmdline": "bash -c whoami",
        "user.name": "labuser",
        "user.uid": 1000,
        "fd.name": ""
    }
})

VALID_FALCO_SHADOW_JSON = json.dumps({
    "time": "2026-08-14T10:05:00Z",
    "rule": "SentinelForge Telemetry Syscalls",
    "priority": "WARNING",
    "output": "Shadow access attempt",
    "output_fields": {
        "evt.type": "openat",
        "evt.hostname": "sentinelforge-host",
        "container.id": "abc123container",
        "container.name": "sentinelforge-target",
        "proc.name": "cat",
        "proc.exe": "/usr/bin/cat",
        "proc.cmdline": "cat /etc/shadow",
        "user.name": "labuser",
        "user.uid": 1000,
        "fd.name": "/etc/shadow"
    }
})


class TestTelemetryNormalizer:
    normalizer = TelemetryNormalizer()

    def test_valid_event_normalization(self):
        ev = self.normalizer.normalize(VALID_FALCO_SHELL_JSON)
        assert ev is not None
        assert isinstance(ev, NormalizedEvent)
        assert ev.ProcessName == "bash"
        assert ev.CommandLine == "bash -c whoami"
        assert ev.UserName == "labuser"
        assert ev.UserUid == 1000
        assert ev.ContainerName == "sentinelforge-target"

    def test_malformed_json_returns_none(self):
        ev = self.normalizer.normalize("{bad json")
        assert ev is None

    def test_oversized_event_rejected(self):
        oversized = json.dumps({"output_fields": {"proc.name": "A" * (MAX_RAW_EVENT_BYTES + 10)}})
        ev = self.normalizer.normalize(oversized)
        assert ev is None

    def test_control_character_sanitization(self):
        dirty_json = json.dumps({
            "time": "2026-08-14T10:00:00Z",
            "output_fields": {
                "evt.type": "execve",
                "proc.name": "bash\x00\x01",
                "proc.cmdline": "whoami\x07",
                "user.name": "labuser"
            }
        })
        ev = self.normalizer.normalize(dirty_json)
        assert ev is not None
        assert ev.ProcessName == "bash"
        assert ev.CommandLine == "whoami"


class TestSigmaEngine:
    @pytest.fixture
    def rules_dir(self):
        return os.path.join(os.path.dirname(__file__), "..", "..", "src", "sentinelforge", "detection", "rules")

    def test_rule_loading(self, rules_dir):
        engine = SigmaEngine()
        loaded = engine.load_rules_from_directory(rules_dir)
        assert loaded >= 3
        assert engine.rule_count >= 3

    def test_shell_execution_matching(self, rules_dir):
        engine = SigmaEngine()
        engine.load_rules_from_directory(rules_dir)

        normalizer = TelemetryNormalizer()
        ev = normalizer.normalize(VALID_FALCO_SHELL_JSON)
        results = engine.evaluate(ev.to_sigma_dict(), event_id=ev.event_id)

        matched_rules = [r.rule_id for r in results if r.matched]
        assert "sentinelforge-shell-execution" in matched_rules

    def test_shadow_access_matching(self, rules_dir):
        engine = SigmaEngine()
        engine.load_rules_from_directory(rules_dir)

        normalizer = TelemetryNormalizer()
        ev = normalizer.normalize(VALID_FALCO_SHADOW_JSON)
        results = engine.evaluate(ev.to_sigma_dict(), event_id=ev.event_id)

        matched_rules = [r.rule_id for r in results if r.matched]
        assert "sentinelforge-shadow-access" in matched_rules


class TestTelemetryCollector:
    @pytest.fixture
    def rules_dir(self):
        return os.path.join(os.path.dirname(__file__), "..", "..", "src", "sentinelforge", "detection", "rules")

    def test_collector_pipeline(self, rules_dir):
        normalizer = TelemetryNormalizer()
        engine = SigmaEngine()
        engine.load_rules_from_directory(rules_dir)

        collector = TelemetryCollector(normalizer=normalizer, engine=engine, redis_client=None)
        results = collector.process_event(VALID_FALCO_SHELL_JSON)
        assert len(results) >= 3
        assert any(r.outcome == DetectionOutcome.DETECTED for r in results)

    def test_collector_stream_processing(self, rules_dir):
        normalizer = TelemetryNormalizer()
        engine = SigmaEngine()
        engine.load_rules_from_directory(rules_dir)

        collector = TelemetryCollector(normalizer=normalizer, engine=engine, redis_client=None)
        lines = [VALID_FALCO_SHELL_JSON, VALID_FALCO_SHADOW_JSON, "{invalid line}"]
        stats = collector.process_stream(lines)

        assert stats["events_processed"] == 2
        assert stats["events_rejected"] == 1
        assert stats["detections"] >= 2
