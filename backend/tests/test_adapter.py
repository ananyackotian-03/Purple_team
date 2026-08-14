import pytest
import uuid
from sentinelforge.simulation.adapter import SimulationAdapter, ContainerLinuxAdapter
from sentinelforge.domain.experiment import ExperimentConstraints


class MockSimulationAdapter(SimulationAdapter):
    def __init__(self):
        self.executed = False
        self.cleaned_up = False

    def execute_bounded(self, executable, arguments, run_as_user, timeout=30, constraints=None):
        self.executed = True
        return 0, b"mock stdout", b"", False, False

    def cleanup(self):
        self.cleaned_up = True

    def health_check(self):
        return True


def test_mock_adapter():
    adapter = MockSimulationAdapter()
    assert adapter.health_check() is True
    res = adapter.execute_bounded("/usr/bin/bash", ["-c", "whoami"], "labuser")
    assert res[0] == 0
    assert res[1] == b"mock stdout"
    assert adapter.executed is True

    adapter.cleanup()
    assert adapter.cleaned_up is True
