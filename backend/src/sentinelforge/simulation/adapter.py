from abc import ABC, abstractmethod
from typing import Tuple
from sentinelforge.domain.experiment import ExperimentConstraints
from sentinelforge.simulation.docker_client import SafeDockerClient


class SimulationAdapter(ABC):
    """Abstract base class for simulation execution environments.

    Allows SentinelForge to support multiple execution backends
    (Docker/Linux, Web/API, DB, Windows, Cloud labs) without
    changing control-plane authorization, signing, or replay protection.
    """

    @abstractmethod
    def execute_bounded(
        self,
        executable: str,
        arguments: list[str],
        run_as_user: str,
        timeout: int = 30,
        constraints: ExperimentConstraints | None = None,
    ) -> Tuple[int, bytes, bytes, bool, bool]:
        """Execute command within target sandbox.

        Returns:
            (exit_code, stdout_bytes, stderr_bytes, truncated, timed_out)
        """
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Mandatory post-experiment reset/cleanup semantics."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check if target range asset is available."""
        pass


class ContainerLinuxAdapter(SimulationAdapter):
    """Concrete Docker/Linux container simulation adapter."""

    def __init__(self, docker_client: SafeDockerClient | None = None):
        if docker_client is not None:
            self._docker = docker_client
        else:
            try:
                self._docker = SafeDockerClient()
            except Exception:
                # Docker engine unavailable (e.g. Docker Desktop Linux engine stopped).
                # Adapter must remain constructible; bounded ops fail-safe via health_check().
                self._docker = None

    def execute_bounded(
        self,
        executable: str,
        arguments: list[str],
        run_as_user: str,
        timeout: int = 30,
        constraints: ExperimentConstraints | None = None,
    ) -> Tuple[int, bytes, bytes, bool, bool]:
        t = constraints.max_execution_seconds if constraints else timeout
        return self._docker.execute_bounded(
            executable=executable,
            arguments=arguments,
            run_as_user=run_as_user,
            timeout=t,
        )

    def cleanup(self) -> None:
        """Mandatory post-experiment reset/cleanup semantics for container target.
        
        Executes bounded cleanup of temporary evidence/artifacts inside the container
        under unprivileged 'labuser' without creating host-level secondary execution pathways.
        """
        try:
            if self.health_check():
                self._docker.execute_bounded(
                    executable="/usr/bin/bash",
                    arguments=["-c", "rm -rf /tmp/sentinelforge_* 2>/dev/null || true"],
                    run_as_user="labuser",
                    timeout=10,
                )
        except Exception:
            # Cleanup is best-effort and must fail-safe without breaking worker flow
            pass

    def health_check(self) -> bool:
        if self._docker is None:
            return False
        try:
            self._docker._get_target_container()
            return True
        except Exception:
            return False
