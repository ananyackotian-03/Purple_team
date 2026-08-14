"""SentinelForge Integration Test Configuration & Docker Availability Fixture

Provides a reusable, deterministic docker_available fixture that distinguishes between:
- DOCKER_UNAVAILABLE (skips test gracefully with explicit diagnostic notice)
- DOCKER_AVAILABLE (runs real Docker container execution; actual failures remain FAILED)
"""

import logging
import os
import pytest
import docker

logger = logging.getLogger(__name__)


def check_docker_daemon() -> bool:
    """Check if Docker daemon is reachable and responding."""
    try:
        client = docker.from_env(timeout=2)
        client.ping()
        return True
    except Exception as exc:
        logger.debug("Docker daemon check failed: %s", exc)
        return False


@pytest.fixture(scope="session")
def docker_available() -> bool:
    """Session-scoped fixture indicating whether Docker daemon is active."""
    return check_docker_daemon()


@pytest.fixture(scope="function")
def require_docker(docker_available: bool):
    """Function-scoped fixture requiring an active Docker daemon.

    In CI environments (CI=true or GITHUB_ACTIONS=true), Docker MUST be available.
    If Docker is missing in CI, fail the test immediately.
    If running locally without Docker, skip gracefully with a diagnostic notice.
    If Docker is available, execution continues; any test failure remains a FAILED test.
    """
    if not docker_available:
        if os.getenv("CI") == "true" or os.getenv("GITHUB_ACTIONS") == "true":
            pytest.fail(
                "CRITICAL CI FAILURE: Docker daemon MUST be available in CI environment, "
                "but docker.from_env().ping() failed."
            )
        pytest.skip(
            "Docker-dependent integration test SKIPPED: Docker daemon is unavailable on the local host "
            "(docker.errors.DockerException: engine pipe/socket unreachable)."
        )
