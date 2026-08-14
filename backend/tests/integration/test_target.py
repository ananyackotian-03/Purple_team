"""SentinelForge Integration Tests — Target Container Hardening & Privileges

Verifies that sentinelforge-target runs as non-root (labuser), filesystem read-only,
dropped capabilities, no-new-privileges, writable /tmp, and no docker.sock mounted.
"""

import docker
import pytest
from sentinelforge.simulation.docker_client import SafeDockerClient

pytestmark = [pytest.mark.integration, pytest.mark.docker]


@pytest.fixture(scope="module")
def client(docker_available):
    if not docker_available:
        pytest.skip(
            "Docker-dependent test SKIPPED: Docker daemon is unavailable on the local host "
            "(docker.errors.DockerException: engine pipe/socket unreachable)."
        )
    try:
        return docker.from_env()
    except Exception as exc:
        pytest.skip(f"Docker client creation failed: {exc}")


@pytest.fixture(scope="module")
def target(client):
    try:
        return client.containers.get("sentinelforge-target")
    except docker.errors.NotFound:
        pytest.fail("Target container 'sentinelforge-target' is not running")
    except Exception as exc:
        pytest.fail(f"Failed to access target container: {exc}")


def test_target_running(target):
    """Verify target container is running."""
    assert target.status == "running"


def test_target_user_is_labuser(target, client):
    """Verify default execution user is labuser."""
    exec_id = client.api.exec_create(target.id, cmd=["whoami"], user="")["Id"]
    output = client.api.exec_start(exec_id).decode().strip()
    assert output == "labuser"


def test_timeout_exists(target, client):
    """Verify GNU coreutils /usr/bin/timeout entrypoint binary exists."""
    exec_id = client.api.exec_create(target.id, cmd=["ls", "/usr/bin/timeout"], user="")["Id"]
    output = client.api.exec_start(exec_id).decode().strip()
    assert output == "/usr/bin/timeout"


def test_read_only_filesystem(target, client):
    """Verify root filesystem is read-only."""
    exec_id = client.api.exec_create(target.id, cmd=["touch", "/etc/test_file"], user="root")["Id"]
    output = client.api.exec_start(exec_id).decode().strip()
    exec_info = client.api.exec_inspect(exec_id)
    assert exec_info["ExitCode"] != 0
    assert "Read-only file system" in output


def test_no_docker_socket(target, client):
    """Verify Docker socket /var/run/docker.sock is NOT exposed to container."""
    exec_id = client.api.exec_create(target.id, cmd=["ls", "/var/run/docker.sock"], user="")["Id"]
    output = client.api.exec_start(exec_id).decode().strip()
    exec_info = client.api.exec_inspect(exec_id)
    assert exec_info["ExitCode"] != 0
    assert "No such file or directory" in output


def test_tmp_is_writable(target, client):
    """Verify /tmp tmpfs mount is writable."""
    exec_id = client.api.exec_create(target.id, cmd=["touch", "/tmp/sentinelforge_test_evidence.log"], user="")["Id"]
    client.api.exec_start(exec_id)
    exec_info = client.api.exec_inspect(exec_id)
    assert exec_info["ExitCode"] == 0


def test_cap_drop_and_no_new_privs(target):
    """Verify HostConfig enforces cap_drop=ALL and no-new-privileges."""
    host_config = target.attrs.get("HostConfig", {})
    assert "ALL" in host_config.get("CapDrop", [])
    assert "no-new-privileges:true" in host_config.get("SecurityOpt", [])
