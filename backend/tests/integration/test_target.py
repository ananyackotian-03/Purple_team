import pytest
import docker
import os

@pytest.fixture(scope="module")
def client():
    return docker.from_env()

@pytest.fixture(scope="module")
def target(client):
    try:
        return client.containers.get("sentinelforge-target")
    except docker.errors.NotFound:
        pytest.fail("Target container sentinelforge-target not running")

def test_target_running(target):
    assert target.status == "running"

def test_target_user_is_labuser(target, client):
    exec_id = client.api.exec_create(target.id, cmd=["whoami"], user="")['Id']
    output = client.api.exec_start(exec_id).decode().strip()
    assert output == "labuser"

def test_timeout_exists(target, client):
    exec_id = client.api.exec_create(target.id, cmd=["ls", "/usr/bin/timeout"], user="")['Id']
    output = client.api.exec_start(exec_id).decode().strip()
    assert output == "/usr/bin/timeout"

def test_read_only_filesystem(target, client):
    exec_id = client.api.exec_create(target.id, cmd=["touch", "/etc/test_file"], user="root")['Id']
    output = client.api.exec_start(exec_id).decode().strip()
    exec_info = client.api.exec_inspect(exec_id)
    assert exec_info["ExitCode"] != 0
    assert "Read-only file system" in output

def test_no_docker_socket(target, client):
    exec_id = client.api.exec_create(target.id, cmd=["ls", "/var/run/docker.sock"], user="")['Id']
    output = client.api.exec_start(exec_id).decode().strip()
    exec_info = client.api.exec_inspect(exec_id)
    assert exec_info["ExitCode"] != 0
    assert "No such file or directory" in output

def test_tmp_is_writable(target, client):
    exec_id = client.api.exec_create(target.id, cmd=["touch", "/tmp/sentinelforge_test_evidence.log"], user="")['Id']
    client.api.exec_start(exec_id)
    exec_info = client.api.exec_inspect(exec_id)
    assert exec_info["ExitCode"] == 0

def test_cap_drop_and_no_new_privs(target, client):
    # For capabilities and no-new-privileges, we can inspect the container config
    host_config = target.attrs['HostConfig']
    assert "ALL" in host_config.get('CapDrop', [])
    assert "no-new-privileges:true" in host_config.get('SecurityOpt', [])
