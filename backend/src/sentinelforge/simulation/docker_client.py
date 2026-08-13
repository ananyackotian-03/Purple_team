import docker
from ..domain.exceptions import SecurityRejection, SecurityRejectionCode

MAX_STDOUT_BYTES = 1024 * 64
MAX_STDERR_BYTES = 1024 * 64

class SafeDockerClient:
    def __init__(self):
        self.client = docker.from_env()

    def _get_target_container(self):
        try:
            return self.client.containers.get("sentinelforge-target")
        except docker.errors.NotFound:
            raise SecurityRejection(SecurityRejectionCode.INVALID_TARGET, "sentinelforge-target container not found")

    def execute_bounded(self, executable: str, arguments: list[str], run_as_user: str, timeout: int = 30):
        container = self._get_target_container()
        
        # Docker API Limitation: exec processes cannot be cleanly terminated.
        # Strategy: Use GNU coreutils timeout inside the container as the entrypoint.
        # This guarantees termination without a secondary privileged Worker execution pathway.
        cmd = ["/usr/bin/timeout", str(timeout), executable] + arguments
        
        exec_id = self.client.api.exec_create(
            container.id, cmd=cmd, user=run_as_user, 
            stdout=True, stderr=True, tty=False
        )['Id']
        
        output_stream = self.client.api.exec_start(exec_id, stream=True)
        
        stdout_buf = bytearray()
        stderr_buf = bytearray()
        truncated = False
        
        try:
            for chunk in output_stream:
                if len(stdout_buf) + len(chunk) <= MAX_STDOUT_BYTES:
                    stdout_buf.extend(chunk)
                else:
                    remaining = MAX_STDOUT_BYTES - len(stdout_buf)
                    if remaining > 0:
                        stdout_buf.extend(chunk[:remaining])
                    truncated = True
                    break
        except Exception:
            pass
            
        exec_info = self.client.api.exec_inspect(exec_id)
        exit_code = exec_info.get("ExitCode", -1)
        
        # GNU timeout exits with 124 if the command times out.
        timed_out = (exit_code == 124)
        
        return exit_code, bytes(stdout_buf), bytes(stderr_buf), truncated, timed_out
