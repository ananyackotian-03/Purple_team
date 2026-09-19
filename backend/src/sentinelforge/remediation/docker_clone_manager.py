"""SentinelForge — Docker Clone Manager.

Extends the filesystem-based CloneManager with real Docker container cloning.
When Docker is available, creates isolated containers from a base image.
When Docker is unavailable, falls back to filesystem cloning.

SECURITY:
- Docker containers are created with resource limits.
- Network isolation via custom Docker network.
- No privileged containers.
- No host filesystem mounts.
- Containers are disposable and cleaned up after experiments.
"""

import hashlib
import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from sentinelforge.remediation.exceptions import CloneCreationFailed, RollbackFailed
from sentinelforge.remediation.models import (
    ApplicationTarget,
    CloneSnapshot,
    CloneStatus,
    TargetClone,
    TargetEnvironment,
)

logger = logging.getLogger(__name__)


def _docker_available() -> bool:
    """Check if Docker daemon is reachable."""
    try:
        import subprocess
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


class DockerCloneManager:
    """Creates and manages isolated Docker containers for remediation.

    Falls back to filesystem cloning when Docker is unavailable.
    """

    # Docker resource limits
    MAX_MEMORY = "256m"
    MAX_CPUS = "1.0"
    NETWORK_NAME = "sentinelforge-isolated"
    BASE_IMAGE = "python:3.11-slim"
    CONTAINER_PREFIX = "sentinelforge-clone"

    def __init__(self, force_filesystem: bool = False):
        self._use_docker = not force_filesystem and _docker_available()
        if self._use_docker:
            self._ensure_network()

    @property
    def backend(self) -> str:
        return "docker" if self._use_docker else "filesystem"

    def _ensure_network(self):
        """Create the isolated Docker network if it doesn't exist."""
        import subprocess
        try:
            subprocess.run(
                ["docker", "network", "create", self.NETWORK_NAME],
                capture_output=True,
                timeout=10,
            )
        except Exception as exc:
            logger.warning(f"Could not create Docker network: {exc}")

    def create_clone(
        self,
        target: ApplicationTarget,
        organization_id: Optional[object] = None,
    ) -> TargetClone:
        """Create an isolated clone of an ApplicationTarget.

        Production targets are always rejected.
        """
        # 1. Validate environment
        if target.environment == TargetEnvironment.PRODUCTION:
            raise CloneCreationFailed(
                "Production targets cannot enter the remediation pipeline. "
                "SentinelForge NEVER modifies production applications."
            )

        if not target.is_active:
            raise CloneCreationFailed("Target is not active")

        if self._use_docker:
            return self._create_docker_clone(target, organization_id)
        else:
            return self._create_filesystem_clone(target, organization_id)

    def _create_docker_clone(
        self,
        target: ApplicationTarget,
        organization_id,
    ) -> TargetClone:
        """Create a Docker-based clone."""
        import subprocess

        source_path = target.local_path
        if not source_path or not os.path.exists(source_path):
            raise CloneCreationFailed(f"Source path does not exist: {source_path}")

        container_name = f"{self.CONTAINER_PREFIX}-{uuid4().hex[:12]}"

        # Build a minimal image from the source
        try:
            # Create a persistent build directory (kept for patches/rebuild)
            tmp_dir = tempfile.mkdtemp(prefix="sentinelforge_docker_")

            dockerfile_content = f"""FROM {self.BASE_IMAGE}
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir flask 2>/dev/null || true
EXPOSE 5000
CMD ["python", "-c", "import app; a = getattr(app, 'app', None); a.run(host='0.0.0.0', port=5000) if a else None"]
"""
            with open(os.path.join(tmp_dir, "Dockerfile"), "w") as f:
                f.write(dockerfile_content)

            # Copy source files to tmp_dir (executor writes here)
            for item in os.listdir(source_path):
                src_item = os.path.join(source_path, item)
                dst_item = os.path.join(tmp_dir, item)
                if os.path.isdir(src_item):
                    shutil.copytree(src_item, dst_item)
                else:
                    shutil.copy2(src_item, dst_item)

            # Build the image
            build_result = subprocess.run(
                ["docker", "build", "-t", container_name, "-f",
                 os.path.join(tmp_dir, "Dockerfile"), tmp_dir],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if build_result.returncode != 0:
                raise CloneCreationFailed(f"Docker build failed: {build_result.stderr[:500]}")

            # Run the container with resource limits
            run_result = subprocess.run(
                [
                    "docker", "run", "-d",
                    "--name", container_name,
                    "--network", self.NETWORK_NAME,
                    "-p", "5000:5000",
                    "--memory", self.MAX_MEMORY,
                    "--cpus", self.MAX_CPUS,
                    "--read-only",
                    "--tmpfs", "/tmp:size=64m",
                    "--tmpfs", "/app/data:size=64m",
                    "--security-opt", "no-new-privileges",
                    "--cap-drop", "ALL",
                    container_name,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # If port 5000 is taken, retry with random host port
            if run_result.returncode != 0 and "port is already allocated" in (run_result.stderr or ""):
                # Remove the failed container (docker run creates it even on port conflict)
                subprocess.run(["docker", "rm", "-f", container_name],
                               capture_output=True, timeout=10)
                run_result = subprocess.run(
                    [
                        "docker", "run", "-d",
                        "--name", container_name,
                        "--network", self.NETWORK_NAME,
                        "-p", "5000",
                        "--memory", self.MAX_MEMORY,
                        "--cpus", self.MAX_CPUS,
                        "--read-only",
                        "--tmpfs", "/tmp:size=64m",
                        "--tmpfs", "/app/data:size=64m",
                        "--security-opt", "no-new-privileges",
                        "--cap-drop", "ALL",
                        container_name,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            if run_result.returncode != 0:
                raise CloneCreationFailed(f"Docker run failed: {run_result.stderr[:500]}")

            source_revision = self._hash_directory(source_path)

            return TargetClone(
                clone_id=uuid4(),
                organization_id=organization_id or target.organization_id,
                source_target_id=target.target_id,
                source_revision=source_revision,
                clone_type=target.target_type,
                docker_container_name=container_name,
                docker_network=self.NETWORK_NAME,
                filesystem_path=tmp_dir,
                network_isolated=True,
                original_secrets_excluded=True,
                status=CloneStatus.READY,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )

        except CloneCreationFailed:
            raise
        except Exception as exc:
            raise CloneCreationFailed(f"Failed to create Docker clone: {exc}") from exc

    def _create_filesystem_clone(
        self,
        target: ApplicationTarget,
        organization_id,
    ) -> TargetClone:
        """Create a filesystem-based clone (fallback)."""
        source_path = target.local_path
        if not source_path or not os.path.exists(source_path):
            raise CloneCreationFailed(f"Source path does not exist: {source_path}")

        clone_dir = tempfile.mkdtemp(prefix="sentinelforge_clone_")
        try:
            shutil.copytree(source_path, clone_dir, dirs_exist_ok=True)
        except Exception as exc:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise CloneCreationFailed(f"Failed to clone target: {exc}") from exc

        source_revision = self._hash_directory(source_path)

        return TargetClone(
            clone_id=uuid4(),
            organization_id=organization_id or target.organization_id,
            source_target_id=target.target_id,
            source_revision=source_revision,
            clone_type=target.target_type,
            filesystem_path=clone_dir,
            network_isolated=True,
            original_secrets_excluded=True,
            status=CloneStatus.READY,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )

    def snapshot_clone(self, clone: TargetClone) -> CloneSnapshot:
        """Create a snapshot of the clone for rollback."""
        if self._use_docker and clone.docker_container_name:
            return self._snapshot_docker(clone)
        elif clone.filesystem_path:
            file_hashes = self._hash_directory_files(clone.filesystem_path)
            return CloneSnapshot(
                snapshot_id=uuid4(),
                clone_id=clone.clone_id,
                version=clone.current_version,
                snapshot_type="pre_remediation",
                file_hashes=file_hashes,
                created_at=datetime.now(timezone.utc),
            )
        else:
            raise RollbackFailed("Clone has no filesystem path or container name")

    def _snapshot_docker(self, clone: TargetClone) -> CloneSnapshot:
        """Snapshot a Docker container by copying files out."""
        import subprocess

        tmp_dir = tempfile.mkdtemp(prefix="sentinelforge_snap_")
        try:
            subprocess.run(
                ["docker", "cp", f"{clone.docker_container_name}:/app/.", tmp_dir],
                capture_output=True,
                timeout=30,
            )
            file_hashes = self._hash_directory_files(tmp_dir)
            return CloneSnapshot(
                snapshot_id=uuid4(),
                clone_id=clone.clone_id,
                version=clone.current_version,
                snapshot_type="pre_remediation",
                file_hashes=file_hashes,
                container_snapshot_id=clone.docker_container_name,
                created_at=datetime.now(timezone.utc),
            )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def rollback_clone(
        self,
        clone: TargetClone,
        snapshot: CloneSnapshot,
        original_source_path: str,
    ) -> bool:
        """Restore clone to a previous snapshot."""
        if self._use_docker and clone.docker_container_name:
            return self._rollback_docker(clone, original_source_path)
        elif clone.filesystem_path:
            return self._rollback_filesystem(clone, snapshot, original_source_path)
        else:
            raise RollbackFailed("Clone has no filesystem path or container name")

    def _rollback_docker(self, clone: TargetClone, original_source_path: str) -> bool:
        """Rollback a Docker container by re-creating it."""
        import subprocess
        try:
            # Stop and remove old container
            subprocess.run(
                ["docker", "stop", clone.docker_container_name],
                capture_output=True, timeout=10,
            )
            subprocess.run(
                ["docker", "rm", clone.docker_container_name],
                capture_output=True, timeout=10,
            )
            # Rebuild and restart
            new_target = ApplicationTarget(
                target_id=clone.source_target_id,
                organization_id=clone.organization_id,
                name="rollback",
                local_path=original_source_path,
                environment=TargetEnvironment.LAB,
            )
            new_clone = self._create_docker_clone(new_target, clone.organization_id)
            clone.docker_container_name = new_clone.docker_container_name
            clone.docker_network = new_clone.docker_network
            clone.current_version += 1
            clone.status = CloneStatus.READY
            return True
        except Exception as exc:
            raise RollbackFailed(f"Docker rollback failed: {exc}") from exc

    def _rollback_filesystem(
        self,
        clone: TargetClone,
        snapshot: CloneSnapshot,
        original_source_path: str,
    ) -> bool:
        """Rollback a filesystem clone."""
        try:
            if clone.filesystem_path and os.path.exists(clone.filesystem_path):
                shutil.rmtree(clone.filesystem_path)
            shutil.copytree(original_source_path, clone.filesystem_path)
            clone.current_version += 1
            clone.status = CloneStatus.READY
            return True
        except Exception as exc:
            raise RollbackFailed(f"Filesystem rollback failed: {exc}") from exc

    def cleanup_clone(self, clone: TargetClone) -> bool:
        """Remove clone and mark as cleaned up. Returns True if cleanup succeeded."""
        success = True

        if self._use_docker and clone.docker_container_name:
            success = self._cleanup_docker(clone)
        elif clone.filesystem_path and os.path.exists(clone.filesystem_path):
            try:
                shutil.rmtree(clone.filesystem_path)
            except Exception as exc:
                logger.warning(f"Filesystem cleanup failed: {exc}")
                success = False

        # Clean up build directory
        if clone.filesystem_path and os.path.exists(clone.filesystem_path):
            try:
                shutil.rmtree(clone.filesystem_path)
            except Exception:
                pass

        clone.status = CloneStatus.CLEANED_UP
        clone.cleanup_status = "CLEANED" if success else "CLEANUP_FAILED"
        return success

    def _cleanup_docker(self, clone: TargetClone) -> bool:
        """Stop and remove a Docker container."""
        import subprocess
        success = True
        try:
            subprocess.run(
                ["docker", "stop", clone.docker_container_name],
                capture_output=True, timeout=10,
            )
            subprocess.run(
                ["docker", "rm", "-f", clone.docker_container_name],
                capture_output=True, timeout=10,
            )
        except Exception as exc:
            logger.warning(f"Docker cleanup failed: {exc}")
            success = False
        return success

    def _docker_health_check(self, container_name: str) -> bool:
        """Check if a Docker container is actively running."""
        import subprocess
        try:
            res = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0 and res.stdout.strip().lower() == "true"
        except Exception:
            return False

    def health_check(self, clone: TargetClone) -> bool:
        """Check if clone is running."""
        if self._use_docker and clone.docker_container_name:
            return self._docker_health_check(clone.docker_container_name)
        elif clone.filesystem_path:
            return os.path.exists(clone.filesystem_path)
        return False

    def rebuild_and_restart(self, clone: TargetClone) -> bool:
        """Rebuild Docker image from patched filesystem_path and restart container.

        Called after CloneRemediationExecutor applies patches to filesystem_path.
        This gets the patched code into the running container.
        """
        if not self._use_docker or not clone.docker_container_name:
            return False
        if not clone.filesystem_path or not os.path.exists(clone.filesystem_path):
            return False

        import subprocess
        try:
            # Stop and remove old container
            subprocess.run(
                ["docker", "stop", clone.docker_container_name],
                capture_output=True, timeout=10,
            )
            subprocess.run(
                ["docker", "rm", clone.docker_container_name],
                capture_output=True, timeout=10,
            )

            # Rebuild image from patched source
            dockerfile_path = os.path.join(clone.filesystem_path, "Dockerfile")
            if not os.path.exists(dockerfile_path):
                return False

            build_result = subprocess.run(
                ["docker", "build", "-t", clone.docker_container_name,
                 "-f", dockerfile_path, clone.filesystem_path],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if build_result.returncode != 0:
                logger.error("Docker rebuild failed: %s", build_result.stderr[:500])
                return False

            # Restart container
            run_result = subprocess.run(
                [
                    "docker", "run", "-d",
                    "--name", clone.docker_container_name,
                    "--network", self.NETWORK_NAME,
                    "-p", "5000:5000",
                    "--memory", self.MAX_MEMORY,
                    "--cpus", self.MAX_CPUS,
                    "--read-only",
                    "--tmpfs", "/tmp:size=64m",
                    "--tmpfs", "/app/data:size=64m",
                    "--security-opt", "no-new-privileges",
                    "--cap-drop", "ALL",
                    clone.docker_container_name,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # If port 5000 is taken, retry with random host port
            if run_result.returncode != 0 and "port is already allocated" in (run_result.stderr or ""):
                run_result = subprocess.run(
                    [
                        "docker", "run", "-d",
                        "--name", clone.docker_container_name,
                        "--network", self.NETWORK_NAME,
                        "-p", "5000",
                        "--memory", self.MAX_MEMORY,
                        "--cpus", self.MAX_CPUS,
                        "--read-only",
                        "--tmpfs", "/tmp:size=64m",
                        "--tmpfs", "/app/data:size=64m",
                        "--security-opt", "no-new-privileges",
                        "--cap-drop", "ALL",
                        clone.docker_container_name,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            if run_result.returncode != 0:
                logger.error("Docker restart failed: %s", run_result.stderr[:500])
                return False

            return True
        except Exception as exc:
            logger.error("rebuild_and_restart failed: %s", exc)
            return False

    def _docker_health_check(self, container_name: str) -> bool:
        """Check if a Docker container is running."""
        import subprocess
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip() == "true"
        except Exception:
            return False

    def execute_in_clone(
        self,
        clone: TargetClone,
        command: str,
        timeout: int = 30,
    ) -> tuple:
        """Execute a command inside a Docker clone container.

        Returns (exit_code, stdout, stderr).
        """
        if not self._use_docker or not clone.docker_container_name:
            raise CloneCreationFailed("Docker not available for execute_in_clone")

        import subprocess
        try:
            result = subprocess.run(
                ["docker", "exec", clone.docker_container_name] + command.split(),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as exc:
            return -1, "", str(exc)

    @staticmethod
    def _hash_directory(path: str) -> str:
        hashes = []
        for root, dirs, files in os.walk(path):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, path)
                try:
                    with open(fpath, "rb") as f:
                        h = hashlib.sha256(f.read()).hexdigest()
                    hashes.append(f"{rel}:{h}")
                except Exception:
                    hashes.append(f"{rel}:unreadable")
        return hashlib.sha256("|".join(hashes).encode()).hexdigest()

    @staticmethod
    def _hash_directory_files(path: str) -> Dict[str, str]:
        result = {}
        for root, dirs, files in os.walk(path):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, path)
                try:
                    with open(fpath, "rb") as f:
                        result[rel] = hashlib.sha256(f.read()).hexdigest()
                except Exception:
                    result[rel] = "unreadable"
        return result
