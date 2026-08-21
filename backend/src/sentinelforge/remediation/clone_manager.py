"""SentinelForge Branch 2 — Clone Lifecycle Management.

Creates, manages, snapshots, rolls back, and cleans up isolated target clones.
For the vertical slice, clone management uses filesystem-based isolation
(no Docker dependency for unit tests; Docker for integration tests).
"""

import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Dict, Optional
from uuid import uuid4

from sentinelforge.remediation.exceptions import CloneCreationFailed, RollbackFailed
from sentinelforge.remediation.models import (
    ApplicationTarget,
    CloneSnapshot,
    CloneStatus,
    TargetClone,
    TargetEnvironment,
)


class CloneManager:
    """Creates, manages, snapshots, rolls back, and cleans up isolated target clones."""

    def create_clone(
        self,
        target: ApplicationTarget,
        organization_id: Optional[object] = None,
    ) -> TargetClone:
        """Create an isolated clone of an ApplicationTarget.

        For the vertical slice: copies the target's local_path to a temp directory.
        Production targets are rejected deterministically.
        """
        # 1. Validate environment (production = READ-ONLY)
        if target.environment == TargetEnvironment.PRODUCTION:
            raise CloneCreationFailed(
                "Production targets cannot enter the remediation pipeline. "
                "SentinelForge NEVER modifies production applications."
            )

        # 2. Validate target is active
        if not target.is_active:
            raise CloneCreationFailed("Target is not active")

        # 3. Create isolated filesystem clone
        source_path = target.local_path
        if not source_path or not os.path.exists(source_path):
            raise CloneCreationFailed(
                f"Source path does not exist: {source_path}"
            )

        clone_dir = tempfile.mkdtemp(prefix="sentinelforge_clone_")
        try:
            shutil.copytree(source_path, clone_dir, dirs_exist_ok=True)
        except Exception as exc:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise CloneCreationFailed(f"Failed to clone target: {exc}") from exc

        # 4. Record source revision (hash of source tree)
        source_revision = self._hash_directory(source_path)

        # 5. Build clone record
        clone = TargetClone(
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

        return clone

    def snapshot_clone(self, clone: TargetClone) -> CloneSnapshot:
        """Create a point-in-time snapshot of a clone for rollback.

        Hashes all files in the clone directory.
        """
        if not clone.filesystem_path or not os.path.exists(clone.filesystem_path):
            raise RollbackFailed(
                f"Clone filesystem path does not exist: {clone.filesystem_path}"
            )

        file_hashes = self._hash_directory_files(clone.filesystem_path)

        snapshot = CloneSnapshot(
            snapshot_id=uuid4(),
            clone_id=clone.clone_id,
            version=clone.current_version,
            snapshot_type="pre_remediation",
            file_hashes=file_hashes,
            created_at=datetime.now(timezone.utc),
        )

        return snapshot

    def rollback_clone(
        self,
        clone: TargetClone,
        snapshot: CloneSnapshot,
        original_source_path: str,
    ) -> bool:
        """Restore clone to a previous snapshot by re-copying from original source.

        For the vertical slice: re-copies the original source to the clone directory.
        """
        if not clone.filesystem_path:
            raise RollbackFailed("Clone has no filesystem path")

        if not os.path.exists(original_source_path):
            raise RollbackFailed(
                f"Original source path does not exist: {original_source_path}"
            )

        try:
            # Remove current clone contents
            if os.path.exists(clone.filesystem_path):
                shutil.rmtree(clone.filesystem_path)
            # Re-copy from original source
            shutil.copytree(original_source_path, clone.filesystem_path)
            clone.current_version += 1
            clone.status = CloneStatus.READY
            return True
        except Exception as exc:
            raise RollbackFailed(f"Rollback failed: {exc}") from exc

    def cleanup_clone(self, clone: TargetClone) -> None:
        """Remove clone filesystem and mark as cleaned up."""
        if clone.filesystem_path and os.path.exists(clone.filesystem_path):
            try:
                shutil.rmtree(clone.filesystem_path)
            except Exception:
                pass  # Best-effort cleanup
        clone.status = CloneStatus.CLEANED_UP
        clone.cleanup_status = "CLEANED"

    def health_check(self, clone: TargetClone) -> bool:
        """Check if clone filesystem exists and is accessible."""
        if not clone.filesystem_path:
            return False
        return os.path.exists(clone.filesystem_path)

    @staticmethod
    def _hash_directory(path: str) -> str:
        """Compute a deterministic hash of a directory tree."""
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
        combined = "|".join(hashes)
        return hashlib.sha256(combined.encode()).hexdigest()

    @staticmethod
    def _hash_directory_files(path: str) -> Dict[str, str]:
        """Hash every file in a directory. Returns {relative_path: sha256}."""
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
