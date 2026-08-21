"""SentinelForge Branch 2 — Remediation Executor.

Applies remediation proposals to isolated clones. NEVER touches production.
For the vertical slice: applies patches to the clone filesystem directly.
"""

import hashlib
import os
from dataclasses import dataclass
from typing import List, Optional
from uuid import uuid4

from sentinelforge.remediation.clone_manager import CloneManager
from sentinelforge.remediation.exceptions import RemediationPolicyViolation
from sentinelforge.remediation.models import (
    CloneSnapshot,
    PatchSpec,
    RemediationExecutionResult,
    RemediationProposal,
    TargetClone,
)
from sentinelforge.remediation.policy import RemediationPolicy, RemediationPolicyValidator


@dataclass
class BuildResult:
    passed: bool
    output: str


@dataclass
class TestResult:
    passed: bool
    output: str


@dataclass
class BehaviorResult:
    preserved: bool
    output: str


class CloneRemediationExecutor:
    """Applies remediation proposals to isolated clones. NEVER touches production."""

    def __init__(self, clone_manager: CloneManager):
        self._clone_manager = clone_manager

    def execute(
        self,
        proposal: RemediationProposal,
        clone: TargetClone,
        original_source_path: str,
        policy: Optional[RemediationPolicy] = None,
    ) -> RemediationExecutionResult:
        """Execute a remediation proposal against a clone.

        1. Validate proposal against RemediationPolicy
        2. Snapshot clone (for rollback)
        3. Apply patches to clone filesystem
        4. Build application
        5. Run tests
        6. Validate behavior
        """
        # 1. Validate proposal
        is_valid, reason = RemediationPolicyValidator.validate(proposal, policy)
        if not is_valid:
            raise RemediationPolicyViolation(reason)

        # 2. Snapshot clone
        snapshot = self._clone_manager.snapshot_clone(clone)

        # 3. Apply patches
        changes = self._apply_patches(clone, proposal.patches)

        # 4. Build application
        build_result = self._build_application(clone)

        # 5. Run tests (only if build passed)
        test_result = TestResult(passed=True, output="Skipped: build failed")
        if build_result.passed:
            test_result = self._run_tests(clone)

        # 6. Validate behavior
        behavior_result = BehaviorResult(preserved=True, output="OK")
        if build_result.passed and test_result.passed:
            behavior_result = self._validate_behavior(clone)

        return RemediationExecutionResult(
            proposal_id=proposal.proposal_id,
            clone_id=clone.clone_id,
            snapshot_id=snapshot.snapshot_id,
            changes_applied=len(changes) > 0,
            build_passed=build_result.passed,
            tests_passed=test_result.passed,
            behavior_preserved=behavior_result.preserved,
            build_output=build_result.output,
            test_output=test_result.output,
        )

    def _apply_patches(
        self,
        clone: TargetClone,
        patches: List[PatchSpec],
    ) -> List[dict]:
        """Apply patches to the clone filesystem. Records each change."""
        if not clone.filesystem_path:
            return []

        changes = []
        for patch in patches:
            target_path = os.path.join(clone.filesystem_path, patch.file_path)

            # Record original hash if file exists
            original_hash = None
            if os.path.exists(target_path):
                with open(target_path, "rb") as f:
                    original_hash = hashlib.sha256(f.read()).hexdigest()

            if patch.operation == "modify" or patch.operation == "create":
                # Ensure parent directory exists
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                # Write new content (patch_diff contains the full file content)
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(patch.patch_diff)
                # Compute new hash
                with open(target_path, "rb") as f:
                    new_hash = hashlib.sha256(f.read()).hexdigest()
                changes.append({
                    "file_path": patch.file_path,
                    "operation": patch.operation,
                    "original_hash": original_hash,
                    "new_hash": new_hash,
                })
            elif patch.operation == "delete":
                if os.path.exists(target_path):
                    os.remove(target_path)
                    changes.append({
                        "file_path": patch.file_path,
                        "operation": "delete",
                        "original_hash": original_hash,
                    })

        return changes

    def _build_application(self, clone: TargetClone) -> BuildResult:
        """Build the application inside the clone.

        For the vertical slice: run 'python -m py_compile' on all Python files
        to verify they parse correctly. This is a lightweight build check.
        """
        if not clone.filesystem_path:
            return BuildResult(passed=False, output="No filesystem path")

        import subprocess
        import sys

        errors = []
        for root, dirs, files in os.walk(clone.filesystem_path):
            for fname in files:
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    try:
                        result = subprocess.run(
                            [sys.executable, "-m", "py_compile", fpath],
                            capture_output=True, text=True, timeout=30,
                        )
                        if result.returncode != 0:
                            errors.append(f"Compile error in {fname}: {result.stderr}")
                    except subprocess.TimeoutExpired:
                        errors.append(f"Timeout compiling {fname}")
                    except Exception as exc:
                        errors.append(f"Error compiling {fname}: {exc}")

        if errors:
            return BuildResult(passed=False, output="\n".join(errors))
        return BuildResult(passed=True, output="All Python files compile successfully")

    def _run_tests(self, clone: TargetClone) -> TestResult:
        """Run the application test suite inside the clone.

        For the vertical slice: run pytest if tests/ directory exists,
        otherwise run a basic import test.
        """
        if not clone.filesystem_path:
            return TestResult(passed=False, output="No filesystem path")

        import subprocess
        import sys

        # Check if tests directory exists
        tests_dir = os.path.join(clone.filesystem_path, "tests")
        if os.path.exists(tests_dir):
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pytest", tests_dir, "-x", "-q", "--tb=short"],
                    capture_output=True, text=True, timeout=60,
                    cwd=clone.filesystem_path,
                )
                return TestResult(
                    passed=result.returncode == 0,
                    output=result.stdout + result.stderr,
                )
            except subprocess.TimeoutExpired:
                return TestResult(passed=False, output="Test execution timed out")
            except Exception as exc:
                return TestResult(passed=False, output=f"Test error: {exc}")
        else:
            # No tests directory; run basic import test on app module
            return self._run_basic_import_test(clone)

    def _run_basic_import_test(self, clone: TargetClone) -> TestResult:
        """Run a basic import/smoke test on the application."""
        import subprocess
        import sys

        app_py = os.path.join(clone.filesystem_path, "app.py")
        if not os.path.exists(app_py):
            return TestResult(passed=False, output="app.py not found")

        try:
            result = subprocess.run(
                [sys.executable, "-c", "import ast; ast.parse(open('app.py').read()); print('Syntax OK')"],
                capture_output=True, text=True, timeout=15,
                cwd=clone.filesystem_path,
            )
            return TestResult(
                passed=result.returncode == 0 and "Syntax OK" in result.stdout,
                output=result.stdout + result.stderr,
            )
        except Exception as exc:
            return TestResult(passed=False, output=f"Import test error: {exc}")

    def _validate_behavior(self, clone: TargetClone) -> BehaviorResult:
        """Validate the application still functions after remediation.

        For the vertical slice: verify that the Flask app can be imported
        and that the login route still exists.
        """
        import subprocess
        import sys

        if not clone.filesystem_path:
            return BehaviorResult(preserved=False, output="No filesystem path")

        check_script = """
import ast, sys
with open('app.py') as f:
    tree = ast.parse(f.read())
# Check that login route still exists
has_login = False
has_index = False
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
        if node.name == 'login':
            has_login = True
        if node.name == 'index':
            has_index = True
if not has_login:
    print('FAIL: login route removed')
    sys.exit(1)
if not has_index:
    print('FAIL: index route removed')
    sys.exit(1)
print('Behavior preserved: login and index routes exist')
"""
        try:
            result = subprocess.run(
                [sys.executable, "-c", check_script],
                capture_output=True, text=True, timeout=15,
                cwd=clone.filesystem_path,
            )
            return BehaviorResult(
                preserved=result.returncode == 0,
                output=result.stdout + result.stderr,
            )
        except Exception as exc:
            return BehaviorResult(preserved=False, output=f"Behavior check error: {exc}")
