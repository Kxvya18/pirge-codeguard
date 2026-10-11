"""
Sandboxed executor for PIRGE-CodeGuard.

This executor is intentionally simple and conservative. It creates a disposable
workspace from scenario artifacts and runs only actions that PIRGE-CodeGuard has
already allowed. It is not a replacement for OS-level containers or VM isolation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from src.pirge_codeguard import ActionProposal, Artifact


@dataclass
class ExecutionResult:
    action_id: str
    executed: bool
    status: str
    cwd: str
    command: str
    returncode: int | None
    latency_ms: float | None
    stdout_tail: str
    stderr_tail: str
    note: str


def docker_available() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        probe = subprocess.run([docker, "info"], capture_output=True, text=True, timeout=5)
        return probe.returncode == 0
    except Exception:
        return False


def safe_join(root: Path, rel: str) -> Path:
    cleaned = rel.replace("\\", "/")
    if cleaned.startswith("/") or cleaned.startswith("../") or "/../" in cleaned:
        raise ValueError(f"unsafe relative path: {rel}")
    target = (root / cleaned).resolve()
    root_resolved = root.resolve()
    if root_resolved != target and root_resolved not in target.parents:
        raise ValueError(f"path escapes sandbox: {rel}")
    return target


def prepare_workspace(root: Path, artifacts: list[Artifact]) -> Path:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        target = safe_join(root, artifact.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(artifact.text, encoding="utf-8")
    return root


def apply_simple_diff(path: Path, diff: str) -> str:
    if not diff.strip():
        return "empty diff; no file change applied"
    original = path.read_text(encoding="utf-8") if path.exists() else ""
    old_lines = []
    new_lines = []
    for line in diff.splitlines():
        if line.startswith("- ") or line.startswith("-"):
            old_lines.append(line[1:].lstrip())
        elif line.startswith("+ ") or line.startswith("+"):
            new_lines.append(line[1:].lstrip())
    if old_lines and new_lines:
        old = "\n".join(old_lines)
        new = "\n".join(new_lines)
        if old in original:
            path.write_text(original.replace(old, new, 1), encoding="utf-8")
            return "applied replace-style diff"
    if new_lines:
        path.parent.mkdir(parents=True, exist_ok=True)
        suffix = "\n" if original and not original.endswith("\n") else ""
        path.write_text(original + suffix + "\n".join(new_lines) + "\n", encoding="utf-8")
        return "appended added lines"
    return "diff not applied; unsupported simple format"


def execute_allowed_action(root: Path, action: ActionProposal, timeout: float = 10) -> ExecutionResult:
    start = time.perf_counter()
    try:
        if action.action_type == "edit":
            target = safe_join(root, action.file_path)
            note = apply_simple_diff(target, action.file_diff)
            elapsed = (time.perf_counter() - start) * 1000
            return ExecutionResult(
                action.action_id,
                True,
                "edited",
                str(root),
                "",
                0,
                round(elapsed, 3),
                "",
                "",
                note,
            )

        if action.action_type == "shell":
            path_parts = [
                str(Path(sys.executable).parent),
                "/Applications/ChatGPT.app/Contents/Resources",
                "/opt/homebrew/bin",
                "/usr/local/bin",
                "/usr/bin",
                "/bin",
                "/usr/sbin",
                "/sbin",
            ]
            safe_env = {
                "PATH": os.pathsep.join(dict.fromkeys(path_parts)),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            completed = subprocess.run(
                action.command,
                cwd=root,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=safe_env,
            )
            elapsed = (time.perf_counter() - start) * 1000
            return ExecutionResult(
                action.action_id,
                True,
                "completed" if completed.returncode == 0 else "failed",
                str(root),
                action.command,
                completed.returncode,
                round(elapsed, 3),
                completed.stdout[-2000:],
                completed.stderr[-2000:],
                "allowed shell command executed in disposable workspace",
            )
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return ExecutionResult(
            action.action_id,
            False,
            "executor_error",
            str(root),
            action.command,
            None,
            round(elapsed, 3),
            "",
            "",
            str(exc),
        )

    return ExecutionResult(
        action.action_id,
        False,
        "unsupported_action_type",
        str(root),
        action.command,
        None,
        None,
        "",
        "",
        f"unsupported action_type={action.action_type}",
    )


def execute_allowed_action_docker(
    root: Path,
    action: ActionProposal,
    timeout: float = 15,
    image: str = "python:3.12-slim",
) -> ExecutionResult:
    """Execute an allowed shell action inside Docker when Docker is available.

    The container is run with network disabled, a read/write mount of only the
    disposable workspace, and no inherited host environment. Edits are still
    applied by the local diff applier because they do not need a shell.
    """
    if action.action_type == "edit":
        return execute_allowed_action(root, action, timeout=timeout)
    start = time.perf_counter()
    if not docker_available():
        elapsed = (time.perf_counter() - start) * 1000
        return ExecutionResult(
            action.action_id,
            False,
            "docker_unavailable",
            str(root),
            action.command,
            None,
            round(elapsed, 3),
            "",
            "",
            "Docker CLI/daemon unavailable; use workspace executor or install/start Docker.",
        )
    docker = shutil.which("docker") or "docker"
    cmd = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--workdir",
        "/workspace",
        "--mount",
        f"type=bind,src={root.resolve()},dst=/workspace",
        image,
        "sh",
        "-lc",
        action.command,
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env={"PATH": os.environ.get("PATH", "")})
        elapsed = (time.perf_counter() - start) * 1000
        return ExecutionResult(
            action.action_id,
            True,
            "completed" if completed.returncode == 0 else "failed",
            str(root),
            action.command,
            completed.returncode,
            round(elapsed, 3),
            completed.stdout[-2000:],
            completed.stderr[-2000:],
            f"allowed shell command executed in Docker image {image} with network disabled",
        )
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return ExecutionResult(
            action.action_id,
            False,
            "docker_executor_error",
            str(root),
            action.command,
            None,
            round(elapsed, 3),
            "",
            "",
            str(exc),
        )


def result_to_dict(result: ExecutionResult) -> dict:
    return asdict(result)
