from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def run(cmd: list[str]) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {"cmd": cmd, "returncode": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as exc:
        return {"cmd": cmd, "error": str(exc)}


def main():
    report = {
        "python": run(["python", "--version"]),
        "pytest": run(["python", "-m", "pytest", "--version"]),
        "rg_available": bool(shutil.which("rg")),
        "docker_available": bool(shutil.which("docker")),
        "docker_version": run(["docker", "--version"]) if shutil.which("docker") else None,
        "sandbox_status": {
            "current": "disposable_workspace_executor",
            "docker": "available" if shutil.which("docker") else "not_available_on_this_machine",
            "production_recommendation": "Use Docker, Firecracker, gVisor, or another hardened isolation layer for production.",
        },
    }
    out = Path("outputs/environment_report.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
