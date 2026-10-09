"""judge-check: verify the red -> green claim yourself. No API keys, no network.

For every vulnerability class it runs the class's PoC against the vulnerable app
(must say VULNERABLE) and against a known-good fix (must say SAFE), then runs
the functional tests on both. It also checks that ScoreRisk is deterministic.

Usage: python judge_check.py
"""
import os
import subprocess
import sys

from catalog import CLASSES
from scorerisk import score_all

VULNERABLE, FIXED = "target_app", "reference_patch"
checks = []


def check(name, ok, detail=""):
    checks.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def run(cmd, env=None):
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def main():
    for cwe, info in CLASSES.items():
        code, _ = run([sys.executable, info["poc"], VULNERABLE])
        check(f"{cwe} {info['name']}: exploit works on {VULNERABLE} (RED)", code == 1, f"exit={code}")
        code, _ = run([sys.executable, info["poc"], FIXED])
        check(f"{cwe} {info['name']}: exploit blocked on {FIXED} (GREEN)", code == 0, f"exit={code}")

    for app_dir in (VULNERABLE, FIXED):
        code, out = run([sys.executable, "-m", "pytest", "-q"], env={**os.environ, "APP_DIR": app_dir})
        check(f"functional tests pass on {app_dir}", code == 0, out.splitlines()[-1] if out else "")

    first, _ = score_all()
    second, _ = score_all()
    check("ScoreRisk is deterministic (same input -> same ranking)", first == second)
    by_id = {r["id"]: r for r in first}
    check(
        "the CVSS 9.8 / low-exploitation finding ranks below the CVSS 7.5 KEV finding",
        by_id["F-11"]["rank"] > by_id["F-04"]["rank"],
        f"F-11 #{by_id['F-11']['rank']} vs F-04 #{by_id['F-04']['rank']}",
    )

    print("\nJUDGE-CHECK:", "ALL PASSED" if all(checks) else "FAILED")
    sys.exit(0 if all(checks) else 1)


if __name__ == "__main__":
    main()
