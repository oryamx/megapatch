"""judge-check: verify the red -> green claim yourself. No API keys, no network.

For every vulnerability class it runs the class's PoC against the vulnerable app
(must say VULNERABLE) and against a known-good fix (must say SAFE), then runs
the functional tests on both. It also checks that ScoreRisk is deterministic.

Usage: python judge_check.py
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from catalog import CLASSES
from scorerisk import FINGERPRINT_VERSION, fingerprint, score_all

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

    # Adversarial: a "fix" that just removes the feature must not count as a fix.
    # The PoC must report BROKEN (exit 2), never SAFE.
    source = Path(VULNERABLE, "app.py").read_text(encoding="utf-8")
    for cwe, info in CLASSES.items():
        with tempfile.TemporaryDirectory() as tmp:
            disabled = source.replace(f'@app.get("{info["route"]}")', f'@app.get("{info["route"]}_disabled")')
            Path(tmp, "app.py").write_text(disabled, encoding="utf-8")
            code, _ = run([sys.executable, info["poc"], tmp])
        check(f"{cwe}: a 'patch' that deletes the route is rejected, not accepted", code == 2, f"exit={code}")

    # The recorded runs shipped in evidence/ must describe the ranking this checkout computes.
    ranking_now, _ = score_all()
    current = {r["id"]: (r["rank"], r["pre_score"], r["cvss"]) for r in ranking_now}
    for name in ("golden_run.json", "run_with_repair.json"):
        data = json.loads(Path("evidence", name).read_text(encoding="utf-8"))
        if data.get("fingerprint_version") == FINGERPRINT_VERSION:
            ok = data.get("inventory_fingerprint") == fingerprint()
            how = "full fingerprint (v2) matches"
        else:
            # Recorded before the full fingerprint existed: compare what the file did record.
            recorded = {i["id"]: (i["scorerisk_rank"], i["pre_score"], i["cvss"]) for i in data["final_order"]}
            ok = recorded == current
            how = "legacy run: recorded ids, ranks, scores and CVSS equal the current ranking"
        check(f"evidence/{name} corresponds to the current inputs", ok, f"({how})")

    first, _ = score_all()
    second, _ = score_all()
    check("ScoreRisk is deterministic (same input -> same ranking)", first == second)
    by_cve = {r["cve"]: r for r in first if r["cve"]}
    rare, kev = by_cve["CVE-2023-37920"], by_cve["CVE-2023-4863"]  # certifi vs libwebp (via Pillow)
    check(
        "a higher-CVSS, rarely exploited finding ranks below a lower-CVSS finding that is in KEV",
        (rare["cvss"] or 0) > (kev["cvss"] or 0) and rare["rank"] > kev["rank"] and kev["kev"],
        f"CVE-2023-37920 CVSS {rare['cvss']} #{rare['rank']} vs CVE-2023-4863 CVSS {kev['cvss']} #{kev['rank']}",
    )

    print("\nJUDGE-CHECK:", "ALL PASSED" if all(checks) else "FAILED")
    sys.exit(0 if all(checks) else 1)


if __name__ == "__main__":
    main()
