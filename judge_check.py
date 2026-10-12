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
from collections import Counter
from pathlib import Path

from catalog import CLASSES, judge_fingerprint
from evidence_utils import lf_sha
from judge import is_accepted
from scorerisk import FINGERPRINT_VERSION, fingerprint, score_all

VULNERABLE, FIXED = "target_app", "reference_patch"
# The runs the re-judge record covers. Its coverage check compares against exactly these, so it
# fails if the record misses one of them or lists any other run.
REJUDGED_RUNS = ("golden_run.json", "run_with_repair.json", "human_approved_run.json")
# Runs made with the current judge. They are checked against the inventory like the others, but they
# are NOT covered by the re-judge record (they were not re-judged: they were judged once, by the
# current judge), so they stay out of REJUDGED_RUNS and the existing record is not touched.
CURRENT_JUDGE_RUNS = ("human_approved_run_b.json",)
# The findings each of those runs must contain: exactly these, none missing and none extra.
EXPECTED_PATCHES = {"human_approved_run_b.json": ("bandit:CWE-78", "bandit:CWE-89", "manual:CWE-22")}
assert set(EXPECTED_PATCHES) == set(CURRENT_JUDGE_RUNS), "every current-judge run needs its expected patches"
INVENTORY_RUNS = REJUDGED_RUNS + CURRENT_JUDGE_RUNS
checks = []
stale_records = []


def check(name, ok, detail=""):
    checks.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def verify_rejudge_record(record_name, record, judge_now, root=Path(".")):
    """Return [(check name, ok, detail)] for one re-judge record.

    Pure function of its inputs so it can be exercised against tampered copies."""
    results = record["results"]
    findings = []

    stale = record.get("judge_fingerprint") != judge_now
    findings.append(
        (
            f"{record_name}: the judge that made the record is the current judge",
            not stale,
            "STALE: the record was made by a different judge version than the current one"
            if stale
            else f"(fingerprint {judge_now})",
        )
    )

    runs, bad_run, bad_diff, bad_original, bad_flag = {}, [], [], [], []
    for r in results:
        label = f"{r['run_file']}::{r['finding_id']}"
        run_path = root / r["run_file"]
        if not run_path.exists():
            bad_run.append(label)
            continue
        if lf_sha(run_path.read_bytes()) != r["run_sha256"]:
            bad_run.append(label)
        run = runs.setdefault(r["run_file"], json.loads(run_path.read_text(encoding="utf-8")))
        patch = run.get("patches", {}).get(r["finding_id"])
        if patch is None:
            bad_diff.append(label)
            continue
        if lf_sha(patch["diff"]) != r["diff_sha256"]:
            bad_diff.append(label)
        orig = r["original"]
        stored = (patch.get("accepted"), patch.get("exported"), patch.get("attempts"), patch.get("approval"),
                  run.get("judge_fingerprint"))
        copied = (orig.get("accepted"), orig.get("exported"), orig.get("attempts"), orig.get("approval"),
                  orig.get("judge_fingerprint"))
        if stored != copied:
            bad_original.append(label)
        expected_flag = bool(orig.get("accepted")) and r["rejudged"].get("accepted") is False
        if bool(r.get("verdict_changed")) != expected_flag:
            bad_flag.append(label)

    # The recorded verdict must be what the acceptance rule gives for the exit codes stored next to it.
    bad_rule = []
    for r in results:
        rejudged = r["rejudged"]
        if "could_not_apply" in rejudged:
            continue  # no judge output exists; reported by the totals check instead
        if rejudged.get("accepted") is not is_accepted(rejudged.get("poc_exit"), rejudged.get("tests_exit")):
            bad_rule.append(f"{r['run_file']}::{r['finding_id']}")

    # The record must cover exactly the patches of the source runs: none missing, none repeated, none extra.
    expected_pairs, missing_runs = [], []
    for name in REJUDGED_RUNS:
        run_file = root / "evidence" / name
        if not run_file.exists():
            missing_runs.append(name)
            continue
        for finding_id in json.loads(run_file.read_text(encoding="utf-8")).get("patches", {}):
            expected_pairs.append((f"evidence/{name}", finding_id))
    got_pairs = [(r["run_file"], r["finding_id"]) for r in results]
    repeated = sorted(pair for pair, count in Counter(got_pairs).items() if count > 1)
    omitted = sorted(set(expected_pairs) - set(got_pairs))
    unexpected = sorted(set(got_pairs) - set(expected_pairs))

    findings.append((f"{record_name}: each recorded verdict follows from its poc_exit and tests_exit by the acceptance rule",
                     not bad_rule, "" if not bad_rule else f"MISMATCH: {bad_rule}"))
    coverage_ok = not (repeated or omitted or unexpected or missing_runs)
    findings.append((
        f"{record_name}: it covers exactly every patch of the three source runs, once each",
        coverage_ok,
        f"({len(expected_pairs)} patches, no duplicates, no omissions)" if coverage_ok else
        f"MISMATCH: repeated={repeated} omitted={omitted} unexpected={unexpected} missing source runs={missing_runs}",
    ))
    findings.append((f"{record_name}: each result points at its run by hash, and the run is unmodified",
                     not bad_run, f"({len(results)} patches)" if not bad_run else f"MISMATCH: {bad_run}"))
    findings.append((f"{record_name}: each diff_sha256 equals the diff stored in the corresponding run",
                     not bad_diff, "" if not bad_diff else f"MISMATCH: {bad_diff}"))
    findings.append((f"{record_name}: the original verdicts copied into the record equal the runs' own data",
                     not bad_original, "" if not bad_original else f"MISMATCH: {bad_original}"))
    findings.append((f"{record_name}: every verdict_changed flag follows from the original and the new verdict",
                     not bad_flag, "" if not bad_flag else f"MISMATCH: {bad_flag}"))

    expected_totals = {
        "patches_rejudged": len(results),
        "accepted_originally": sum(1 for r in results if r["original"].get("accepted")),
        "accepted_by_current_judge": sum(1 for r in results if r["rejudged"].get("accepted")),
        "verdict_changed_to_rejected": sum(1 for r in results if r.get("verdict_changed")),
        "could_not_apply": sum(1 for r in results if "could_not_apply" in r["rejudged"]),
        "diff_roundtrip_failed": sum(1 for r in results if not r.get("diff_roundtrip_ok")),
    }
    summary = record.get("summary", {})
    mismatched = {k: {"record": summary.get(k), "results": v} for k, v in expected_totals.items() if summary.get(k) != v}
    findings.append((f"{record_name}: the summary totals add up to its results",
                     not mismatched, f"({expected_totals})" if not mismatched else f"MISMATCH: {mismatched}"))
    findings.append((f"{record_name}: every patch was rebuilt exactly and applied to the current app",
                     expected_totals["could_not_apply"] == 0 and expected_totals["diff_roundtrip_failed"] == 0,
                     ""))
    return findings


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
    recorded_runs = [n for n in INVENTORY_RUNS if Path("evidence", n).exists()]
    for name in recorded_runs:
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

    # Runs made with the current judge: they must exist, must have been made by the judge that is
    # current NOW (a run from an older judge says nothing about today's), and the data must say what
    # the README says about them: every patch accepted at the first attempt, marked human, exported.
    for name in CURRENT_JUDGE_RUNS:
        path = Path("evidence", name)
        check(f"evidence/{name} is present", path.exists())
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        recorded, now = data.get("judge_fingerprint"), judge_fingerprint()
        check(
            f"evidence/{name} was made by the current judge",
            recorded == now,
            f"(fingerprint {now})" if recorded == now
            else f"STALE: made by judge {recorded}, the current judge is {now}; this run must be repeated",
        )
        patches = data.get("patches", {})
        expected_ids = set(EXPECTED_PATCHES[name])
        missing, unexpected = sorted(expected_ids - set(patches)), sorted(set(patches) - expected_ids)
        check(
            f"evidence/{name} contains exactly {', '.join(sorted(expected_ids))}",
            not missing and not unexpected,
            f"({len(patches)} patches)" if not (missing or unexpected)
            else f"MISMATCH: missing={missing} unexpected={unexpected}",
        )
        clean = bool(patches) and all(
            p.get("accepted") is True and p.get("attempts") == 1 and not p.get("attempt_history")
            and p.get("exported") is True and str(p.get("approval", "")).startswith("human")
            for p in patches.values()
        )
        check(
            f"evidence/{name}: every patch was accepted at the first attempt, marked human and exported "
            "(no rejection in this run)",
            clean,
            f"({len(patches)} patches)",
        )

    # Adversarial: a "fix" that compares path STRINGS with startswith still leaks a sibling
    # directory whose name starts with "public". The PoC must keep reporting VULNERABLE (exit 1).
    prefix_fix = source.replace(
        "        path = public / name\n",
        "        path = (public / name).resolve()\n"
        "        if not str(path).startswith(str(public.resolve())):\n"
        "            return jsonify(error=\"not found\"), 404\n",
    )
    assert prefix_fix != source, "judge_check could not build the prefix-comparison variant"
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "app.py").write_text(prefix_fix, encoding="utf-8")
        code, out = run([sys.executable, "poc_path.py", tmp])
    check(
        "CWE-22: a startswith() 'patch' that still leaks a sibling directory is rejected",
        code == 1 and "same prefix" in out,
        f"exit={code}",
    )

    # Re-judge records are separate artifacts. Each one must be internally consistent, must point
    # at the recorded runs it covers, and must have been made by the CURRENT judge: a record from
    # an older judge says nothing about today's judge, so it fails instead of passing quietly.
    for record_path in sorted(Path("evidence").glob("rejudge_*.json")):
        record = json.loads(record_path.read_text(encoding="utf-8"))
        for name, ok, detail in verify_rejudge_record(record_path.name, record, judge_fingerprint()):
            check(name, ok, detail)
            if "STALE" in detail:
                stale_records.append(record_path.name)

    # The interactive mode's rules (progress, same PoC, approval gating), exercised with fake
    # judge/model functions: no credentials, no network, nothing written outside a temp folder.
    code, out = run([sys.executable, "check_interactive.py"])
    check(
        "interactive mode: progress, same PoC and approval gating hold",
        code == 0 and "ALL PASSED" in out,
        (out.splitlines() or [""])[-1],
    )

    # How an export is shown: pending, failed and declined are told apart, and exported=false is
    # never read as a refusal by itself. Uses temporary folders and a temporary copy of the project.
    code, out = run([sys.executable, "check_export_state.py"])
    check(
        "export state: pending, failed and declined are told apart in the patch detail",
        code == 0 and "ALL PASSED" in out,
        (out.splitlines() or [""])[-1],
    )

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

    if stale_records:
        print(
            "\nSTALE RE-JUDGE RECORD: " + ", ".join(sorted(set(stale_records)))
            + "\n  The judge (PoCs, tests, harness, app, catalog, sandbox_judge or judge.py) changed after the"
            "\n  record was made, so its verdicts describe an OLDER judge. Re-run `python rejudge.py --force`."
        )
    print("\nJUDGE-CHECK:", "ALL PASSED" if all(checks) else "FAILED")
    sys.exit(0 if all(checks) else 1)


if __name__ == "__main__":
    main()
