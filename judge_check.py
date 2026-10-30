"""judge-check: verify the red -> green claim yourself. No API keys, no network.

For every vulnerability class it runs the class's PoC against the vulnerable app
(must say VULNERABLE) and against a known-good fix (must say SAFE), then runs
the functional tests on both. It also checks that ScoreRisk is deterministic.

Usage: python judge_check.py
Ends with ALL PASSED (exit code 0) only when every check ran in full and passed; FAILED (exit code 1) when any
check failed; INCOMPLETE (exit code 2) when none failed but a check script skipped part of its work (it printed
SKIP or SKIPPED, for example because the pinned scanners of requirements-scan.txt are not installed). A skipped
part is never counted as passed.
"""
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import no_network
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
incomplete = []  # check scripts that skipped part of their work: never counted as passed
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


def sub_check(name, script):
    """Run one check script and read its verdict line (CHECK-...: ALL PASSED / INCOMPLETE / FAILED), its exit code
    and the lines that start with [FAIL] or [SKIP] (never words elsewhere in the output). It passes only if it ran in
    full: exit code 0, ALL PASSED and no [SKIP] line. If it skipped a part (exit code 2 with INCOMPLETE, or a [SKIP]
    line) and no check failed, it is INCOMPLETE, which is not a pass. Anything else is a failure: exit code 1,
    FAILED, a [FAIL] line, a crash, no verdict."""
    code, out = run([sys.executable, script])
    lines = out.splitlines()
    verdicts = [line for line in lines if line.startswith("CHECK-")]
    verdict = verdicts[-1] if verdicts else (lines or ["(no output)"])[-1]
    skips = [line.strip() for line in lines if line.startswith("[SKIP]")]
    failed = code not in (0, 2) or verdict.endswith("FAILED") or any(line.startswith("[FAIL]") for line in lines)
    if not failed and ((code == 2 and ": INCOMPLETE" in verdict) or (code == 0 and skips)):
        incomplete.append(name)
        print(f"[INCOMPLETE] {name} ({(skips or [verdict])[0][:200]})")
    else:
        check(name, not failed and code == 0 and verdict.endswith("ALL PASSED"), verdict)


def main():
    no_network.install()  # this process reaches no other host; each check script installs it for itself too
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
    sub_check(
        "interactive mode: progress, same PoC and approval gating hold",
        "check_interactive.py",
    )

    # How an export is shown: pending, failed and declined are told apart, and exported=false is
    # never read as a refusal by itself. Uses temporary folders and a temporary copy of the project.
    sub_check(
        "export state: pending, failed and declined are told apart in the patch detail",
        "check_export_state.py",
    )

    # What a first-time visitor sees: the five-step loop, stated with numbers computed from the files,
    # the approval kind of each run as recorded, and one finding followed with the same PoC. Read-only.
    sub_check(
        "dashboard story: the five steps and the walkthrough match the recorded data",
        "check_walkthrough.py",
    )

    # The English / Español selector changes words only: same data in both languages, nothing left untranslated,
    # and the selected run and finding survive a switch. Read-only.
    sub_check(
        "language: Spanish and English show the same data, and the interface is fully translated",
        "check_language.py",
    )

    # Scanning another repository: the file and line of each finding are kept, nothing from that repository is
    # run, every scan keeps its own folder, the two queues use no made-up values, and the demo's files are never
    # written. Fake pip-audit output, a temporary folder, no network.
    sub_check(
        "repository scan: real file and line, nothing executed, one new folder per scan, two queues, demo untouched",
        "check_repo_scan.py",
    )

    # A patch proposal for one B602 finding: only the target function is sent, only with consent; the answer is
    # reviewed statically on a disposable copy and exported only after approval. Fake Nemotron, no request is
    # made. It needs the pinned scanners (requirements-scan.txt); without them it says SKIPPED: INCOMPLETE here.
    sub_check(
        "patch proposal (B602): only the function, only with consent, statically reviewed, never run, approved by "
        "a person before export",
        "check_patch_proposal.py",
    )

    # What MegaPatch may reach and run: model-written code is never run (sandbox or --local), the PoCs reach the
    # practice app only in-process, a scan is local unless asked otherwise, and a text search finds six network
    # call patterns only in the listed modules of MegaPatch's own code (a limited inventory, not a proof of
    # isolation). Its in-process detector refuses other hosts in its own process. Read-only.
    sub_check(
        "offline: no model-written code is run, PoCs stay in-process, scans are local by default, network call "
        "patterns only in listed modules (a text search)",
        "check_offline.py",
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
    check("judge_check itself did not try to reach another host", not no_network.ATTEMPTS, f"({no_network.ATTEMPTS})")
    if not all(checks):
        print("\nJUDGE-CHECK: FAILED")
        sys.exit(1)
    if incomplete:
        print(f"\nJUDGE-CHECK: INCOMPLETE ({len(incomplete)} check(s) skipped part of their work and did not pass: "
              + "; ".join(incomplete) + ")")
        sys.exit(2)
    print("\nJUDGE-CHECK: ALL PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
