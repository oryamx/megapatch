"""Re-judge the patches stored in recorded runs with the CURRENT judge.

This is a SEPARATE artifact. It never edits a recorded run, never calls a model, never
exports a patch, and its verdicts are not part of the original runs: it answers one
question, "would the judge we have today still accept the patch that run recorded?".

For each patch in each run it:
  1. rebuilds the patch from the diff stored in the run, checking the round trip against
     the vulnerable app as it was when the run was made (--base-ref);
  2. applies the same change to the CURRENT target_app/app.py;
  3. judges that candidate in the Nebius sandbox with the current PoCs and tests;
  4. records the original verdict next to the new one, with hashes, the judge
     fingerprint, the sandbox environment and the judge's own output.

Needs Nebius credentials (it runs the judge in the sandbox).
Usage: python rejudge.py [--base-ref 5c74bd2] [--force]
"""
import argparse
import difflib
import json
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from catalog import CLASSES, judge_files, judge_fingerprint
from evidence_utils import lf_sha as sha
from judge import is_accepted
from sandbox_judge import describe_environment, judge_in_sandbox, warm_up

DEFAULT_RUNS = ["golden_run.json", "run_with_repair.json", "human_approved_run.json"]
DEFAULT_BASE_REF = "5c74bd2"  # the published commit all three recorded runs were made on
WORKERS = 4


def parse_hunks(diff):
    hunks, current = [], None
    for line in diff.splitlines():
        if line.startswith("@@"):
            current = []
            hunks.append(current)
        elif current is not None and not line.startswith("\\") and line[:1] in (" ", "-", "+"):
            current.append((line[:1], line[1:]))
    return hunks


def apply_hunks(base_lines, hunks):
    """Apply each hunk where its old block (context + removed lines) occurs exactly once."""
    lines = list(base_lines)
    for hunk in hunks:
        old = [body for tag, body in hunk if tag in " -"]
        new = [body for tag, body in hunk if tag in " +"]
        spots = [i for i in range(len(lines) - len(old) + 1) if lines[i : i + len(old)] == old]
        if len(spots) != 1:
            raise ValueError(f"a hunk matches {len(spots)} places (expected exactly 1)")
        lines[spots[0] : spots[0] + len(old)] = new
    return lines


def to_text(lines):
    return "\n".join(lines) + "\n"


def rejudge_patch(item, base_text, current_text, cwe, workdir):
    recorded_diff = item["diff"]
    hunks = parse_hunks(recorded_diff)
    result = {"diff_sha256": sha(recorded_diff)}

    # 1. Round trip: the diff must rebuild exactly the patch that was judged back then.
    try:
        old_lines = base_text.splitlines()
        rebuilt = to_text(apply_hunks(old_lines, hunks))
        again = "".join(
            difflib.unified_diff(
                base_text.splitlines(keepends=True),
                rebuilt.splitlines(keepends=True),
                "target_app/app.py",
                f"candidates/{cwe}/app.py",
            )
        )
        result["diff_roundtrip_ok"] = again == recorded_diff
    except ValueError as exc:
        result["diff_roundtrip_ok"] = False
        result["roundtrip_error"] = str(exc)

    # 2. Same change, applied to the vulnerable app the current judge uses.
    try:
        candidate = to_text(apply_hunks(current_text.splitlines(), hunks))
    except ValueError as exc:
        result["rejudged"] = {"could_not_apply": str(exc)}
        return result
    result["candidate_sha256"] = sha(candidate)
    cdir = Path(workdir)
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "app.py").write_text(candidate, encoding="utf-8", newline="\n")

    # 3. Judge it in the sandbox, with the current PoC and tests.
    poc_code, poc_out, test_code, test_out = judge_in_sandbox(cdir, CLASSES[cwe]["poc"])
    result["rejudged"] = {
        "accepted": is_accepted(poc_code, test_code),
        "poc": CLASSES[cwe]["poc"],
        "poc_exit": poc_code,
        "tests_exit": test_code,
        "poc_output": poc_out,
        "tests_output_tail": (test_out or "")[-700:],
    }
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-ref", default=DEFAULT_BASE_REF)
    parser.add_argument("--runs", nargs="*", default=DEFAULT_RUNS)
    parser.add_argument("--force", action="store_true", help="overwrite an existing record for this judge version")
    args = parser.parse_args()

    fingerprint = judge_fingerprint()
    out = Path("evidence") / f"rejudge_{fingerprint}.json"
    if out.exists() and not args.force:
        raise SystemExit(f"{out} already exists (same judge version). Use --force to overwrite it.")

    base_text = subprocess.run(
        ["git", "show", f"{args.base_ref}:target_app/app.py"], capture_output=True, text=True, check=True
    ).stdout.replace("\r\n", "\n")
    current_text = Path("target_app/app.py").read_text(encoding="utf-8")

    warm_up()
    environment = describe_environment()

    jobs = []
    with tempfile.TemporaryDirectory() as tmp:
        for run_name in args.runs:
            run_path = Path("evidence") / run_name
            run = json.loads(run_path.read_text(encoding="utf-8"))
            for finding_id, patch in run["patches"].items():
                cwe = finding_id.split(":")[-1]
                workdir = Path(tmp) / f"{run_path.stem}_{cwe}"
                jobs.append((run_path, run, finding_id, cwe, patch, workdir))

        def work(job):
            run_path, run, finding_id, cwe, patch, workdir = job
            res = rejudge_patch(patch, base_text, current_text, cwe, workdir)
            return {
                "run_file": f"evidence/{run_path.name}",
                "run_sha256": sha(run_path.read_bytes()),
                "finding_id": finding_id,
                "cwe": cwe,
                "original": {
                    "judge_fingerprint": run.get("judge_fingerprint"),
                    "accepted": patch.get("accepted"),
                    "attempts": patch.get("attempts"),
                    "approval": patch.get("approval"),
                    "exported": patch.get("exported"),
                },
                **res,
            }

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = list(pool.map(work, jobs))

    for r in results:
        now = r["rejudged"].get("accepted")
        r["verdict_changed"] = (r["original"]["accepted"] is True) and (now is False)

    record = {
        "kind": "rejudge",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": (
            "Separate artifact. The recorded runs were not modified and these verdicts are not part of "
            "them. Nothing was exported and no model was called."
        ),
        "judge_fingerprint": fingerprint,
        "judge_fingerprint_files": judge_files(),
        "judge_fingerprint_not_covered": (
            "packages installed in the sandbox at run time (see sandbox_environment), the contree-sdk "
            "version, and Nebius platform behavior"
        ),
        "sandbox_environment": environment,
        "base_ref_for_recorded_diffs": args.base_ref,
        "base_target_app_sha256": sha(base_text),
        "current_target_app_sha256": sha(current_text),
        "results": results,
        "summary": {
            "patches_rejudged": len(results),
            "accepted_originally": sum(1 for r in results if r["original"]["accepted"]),
            "accepted_by_current_judge": sum(1 for r in results if r["rejudged"].get("accepted")),
            "verdict_changed_to_rejected": sum(1 for r in results if r["verdict_changed"]),
            "could_not_apply": sum(1 for r in results if "could_not_apply" in r["rejudged"]),
            "diff_roundtrip_failed": sum(1 for r in results if not r.get("diff_roundtrip_ok")),
        },
    }
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")

    print(f"judge fingerprint {fingerprint} | sandbox {environment}")
    print(f"{'run':26}{'finding':16}{'then':>8}{'now':>10}  roundtrip")
    for r in results:
        now = r["rejudged"].get("accepted")
        print(
            f"{Path(r['run_file']).stem:26}{r['finding_id']:16}"
            f"{'accepted' if r['original']['accepted'] else 'rejected':>8}"
            f"{('accepted' if now else 'REJECTED') if now is not None else 'n/a':>10}  "
            f"{'ok' if r.get('diff_roundtrip_ok') else 'FAILED'}"
        )
    print(json.dumps(record["summary"], indent=2))
    print(f"\nWritten {out} (nothing exported, recorded runs untouched)")


if __name__ == "__main__":
    main()
