"""Focused check: how a patch's export state is read and shown.

`exported: false` is not a refusal. A record that says "pending" or "failed" also has it, so the
text must follow `export_status` and say "the person declined" only for "declined".

Three layers, all in temporary folders (no run, diff or evidence file of the project is touched):
  A. evidence_utils.describe_export over every combination of the fields it reads;
  B. records really written by interactive.decide(), read back through describe_export;
  C. the dashboard itself, rendered headless from a temporary COPY of the project.

Usage: python check_export_state.py   (judge_check.py runs it too)
"""
import itertools
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import check_interactive as ci
import interactive as ia
from evidence_utils import describe_export

HERE = Path(__file__).resolve().parent
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


HUMAN = "human, on the judge-accepted patch (the sandbox ran it automatically; interactive dashboard)"
AUTO = "auto (--yes)"
NONE = "none (the judge did not accept the patch, so no export decision was asked)"


def patch(status, exported, *, approval=HUMAN, accepted=True, **extra):
    base = {"accepted": accepted, "approval": approval, "exported": exported}
    if status is not None:
        base["export_status"] = status
    return {**base, **extra}


# The child renders the dashboard from a temporary copy of the project: it writes four real
# interactive records there (through ia.decide), then loads each run in the dashboard headless.
RENDER_CHILD = """
import json, os
from pathlib import Path
import check_interactive as ci
import interactive as ia
from catalog import CLASSES, judge_fingerprint
from scorerisk import FINGERPRINT_VERSION, fingerprint, score_all

ranked, _ = score_all()
finding = next(r for r in ranked if r.get("cwe") in CLASSES)
fp = {"inventory": fingerprint(), "version": FINGERPRINT_VERSION, "judge": judge_fingerprint()}
evidence, export_root = Path("evidence"), Path("out") / "patches"
usage = {"nemotron_calls": 1, "tokens": 10, "est_cost_usd": 0.0}


def session():
    result, _, _ = ci.run(ci.FakeJudge(ci.VULNERABLE, ci.SAFE_OK), cwe=finding["cwe"])
    return result


def decide(result, approve):
    return ia.decide(result, approve, finding=finding, ranked=ranked, stamp="20261012T000000Z", model="m",
                     usage=usage, fingerprints=fp, human_wait_s=3.0, export_root=export_root,
                     evidence_dir=evidence)


sessions = {}
r = session(); sessions["exported"] = r["session_id"]; decide(r, True)
r = session(); sessions["declined"] = r["session_id"]; decide(r, False)

r = session(); sessions["pending"] = r["session_id"]          # finalizing the record fails
real_replace = ia.os.replace
def broken(src, dst):
    raise OSError("the disk went away")
ia.os.replace = broken
try:
    decide(r, True)
except OSError:
    pass
finally:
    ia.os.replace = real_replace

r = session(); sessions["failed"] = r["session_id"]            # the diff cannot be written
(export_root / r["session_id"]).parent.mkdir(parents=True, exist_ok=True)
(export_root / r["session_id"]).write_text("a file where the export folder should be", encoding="utf-8")
try:
    decide(r, True)
except OSError:
    pass

from streamlit.testing.v1 import AppTest

at = AppTest.from_file("dashboard.py", default_timeout=180).run()
labels = list(at.sidebar.selectbox[0].options)
out = {"sessions": sessions, "runs": []}
for index, label in enumerate(labels):
    page = at.sidebar.selectbox[0].select_index(index).run()
    out["runs"].append({
        "label": label,
        "exceptions": [str(e.value) for e in page.exception],
        "judge_lines": [m.value for m in page.markdown if m.value.startswith("**Judge:")],
        "banners": [s.value for s in page.success],
    })
print("RENDER-JSON:" + json.dumps(out))
"""


def main():
    # --- A. describe_export over every combination -------------------------------------------
    cases = {
        "pending": (patch("pending", False), "pending", ["export pending"]),
        "failed": (patch("failed", False, export_error="OSError: boom"), "failed",
                   ["export failed", "OSError: boom"]),
        "declined": (patch("declined", False), "declined", ["the person declined to export it"]),
        "exported": (patch("exported", True), "exported", ["export approved by a person"]),
    }
    for name, (p, kind, needles) in cases.items():
        got_kind, text = describe_export(p)
        check(f"state: export_status={name} reads as '{kind}' and says so",
              got_kind == kind and all(n in text for n in needles), f"-> {text!r}")
    for name in ("pending", "failed"):
        _, text = describe_export(cases[name][0])
        check(f"state: export_status={name} with exported=false is NOT shown as a refusal by the person",
              "declin" not in text.lower() and "refus" not in text.lower() and "rejected" not in text.lower())

    wrong, combinations = [], 0
    for approval, status, exported, accepted in itertools.product(
            (HUMAN, AUTO, NONE, ""), (None, "exported", "pending", "failed", "declined", "not_applicable", "weird"),
            (True, False), (True, False)):
        combinations += 1
        kind, text = describe_export(patch(status, exported, approval=approval, accepted=accepted))
        says_declined = "person declined" in text
        should_decline = accepted and status == "declined" and not exported
        should_pend = accepted and status == "pending" and not exported
        should_fail = accepted and status == "failed" and not exported
        if (kind == "declined") != should_decline or says_declined != should_decline:
            wrong.append(("declined", approval[:6], status, exported, accepted, kind))
        if (kind == "pending") != should_pend or (kind == "failed") != should_fail:
            wrong.append(("pending/failed", approval[:6], status, exported, accepted, kind))
    check(f"state: over all {combinations} combinations, 'the person declined' appears only for "
          "export_status=declined (accepted, exported=false); pending and failed only for their own status",
          not wrong and combinations == 112, f"{wrong[:3]}")

    legacy_no = describe_export(patch(None, False))
    check("state: an older record (no export_status) with exported=false is not called a refusal, and says it is old",
          legacy_no[0] == "not_approved" and "declin" not in legacy_no[1] and "older record" in legacy_no[1],
          f"-> {legacy_no[1]!r}")
    check("state: an older record exported with a person's approval, and one exported with --yes, keep their meaning",
          describe_export(patch(None, True))[0] == "exported"
          and describe_export(patch(None, True, approval=AUTO))[0] == "auto_exported")
    contradictory = [describe_export(patch("exported", False))[0], describe_export(patch("pending", True))[0],
                     describe_export(patch("declined", True))[0]]
    check("state: a record that contradicts itself is flagged, not guessed", contradictory == ["inconsistent"] * 3)
    check("state: an unknown export_status is reported as unknown, not interpreted",
          describe_export(patch("weird", False))[0] == "unknown")

    # --- B. records really written by decide(), read back -----------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        def one(approve, mutate=None):
            res, _, _ = ci.run(ci.FakeJudge(ci.VULNERABLE, ci.SAFE_OK))
            if mutate:
                mutate(res, tmp)
            try:
                ci.decide(res, approve, tmp)
            except OSError:
                pass
            rec = json.loads((Path(tmp) / "evidence" / f"interactive_run_{res['session_id']}.json")
                             .read_text(encoding="utf-8"))
            return describe_export(next(iter(rec["patches"].values())))

        approved = one(True)
        declined = one(False)

        def block_folder(res, base):
            folder = Path(base) / "out" / res["session_id"]
            folder.parent.mkdir(parents=True, exist_ok=True)
            folder.write_text("a file where the export folder should be", encoding="utf-8")

        failed = one(True, block_folder)

        real_replace = ia.os.replace
        def broken(src, dst):
            raise OSError("the disk went away")
        ia.os.replace = broken
        try:
            pending = one(True)
        finally:
            ia.os.replace = real_replace

        res, _, _ = ci.run(ci.FakeJudge(ci.VULNERABLE, ci.STILL_VULN, ci.STILL_VULN))
        ci.decide(res, False, tmp)
        rec = json.loads((Path(tmp) / "evidence" / f"interactive_run_{res['session_id']}.json")
                         .read_text(encoding="utf-8"))
        rejected = describe_export(next(iter(rec["patches"].values())))

    check("records: what interactive.decide() writes is read back as the same state",
          [approved[0], declined[0], failed[0], pending[0], rejected[0]]
          == ["exported", "declined", "failed", "pending", "not_accepted"],
          f"({[approved[0], declined[0], failed[0], pending[0], rejected[0]]})")
    check("records: the failed one carries the error, and neither pending nor failed says 'declined'",
          "export failed" in failed[1] and "declined" not in failed[1] and "declined" not in pending[1])

    # --- C. the dashboard, rendered headless from a temporary copy of the project ------------
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "project"
        copy.mkdir()
        for source in HERE.glob("*.py"):
            shutil.copy2(source, copy / source.name)
        for folder in ("data", "scans", "target_app", "reference_patch"):  # inputs the dashboard reads
            shutil.copytree(HERE / folder, copy / folder, ignore=shutil.ignore_patterns("__pycache__"))
        (copy / "evidence").mkdir()
        for name in ("golden_run.json", "human_approved_run.json",
                     "human_approved_run_b.json"):  # read-only copies of the real runs
            shutil.copy2(HERE / "evidence" / name, copy / "evidence" / name)
        try:  # it normally takes about 10 s; a hang must be a clear failure, not a ten-minute wait
            proc = subprocess.run([sys.executable, "-c", RENDER_CHILD], cwd=copy, capture_output=True, text=True,
                                  timeout=240)
        except subprocess.TimeoutExpired:
            proc = subprocess.CompletedProcess([], returncode=-1, stdout="", stderr="timed out after 240 s")
        line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RENDER-JSON:")), None)
        if proc.returncode != 0 or line is None:
            check("dashboard: rendered headless from a temporary copy", False,
                  f"(exit {proc.returncode}) {(proc.stderr or proc.stdout).strip()[-600:]}")
        else:
            data = json.loads(line.removeprefix("RENDER-JSON:"))
            sessions = data["sessions"]

            def judge_lines(fragment):
                runs = [r for r in data["runs"] if fragment in r["label"]]
                return runs[0] if runs else {"judge_lines": [], "banners": [], "exceptions": ["run not listed"]}

            check("dashboard: every run rendered without an exception",
                  len(data["runs"]) == 7 and all(not r["exceptions"] for r in data["runs"]),
                  f"({len(data['runs'])} runs)")
            expected = {
                "exported": (["export approved by a person"], ["declin", "pending", "failed"],
                             "1 of 1 were approved."),
                "declined": (["the person declined to export it"], ["pending", "export failed"],
                             "0 of 1 were approved."),
                "pending": (["export pending", "export_status: pending"], ["declin", "export failed"],
                            "1 of 1 were approved (0 exported, 1 pending, 0 failed)"),
                "failed": (["export failed", "export_status: failed"], ["declin", "export pending"],
                           "1 of 1 were approved (0 exported, 0 pending, 1 failed)"),
            }
            for name, (needles, banned, banner) in expected.items():
                run = judge_lines(sessions[name])
                text = " ".join(run["judge_lines"])
                check(f"dashboard: the patch detail of the '{name}' session shows the right state",
                      len(run["judge_lines"]) == 1 and all(n in text for n in needles)
                      and not any(b in text.lower() for b in banned)
                      and any(banner in b for b in run["banners"]),
                      f"-> {text[:150]!r}")
            human = judge_lines("approved by a person")
            human_text = " ".join(human["judge_lines"])
            check("dashboard: the older human-approved run is not turned into a 'declined' (no export_status)",
                  human_text.count("export approved by a person") == 2 and "did not approve it" in human_text
                  and "declin" not in human_text.lower()
                  and any("2 of 3 were approved." in b for b in human["banners"]),
                  f"-> {human_text[:120]!r}")
            # Run B: a readable label, three exported patches, no refusal anywhere, "3 of 3 were approved".
            run_b = judge_lines("Recorded run with the current judge")
            b_text = " ".join(run_b["judge_lines"])
            check("dashboard: the run made with the current judge has a readable label and shows three "
                  "approved exports, no refusal",
                  len(run_b["judge_lines"]) == 3 and b_text.count("export approved by a person") == 3
                  and "declin" not in b_text.lower() and "did not approve" not in b_text
                  and any("3 of 3 were approved." in b for b in run_b["banners"])
                  and "human_approved_run_b.json" not in " ".join(r["label"] for r in data["runs"]),
                  f"-> {len(run_b['judge_lines'])} patches")

    print("\nCHECK-EXPORT-STATE:", "ALL PASSED" if all(results) else "FAILED")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
