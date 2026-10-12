"""Checks for interactive.py: no credentials, no network, no browser, nothing outside a temp folder.

It exercises the rules of the interactive mode with fake judge/model functions:
  progress is visible, the SAME PoC is used before and after, and nothing is exported
  until a person approves a judge-accepted patch.

Usage: python check_interactive.py   (judge_check.py runs it too)
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import interactive as ia
from catalog import CLASSES

HERE = Path(__file__).resolve().parent
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


class FakeJudge:
    """Returns scripted (poc_exit, poc_output, tests_exit, tests_output) and records every call."""

    def __init__(self, *script):
        self.script, self.calls = list(script), []

    def __call__(self, app_dir, poc, run_tests=True):
        self.calls.append((str(app_dir), poc, run_tests))
        return self.script.pop(0)


VULNERABLE = (1, "VULNERABLE: the exploit fired", None, "")
SAFE_OK = (0, "SAFE: blocked", 0, "6 passed in 0.2s")
STILL_VULN = (1, "VULNERABLE: still leaks", 0, "6 passed in 0.2s")


def run(judge, generate=None, cwe="CWE-22", prepare=None, now=None, session_id=None):
    events, gen_calls = [], []

    def default_generate(c, evidence, feedback):
        gen_calls.append({"cwe": c, "evidence": evidence, "feedback": feedback})

    extra = {} if now is None else {"now": now}
    result = ia.analyze(
        cwe, judge=judge, generate=generate or default_generate,
        diff_of=lambda c: f"--- target_app/app.py\n+++ candidates/{c}/app.py\n@@\n-old\n+new\n",
        read_candidate=lambda c: "previous candidate source",
        prepare=prepare, notify=lambda stages: events.append([dict(s) for s in stages]),
        session_id=session_id, **extra,
    )
    return result, events, gen_calls


RANKED = [
    {"id": "manual:CWE-22", "rank": 4, "pre_score": 60.0, "cvss": 7.5},
    {"id": "bandit:CWE-89", "rank": 3, "pre_score": 64.6, "cvss": 9.8},
    {"id": "pillow:X", "rank": 1, "pre_score": 97.6, "cvss": 8.8},
]
FINDING = RANKED[0]
FINDING_89 = RANKED[1]
FP = {"inventory": "inv", "version": 2, "judge": "jf"}


def decide(result, approve, tmp, stamp="20260101T000000Z", finding=None, **kw):
    kw.setdefault("export_root", Path(tmp) / "out")
    kw.setdefault("evidence_dir", Path(tmp) / "evidence")
    return ia.decide(
        result, approve, finding=finding or FINDING, ranked=RANKED, stamp=stamp, model="m",
        usage={"nemotron_calls": 1, "tokens": 10, "est_cost_usd": 0.0}, fingerprints=FP,
        human_wait_s=12.3, **kw,
    )


def tree_hashes(root):
    """{relative path: sha256} of every file under root, to prove nothing was overwritten."""
    import hashlib

    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


# A child process that is killed (os._exit: no cleanup, no finally blocks) at a chosen moment of
# the export. It imports this module only for its helpers; main() is guarded by __name__.
KILLED_CHILD = """
import os, sys
import check_interactive as ci
import interactive as ia

tmp, mode = sys.argv[1], sys.argv[2]
res, _, _ = ci.run(ci.FakeJudge(ci.VULNERABLE, ci.SAFE_OK))
original = ia._create_new

def hooked(path, text):
    is_diff = str(path).endswith(".diff")
    if is_diff and mode == "before_diff":
        os._exit(7)   # killed before the diff is written
    original(path, text)
    if is_diff and mode == "after_diff":
        os._exit(7)   # killed after the diff exists, before the record is finalized

ia._create_new = hooked
ci.decide(res, True, tmp)
os._exit(0)
"""


class InterruptedHandle:
    """A file handle that dies halfway through the write, the way Ctrl+C would."""

    def __init__(self, real):
        self.real = real

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.real.close()
        return False

    def write(self, text):
        self.real.write(text[: len(text) // 2])
        self.real.flush()
        raise KeyboardInterrupt


def records_in(tmp):
    """The (single) evidence record under tmp, parsed, plus its first patch entry."""
    folder = Path(tmp) / "evidence"
    found = sorted(folder.glob("interactive_run_*.json")) if folder.exists() else []
    if len(found) != 1:
        return None, {}, len(found)
    rec = json.loads(found[0].read_text(encoding="utf-8"))
    return rec, next(iter(rec["patches"].values()), {}), 1


def temp_leftovers(tmp):
    return [p.name for p in Path(tmp).rglob("*") if p.is_file() and p.name.endswith(".tmp")]


def main():
    poc = CLASSES["CWE-22"]["poc"]

    # --- 1. progress is visible ------------------------------------------------------------
    judge = FakeJudge(VULNERABLE, SAFE_OK)
    result, events, gens = run(judge, prepare=lambda: None)
    keys = [s["key"] for s in result["stages"]]
    check("progress: stages appear in order, each announced as it starts and ends",
          keys == ["prepare", "confirm", "generate_1", "judge_1", "approval"] and len(events) >= 2 * 4,
          f"({keys})")
    check("progress: every stage has a start time and, except the waiting one, an end time",
          all(s["started_at"] for s in result["stages"])
          and all(s["finished_at"] for s in result["stages"] if s["key"] != "approval"))
    check("progress: the analysis stops at 'awaiting approval' and reports it",
          result["state"] == "awaiting_approval" and result["stages"][-1]["status"] == "pending")

    # --- 2. the SAME PoC before and after ---------------------------------------------------
    pocs = {c[1] for c in judge.calls}
    check("same PoC: the confirmation and the judging use one PoC file", pocs == {poc}, f"({pocs})")
    check("same PoC: confirmed on the vulnerable app, judged on the candidate, exit codes kept",
          judge.calls[0][0] == "target_app" and judge.calls[1][0].replace("\\", "/") == "candidates/CWE-22"
          and result["before"]["poc_exit"] == 1 and result["attempts"][0]["poc_exit"] == 0)

    # --- 3. nothing is exported until a person approves -----------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        result, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK))
        check("approval: after the analysis nothing exists in the export or evidence folders",
              not (Path(tmp) / "out").exists() and not (Path(tmp) / "evidence").exists())
        declined = decide(result, False, tmp)
        rec = json.loads(Path(declined["evidence_path"]).read_text(encoding="utf-8"))
        check("approval: 'Reject' exports nothing and records exported=false as a human decision",
              not (Path(tmp) / "out").exists() and declined["exported"] is False
              and rec["patches"][FINDING["id"]]["exported"] is False
              and rec["patches"][FINDING["id"]]["approval"].startswith("human")
              and rec["patches"][FINDING["id"]]["accepted"] is True)
        try:
            decide(result, True, tmp)       # the SAME session cannot record a second decision
            twice = False
        except FileExistsError:
            twice = True
        check("approval: a session records one decision only; a second one is refused", twice
              and not (Path(tmp) / "out").exists())

        result2, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK))
        approved = decide(result2, True, tmp)
        exported = Path(approved["export_path"])
        rec = json.loads(Path(approved["evidence_path"]).read_text(encoding="utf-8"))
        check("approval: 'Approve' writes the diff once, inside the session's own folder, and records it",
              exported.read_text(encoding="utf-8") == result2["attempts"][-1]["diff"]
              and exported.parent.name == result2["session_id"]
              and rec["patches"][FINDING["id"]]["exported"] is True
              and rec["patches"][FINDING["id"]]["export_path"] == str(exported))
        check("approval: the finished record says export_status=exported and no temporary file is left",
              rec["patches"][FINDING["id"]].get("export_status") == "exported" and not temp_leftovers(tmp))

        # the evidence must fit what the dashboard reads
        needed = {"final_order", "verdicts", "patches", "enrichment", "usage", "duration_s", "executor",
                  "model", "top_n", "inventory_fingerprint", "fingerprint_version", "judge_fingerprint"}
        check("evidence: has every key the dashboard reads, and lists all ranked findings",
              needed <= set(rec) and {i["id"] for i in rec["final_order"]} == {r["id"] for r in RANKED})

    # --- 4. repair path, and a judge that never accepts ------------------------------------
    result, _, gens = run(FakeJudge(VULNERABLE, STILL_VULN, SAFE_OK))
    check("repair: a rejected attempt sends the judge's output back to the model, once",
          len(gens) == 2 and gens[0]["feedback"] is None
          and "still leaks" in gens[1]["feedback"]["judge_output"]
          and result["state"] == "awaiting_approval" and len(result["attempts"]) == 2)

    with tempfile.TemporaryDirectory() as tmp:
        result, _, _ = run(FakeJudge(VULNERABLE, STILL_VULN, STILL_VULN))
        try:
            decide(result, True, tmp, stamp="20260101T000003Z")
            blocked = False
        except ValueError:
            blocked = True
        check("approval: a patch the judge did not accept cannot be approved", result["state"] == "rejected_by_judge"
              and blocked and not (Path(tmp) / "out").exists())
        recorded = decide(result, False, tmp, stamp="20260101T000004Z")
        rec = json.loads(Path(recorded["evidence_path"]).read_text(encoding="utf-8"))
        check("record: a judge-rejected analysis is recorded without any human-approval label",
              not rec["patches"][FINDING["id"]]["approval"].startswith("human")
              and rec["patches"][FINDING["id"]]["exported"] is False)

    # --- 5. nothing to fix, and a failure that must be visible ------------------------------
    judge = FakeJudge((0, "SAFE: not reproducible", None, ""))
    result, _, gens = run(judge)
    check("confirm: if the exploit does not fire, no patch is requested", result["state"] == "not_confirmed"
          and not gens)

    def boom(cwe, evidence, feedback):
        raise RuntimeError("model unreachable")

    result, _, _ = run(FakeJudge(VULNERABLE), generate=boom)
    check("errors: a failure shows up as a failed stage with its message, not as silence",
          result["state"] == "error" and result["stages"][-1]["status"] == "failed"
          and "model unreachable" in result["stages"][-1]["detail"])

    # --- 5b. unique sessions, nothing overwritten, no orphan diffs ----------------------------
    same_second = lambda: 1767225600.0  # noqa: E731  two sessions started in the very same second

    with tempfile.TemporaryDirectory() as tmp:
        r22, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK), cwe="CWE-22", now=same_second)
        r89, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK), cwe="CWE-89", now=same_second)
        check("sessions: two sessions started in the same second get different ids",
              r22["session_id"] != r89["session_id"]
              and r22["session_id"].split("_")[0] == r89["session_id"].split("_")[0],
              f"({r22['session_id']} vs {r89['session_id']})")

        one = decide(r22, True, tmp, stamp="20260101T000000Z", finding=FINDING)
        before = tree_hashes(tmp)
        two = decide(r89, True, tmp, stamp="20260101T000000Z", finding=FINDING_89)  # same timestamp
        after = tree_hashes(tmp)
        check("collision: two findings, the same timestamp: both are recorded and exported",
              one["evidence_path"] != two["evidence_path"] and one["export_path"] != two["export_path"]
              and Path(one["export_path"]).exists() and Path(two["export_path"]).exists())
        check("collision: the second decision overwrote nothing the first one wrote",
              all(after.get(path) == digest for path, digest in before.items()) and len(after) == len(before) + 2)
        inconsistent = []
        for ev in (one, two):
            rec = json.loads(Path(ev["evidence_path"]).read_text(encoding="utf-8"))
            patch = next(iter(rec["patches"].values()))
            if not (patch["exported"] and Path(patch["export_path"]).read_text(encoding="utf-8") == patch["diff"]):
                inconsistent.append(ev["evidence_path"])
        check("consistency: every exported diff has its own record, and the record points at it",
              not inconsistent and sum(1 for _ in Path(tmp).rglob("*.diff")) == 2
              and sum(1 for _ in (Path(tmp) / "evidence").glob("*.json")) == 2)

    # Even if two session ids ever collided, the second decision must fail BEFORE writing anything.
    with tempfile.TemporaryDirectory() as tmp:
        a, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK), cwe="CWE-22", session_id="FIXED_ID")
        b, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK), cwe="CWE-89", session_id="FIXED_ID")
        decide(a, True, tmp, finding=FINDING)
        before = tree_hashes(tmp)
        try:
            decide(b, True, tmp, finding=FINDING_89)
            refused = False
        except FileExistsError:
            refused = True
        check("collision: a forced session-id clash is refused before anything is written, no orphan diff",
              refused and tree_hashes(tmp) == before and not list(Path(tmp).rglob("CWE-89.diff")))

    # A failure while recording must not leave a diff behind; a failure while exporting must
    # not leave a record that claims an export.
    with tempfile.TemporaryDirectory() as tmp:
        blocker = Path(tmp) / "evidence"
        blocker.write_text("this is a file, so no evidence folder can be created", encoding="utf-8")
        res, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK))
        try:
            decide(res, True, tmp)
            failed = False
        except OSError:
            failed = True
        check("failure: if the record cannot be written, no diff is exported",
              failed and not (Path(tmp) / "out").exists() and not list(Path(tmp).rglob("*.diff")))

    with tempfile.TemporaryDirectory() as tmp:
        blocker = Path(tmp) / "out"
        blocker.write_text("this is a file, so no export folder can be created", encoding="utf-8")
        res, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK))
        attempted, original = [], ia._create_new

        def spy(path, text):  # not vacuous: it proves the record WAS written before the diff failed
            attempted.append(Path(path).name)
            return original(path, text)

        ia._create_new = spy
        try:
            decide(res, True, tmp)
            failed = False
        except OSError:
            failed = True
        finally:
            ia._create_new = original
        rec, patch, n_records = records_in(tmp)
        check("failure: if the diff cannot be written, the record stays and says the export FAILED, never exported",
              failed and n_records == 1 and patch.get("exported") is False
              and patch.get("export_status") == "failed" and patch.get("export_error")
              and "FAILED" in rec["final_order"][0]["status"]
              and not list(Path(tmp).rglob("*.diff")) and not temp_leftovers(tmp)
              and len(attempted) == 3 and attempted[0].startswith("interactive_run_")
              and attempted[1].endswith(".diff") and attempted[2].endswith(".tmp"),
              f"(attempts: {attempted}, status: {patch.get('export_status')})")

    # --- 5c. interruptions: the record must never claim an export that did not complete ----------
    for mode, label in (("before_diff", "killed before the diff is written"),
                        ("after_diff", "killed after the diff is written, before the record is finalized")):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run([sys.executable, "-c", KILLED_CHILD, tmp, mode], cwd=HERE,
                                  capture_output=True, text=True, timeout=120)
            rec, patch, n_records = records_in(tmp)
            diffs = list(Path(tmp).rglob("*.diff"))
            ok = (proc.returncode == 7 and n_records == 1 and patch.get("exported") is False
                  and patch.get("export_status") == "pending" and patch.get("export_path") is None
                  and bool(patch.get("export_target"))
                  and "export pending" in rec["final_order"][0]["status"]
                  and len(diffs) == (0 if mode == "before_diff" else 1)
                  and not temp_leftovers(tmp))
            check(f"interrupt: process {label}: the record says pending, exported=false",
                  ok, f"(exit {proc.returncode}, status {patch.get('export_status')}, diffs {len(diffs)}"
                      f"{', ' + proc.stderr.strip()[-200:] if proc.returncode != 7 else ''})")

    with tempfile.TemporaryDirectory() as tmp:
        res, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK))
        original_open = ia.__dict__.get("open")  # None: interactive uses the builtin

        def open_then_interrupt(path, mode="r", *args, **kwargs):
            real = open(path, mode, *args, **kwargs)  # the builtin: this module defines no open
            return InterruptedHandle(real) if str(path).endswith(".diff") else real

        ia.open = open_then_interrupt
        try:
            decide(res, True, tmp)
            interrupted = False
        except KeyboardInterrupt:
            interrupted = True
        finally:
            if original_open is None:
                del ia.open
            else:
                ia.open = original_open
        rec, patch, n_records = records_in(tmp)
        check("interrupt: Ctrl+C halfway through the diff leaves no partial diff and a record that says failed",
              interrupted and not list(Path(tmp).rglob("*.diff")) and n_records == 1
              and patch.get("exported") is False and patch.get("export_status") == "failed"
              and "KeyboardInterrupt" in patch.get("export_error", "") and not temp_leftovers(tmp))

    with tempfile.TemporaryDirectory() as tmp:
        res, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK))
        real_replace = ia.os.replace

        def replace_fails(src, dst):
            raise OSError("the disk went away")

        ia.os.replace = replace_fails
        try:
            decide(res, True, tmp)
            finalize_failed = False
        except OSError:
            finalize_failed = True
        finally:
            ia.os.replace = real_replace
        rec, patch, n_records = records_in(tmp)
        check("interrupt: if finalizing the record fails, the diff this call wrote is withdrawn and the record "
              "stays pending",
              finalize_failed and not list(Path(tmp).rglob("*.diff")) and n_records == 1
              and patch.get("exported") is False and patch.get("export_status") == "pending"
              and not temp_leftovers(tmp))

    with tempfile.TemporaryDirectory() as tmp:
        res, _, _ = run(FakeJudge(VULNERABLE, SAFE_OK))
        real_replace = ia.os.replace

        def replace_then_interrupt(src, dst):
            real_replace(src, dst)        # the record is finalized...
            raise KeyboardInterrupt       # ...and the interrupt lands right after

        ia.os.replace = replace_then_interrupt
        try:
            decide(res, True, tmp)
            late = False
        except KeyboardInterrupt:
            late = True
        finally:
            ia.os.replace = real_replace
        rec, patch, n_records = records_in(tmp)
        diffs = list(Path(tmp).rglob("*.diff"))
        check("interrupt: if it lands right after the record says exported, the diff is NOT withdrawn",
              late and n_records == 1 and patch.get("exported") is True
              and patch.get("export_status") == "exported" and len(diffs) == 1
              and diffs[0].read_text(encoding="utf-8") == patch["diff"]
              and str(diffs[0]) == patch["export_path"] and not temp_leftovers(tmp))

    # --- 5d. cleanup is limited to files this call has confirmed it created -----------------------
    with tempfile.TemporaryDirectory() as tmp:
        theirs = Path(tmp) / "not_ours.diff"
        theirs.write_text("a file this call did not create", encoding="utf-8")
        before = tree_hashes(tmp)

        def open_denied(path, mode="r", *args, **kwargs):
            raise PermissionError("denied")

        ia.open = open_denied
        try:
            ia._create_new(theirs, "new text")
            denied = "no error"
        except PermissionError:
            denied = "PermissionError"
        finally:
            del ia.open
        kept_after_denied = tree_hashes(tmp) == before
        try:
            ia._create_new(theirs, "new text")
            clash = "no error"
        except FileExistsError:
            clash = "FileExistsError"
        check("cleanup: an open() that fails (even with PermissionError) never removes a file that was already there",
              denied == "PermissionError" and kept_after_denied
              and clash == "FileExistsError" and tree_hashes(tmp) == before,
              f"({denied}, {clash})")

    source = Path(ia.__file__).read_text(encoding="utf-8")
    readme_path = HERE / "README.md"
    readme = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""
    check("wording: a collision is described as rejected without overwriting, never as impossible",
          "cannot collide" not in source and "cannot collide" not in readme
          and "without overwriting" in source and (not readme or "without overwriting any file" in readme))

    # --- 6. live runs are a local opt-in ---------------------------------------------------
    creds = {"NEBIUS_API_KEY": "k", "NEBIUS_PROJECT_ID": "p"}
    check("opt-in: credentials alone do not enable live runs", ia.is_enabled(dict(creds)) is False)
    check("opt-in: the flag alone does not enable live runs",
          ia.is_enabled({"MEGAPATCH_ENABLE_INTERACTIVE": "1"}) is False)
    check("opt-in: credentials plus the explicit flag do",
          ia.is_enabled({**creds, "MEGAPATCH_ENABLE_INTERACTIVE": "1"}) is True)
    check("engine: it does not import the UI or the model client at import time",
          "streamlit" not in sys.modules and "llm" not in sys.modules)

    print("\nCHECK-INTERACTIVE:", "ALL PASSED" if all(results) else "FAILED")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
