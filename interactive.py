"""Interactive analysis for the dashboard: ONE vulnerability class, run locally.

Scope, deliberately small:
  1. progress is visible stage by stage;
  2. the SAME PoC is shown before and after the patch;
  3. nothing is exported until a person approves the judge-accepted patch.

For now the patch is NOT run (execution_policy.py): model-written code runs nowhere until an environment is
proven to block outbound network. The analysis confirms the vulnerability on the practice app, asks Nemotron
for a patch, shows it as a proposal "not executed and not verified" and stops (state "proposed_not_run"):
there is no judge verdict, so nothing can be approved or exported.

It reuses the CLI's functions and does not change the judge or the CLI. There is no
Streamlit import here, so every rule below is tested without a browser
(see check_interactive.py).

What it does NOT claim: the PoCs call the app in-process through Flask's test client
(not over HTTP), and the sandbox is not shown to be offline: on 2026-10-10 one outbound
TCP connection from it to pypi.org:443 succeeded, which does not establish the full
extent of its network access.
"""
import contextlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import execution_policy as policy
from catalog import CLASSES
from judge import is_accepted

TARGET = Path("target_app")
CANDIDATES = Path("candidates")
EXPORT_ROOT = Path("out") / "patches"
EVIDENCE = Path("evidence")
MAX_ATTEMPTS = 2

NO_DECISION = "none (the judge did not accept the patch, so no export decision was asked)"
HUMAN = "human, on the judge-accepted patch (the sandbox ran it automatically; interactive dashboard)"


def is_enabled(env=None):
    """Live runs are a LOCAL opt-in: credentials AND an explicit flag. A deployed copy of the
    dashboard can therefore never expose live runs by accident."""
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass
    env = os.environ if env is None else env
    return (
        env.get("MEGAPATCH_ENABLE_INTERACTIVE") == "1"
        and bool(env.get("NEBIUS_API_KEY"))
        and bool(env.get("NEBIUS_PROJECT_ID"))
    )


def default_dependencies():
    """The real model and sandbox. Imported lazily so the engine can be tested without them."""
    import llm
    import run_patch_loop as loop
    from sandbox_judge import judge_in_sandbox, warm_up

    return SimpleNamespace(
        judge=judge_in_sandbox,
        generate=loop.generate_candidate,
        diff_of=loop.diff_text,
        read_candidate=lambda cwe: (loop.candidate_dir(cwe) / "app.py").read_text(encoding="utf-8"),
        prepare=warm_up,
        usage_lines=llm.usage_lines,
        model=llm.MODEL,
    )


class _Progress:
    """Ordered list of stages with status, start and end time; every change is announced."""

    def __init__(self, notify, now):
        self.stages, self._notify, self._now = [], notify, now

    def start(self, key, label):
        stage = {"key": key, "label": label, "status": "running", "started_at": self._now(),
                 "finished_at": None, "detail": ""}
        self.stages.append(stage)
        self._notify(self.stages)
        return stage

    def finish(self, stage, status, detail=""):
        stage.update(status=status, finished_at=self._now(), detail=detail)
        self._notify(self.stages)


def new_session_id(moment=None):
    """A session id: UTC timestamp (to the second, for sorting) plus 8 random hex characters.
    Two sessions started in the same second get different ids with overwhelming probability. It is
    not a guarantee: if a collision ever happened, decide() rejects it and overwrites no file."""
    stamp = datetime.fromtimestamp(time.time() if moment is None else moment, timezone.utc)
    return f"{stamp.strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}"


def analyze(cwe, *, judge, generate, diff_of, read_candidate, prepare=None, notify=None,
            now=time.time, max_attempts=MAX_ATTEMPTS, session_id=None):
    """Confirm, patch, judge (repairing once on rejection) and STOP before any export.

    Returns a dict whose "state" is one of: awaiting_approval, rejected_by_judge,
    not_confirmed, proposed_not_run (the patch was not run: execution_policy), error.
    It never exports and never asks anything of a person.
    Every call gets its own "session_id", which names everything that is later written."""
    info = CLASSES[cwe]
    poc = info["poc"]
    progress = _Progress(notify or (lambda stages: None), now)
    result = {
        "session_id": session_id or new_session_id(now()),
        "cwe": cwe, "poc": poc, "route": info["route"], "stages": progress.stages,
        "state": "error", "before": None, "attempts": [], "started_at": now(),
    }
    stage = None
    try:
        if prepare is not None:
            stage = progress.start("prepare", "Prepare the sandbox (dependency checkpoint)")
            prepare()
            progress.finish(stage, "done")

        stage = progress.start("confirm", f"Run {poc} on the vulnerable app, in the sandbox")
        poc_code, evidence, _, _ = judge(TARGET, poc, run_tests=False)
        result["before"] = {"poc_exit": poc_code, "poc_output": evidence}
        if poc_code != 1:
            progress.finish(stage, "failed", f"the exploit did not fire (exit {poc_code}); nothing to fix")
            result["state"] = "not_confirmed"
            return _close(result, now)
        progress.finish(stage, "done", "VULNERABLE: the exploit fired (exit 1)")

        feedback = None
        for attempt in range(1, max_attempts + 1):
            stage = progress.start(f"generate_{attempt}", f"Ask Nemotron for a patch (attempt {attempt})")
            generate(cwe, evidence, feedback)
            diff = diff_of(cwe)
            progress.finish(stage, "done", f"{len(diff.splitlines())} diff lines")

            if not policy.candidates_may_run():  # the candidate is never run: a proposal, and the analysis stops
                stage = progress.start(f"not_run_{attempt}", f"Not run: {policy.NOT_RUN}")
                result["attempts"].append({"attempt": attempt, "approved": False, "accepted": False,
                                           "executed": False, "diff": diff, "not_run": policy.REASON})
                progress.finish(stage, "done", policy.REASON)
                result["state"] = "proposed_not_run"
                return _close(result, now)

            stage = progress.start(
                f"judge_{attempt}", f"Judge it in the sandbox: the same {poc} and the functional tests"
            )
            p_code, p_out, t_code, t_out = judge(CANDIDATES / cwe, poc)
            accepted = is_accepted(p_code, t_code)
            result["attempts"].append(
                {"attempt": attempt, "approved": True, "accepted": accepted, "diff": diff,
                 "poc_exit": p_code, "poc_output": p_out, "tests_exit": t_code, "tests_output": t_out}
            )
            tests = (t_out or "").strip().splitlines()
            progress.finish(
                stage, "done" if accepted else "failed",
                f"{'ACCEPTED' if accepted else 'REJECTED'}: {poc} exit {p_code}, tests exit {t_code}"
                + (f" ({tests[-1]})" if tests else ""),
            )
            if accepted:
                result["state"] = "awaiting_approval"
                result["awaiting_since"] = now()
                stage = progress.start("approval", "Waiting for a person to approve the export")
                progress.finish(stage, "pending", "nothing is exported until you click Approve")
                stage["finished_at"] = None
                return _close(result, now)
            feedback = {"previous": read_candidate(cwe), "judge_output": f"{p_out}\n{t_out}"}

        result["state"] = "rejected_by_judge"
        return _close(result, now)
    except Exception as exc:  # the failure must be visible in the progress list, not swallowed
        if stage is not None and stage["status"] == "running":
            progress.finish(stage, "failed", f"{type(exc).__name__}: {exc}")
        result["state"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
        return _close(result, now)


def _close(result, now):
    result["finished_at"] = now()
    return result


def decide(result, approve, *, finding, ranked, stamp, model, usage, fingerprints,
           human_wait_s=0.0, executor="the Nebius sandbox",
           export_root=EXPORT_ROOT, evidence_dir=EVIDENCE):
    """Record the person's decision. Only a judge-accepted patch can be approved.

    Files are named from the session's own id (result["session_id"]); `stamp` is only the
    decision time written inside the record. Rules:
      - existing files are never replaced, and both targets are checked before anything is
        written, so a name collision is rejected without overwriting anything;
      - the record is written FIRST and says exported=false, export_status="pending". Only once the
        diff is confirmed on disk is it finalized as exported=true. If the process stops in
        between (an interrupt, a kill), the record says "pending" and never "exported", and a diff
        is never left without a record;
      - if the diff cannot be written, the record is updated to export_status="failed";
      - cleanup only ever removes files this call has confirmed it created.
    """
    if approve and result["state"] != "awaiting_approval":
        raise ValueError("only a patch accepted by the judge can be exported")

    last = result["attempts"][-1] if result["attempts"] else None
    session = result["session_id"]
    evidence_path = Path(evidence_dir) / f"interactive_run_{session}.json"
    exported_path = Path(export_root) / session / f"{result['cwe']}.diff" if approve else None
    # Refuse BEFORE writing anything: either both targets are free or nothing is written.
    for target in (evidence_path, exported_path):
        if target is not None and target.exists():
            raise FileExistsError(f"{target} already exists; refusing to overwrite it (nothing was written)")

    asked = result["state"] == "awaiting_approval"
    verdicts = {}
    if result["before"] is not None:
        verdict = "CONFIRMED" if result["before"]["poc_exit"] == 1 else "NOT_REPRODUCIBLE"
        verdicts[finding["id"]] = {"verdict": verdict, "evidence": result["before"]["poc_output"]}
    others = [r for r in ranked if r["id"] != finding["id"]]

    def build(status_text, *, exported, export_status, export_path=None, error=None):
        patches = {}
        if last:
            patch = {
                **last,
                "attempts": len(result["attempts"]),
                "attempt_history": result["attempts"][:-1],
                "human_wait_s": float(human_wait_s) if asked else 0.0,
                "approval": HUMAN if asked else NO_DECISION,
                "exported": exported,
                "export_status": export_status,
                "export_path": export_path,
                "export_target": str(exported_path) if exported_path else None,
            }
            if error:
                patch["export_error"] = error
            patches[finding["id"]] = patch
        final_order = [{"position": 1, "id": finding["id"], "scorerisk_rank": finding["rank"],
                        "pre_score": finding["pre_score"], "cvss": finding["cvss"], "status": status_text}]
        final_order += [
            {"position": i, "id": r["id"], "scorerisk_rank": r["rank"], "pre_score": r["pre_score"],
             "cvss": r["cvss"], "status": "not analyzed in this interactive session"}
            for i, r in enumerate(others, 2)
        ]
        return json.dumps(
            {
                "run_at": stamp, "executor": executor, "top_n": 1, "model": model,
                "mode": "interactive dashboard, one finding", "session_id": session,
                "inventory_fingerprint": fingerprints["inventory"],
                "fingerprint_version": fingerprints["version"],
                "judge_fingerprint": fingerprints["judge"],
                "final_order": final_order, "verdicts": verdicts, "patches": patches, "enrichment": {},
                "usage": usage,
                "duration_s": round(result["finished_at"] - result["started_at"], 1),
                "human_review_s": round(float(human_wait_s), 1) if asked else 0.0,
            },
            indent=2,
        )

    def outcome(exported, path):
        return {"exported": exported, "export_path": str(path) if path else None,
                "evidence_path": str(evidence_path), "session_id": session}

    if not approve:
        if not last:
            text = "CONFIRMED -> no patch was produced" if result["before"] else "not analyzed"
        elif result["state"] == "proposed_not_run":
            text = f"CONFIRMED -> patch proposed by Nemotron, {policy.NOT_RUN}"
        elif asked:
            text = "CONFIRMED -> patch accepted by the judge, export not approved"
        else:
            text = "CONFIRMED -> patch REJECTED by PoC/tests"
        _create_new(evidence_path, build(text, exported=False,
                                         export_status="declined" if asked else "not_applicable"))
        return outcome(False, None)

    # (1) The record exists first and does NOT claim an export.
    _create_new(evidence_path, build("CONFIRMED -> patch accepted by the judge, export pending",
                                     exported=False, export_status="pending"))
    # (2) The diff. Whatever stops the process here (even an interrupt), the record still says "pending".
    try:
        _create_new(exported_path, last["diff"])
    except BaseException as exc:
        with contextlib.suppress(Exception):  # best effort; if it fails the record simply stays "pending"
            _replace_own_file(evidence_path, build(
                "CONFIRMED -> patch accepted by the judge, export FAILED",
                exported=False, export_status="failed", error=f"{type(exc).__name__}: {exc}"))
        raise
    # (3) Only now, with the diff confirmed on disk, the record may say it was exported.
    try:
        _replace_own_file(evidence_path, build(
            "CONFIRMED -> PATCHED, same PoC now fails",
            exported=True, export_status="exported", export_path=str(exported_path)))
    except BaseException:
        # Withdraw the diff (this call created it: step 2 returned) only if the record is confirmed to
        # still say "pending". An interrupt that lands right after the replace leaves a record that
        # already says "exported"; then the diff must stay, or the record would claim a missing file.
        if _record_status(evidence_path) == "pending":
            with contextlib.suppress(OSError):
                exported_path.unlink()
        raise
    return outcome(True, exported_path)


def _record_status(path):
    """export_status of the first patch in a record on disk, or None if it cannot be read."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return next(iter(data["patches"].values()))["export_status"]
    except Exception:
        return None


def _create_new(path, text):
    """Create a file that must not exist yet. 'x' mode never overwrites: if the path exists,
    FileExistsError is raised and the existing file is left alone.

    Cleanup is limited to a file whose creation by THIS call is confirmed: an error raised by
    open() itself (a permissions problem, a missing folder, anything) removes nothing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "x", encoding="utf-8")  # returns only if THIS call created the file
    try:
        with handle:
            handle.write(text)
    except BaseException:  # includes KeyboardInterrupt: no half-written file is left behind
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def _replace_own_file(path, text):
    """Replace a file this same call created earlier, atomically: write a new file beside it, then
    os.replace. A failure leaves the original file as it was and removes only the temporary file."""
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.tmp")
    _create_new(temporary, text)  # if this returns, the temporary file is confirmed ours
    try:
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise
