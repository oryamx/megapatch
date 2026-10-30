"""Patch loop: Nemotron writes a patch, then the SAME PoC and tests judge it.

For now the candidate is NOT run, anywhere (execution_policy.py): no environment here is proven to block
outbound network, so model-written code is a proposal, "not executed and not verified". It is printed as a
diff and recorded; it is never judged, never accepted and never exported. The PoC still runs against the
bundled practice app (target_app/) to confirm the vulnerability: that is code written by hand, not by a model.

How it worked, and will work again once isolation is proven:
- Sandbox (default): model-written code runs only inside the Nebius sandbox, which holds no secrets. A human
  approves the patch the judge accepted before it is exported (the real effect).
- --local: the judge runs on this machine, so a human approves BEFORE it runs.
- --yes skips every question (development only; the evidence labels it).

If the judge rejects a patch, Nemotron gets the judge's output and tries once more
(MAX_ATTEMPTS).

Usage:
  python run_patch_loop.py [--cwe CWE-89]   generate, judge in the Nebius sandbox, ask to export
  python run_patch_loop.py --yes            same, without questions
  python run_patch_loop.py --eval-only      skip the model, judge the existing candidate
  python run_patch_loop.py --local          judge on this machine instead (no sandbox credentials needed)

In the recorded runs, the model proposed and the same PoC + tests judged each patch.
In this version the patch is not run, so nothing judges it (execution_policy.py).
megapatch.py reuses these functions.
"""
import argparse
import difflib
import re
import sys
import time
from pathlib import Path

import execution_policy as policy
from catalog import CLASSES
from judge import is_accepted, judge_local  # the acceptance rule and the local executor live in judge.py
from llm import chat

TARGET = Path("target_app")
CANDIDATES = Path("candidates")
EXPORTS = Path("out") / "patches"
MAX_ATTEMPTS = 2
LOCAL_LABEL = "THIS machine"

SYSTEM = (
    "You are a senior application security engineer. "
    "You fix vulnerabilities with the smallest safe change."
)

USER_TEMPLATE = """This Flask app has a {name} vulnerability ({cwe}) in the route {route}.
Evidence from our proof-of-concept:

{poc_output}

Current app.py:
```python
{source}
```

Return the complete fixed app.py in ONE ```python block and nothing else.
Rules: keep create_app() and ALL routes with the same JSON response shape (the
other routes must keep working exactly as before); fix only this vulnerability,
at its root cause (no blacklists or character filtering); do not add dependencies."""

REPAIR_SUFFIX = """

Your previous patch was REJECTED by the judge.

Previous patch (full app.py):
```python
{previous}
```

Judge output:
{judge_output}

Fix the problem. Return the complete corrected app.py in ONE ```python block and
nothing else, following the same rules."""


def candidate_dir(cwe):
    return CANDIDATES / cwe


def choose_judge(local):
    if local:
        return judge_local, LOCAL_LABEL
    from sandbox_judge import judge_in_sandbox  # imported here so --local needs no sandbox credentials

    return judge_in_sandbox, "the Nebius sandbox"


def confirm_vulnerability(judge, cwe):
    """Run the class's PoC against the vulnerable app. Returns (poc_exit_code, evidence).

    Exit 1 = the exploit fired (CONFIRMED), 0 = it did not, 2 = the app is broken.
    """
    poc_code, evidence, _, _ = judge(TARGET, CLASSES[cwe]["poc"], run_tests=False)
    return poc_code, evidence


def extract_code(text):
    match = re.search(r"```(?:python)?\s*\n(.*?)```", text, re.S)
    return (match.group(1) if match else text).strip() + "\n"


def generate_candidate(cwe, evidence, feedback=None):
    """Ask Nemotron for a patch. `feedback` = judge output of a rejected attempt (repair)."""
    info = CLASSES[cwe]
    source = (TARGET / "app.py").read_text(encoding="utf-8")
    prompt = USER_TEMPLATE.format(
        name=info["name"], cwe=cwe, route=info["route"], poc_output=evidence, source=source
    )
    if feedback:
        prompt += REPAIR_SUFFIX.format(
            previous=feedback["previous"], judge_output=feedback["judge_output"][-1500:]
        )
    response = chat(
        f"generate_patch:{cwe}" + (":repair" if feedback else ""),
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=6000,  # reasoning tokens count against this budget
    )
    out_dir = candidate_dir(cwe)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "app.py").write_text(
        extract_code(response.choices[0].message.content or ""), encoding="utf-8"
    )


def diff_text(cwe):
    old = (TARGET / "app.py").read_text(encoding="utf-8").splitlines(keepends=True)
    new = (candidate_dir(cwe) / "app.py").read_text(encoding="utf-8").splitlines(keepends=True)
    return "".join(difflib.unified_diff(old, new, "target_app/app.py", f"candidates/{cwe}/app.py"))


def ask(question):
    """One yes/no question to a human. Returns (answer_is_yes, seconds_waited)."""
    asked_at = time.time()
    answer = input(question)
    return answer.strip().lower() == "y", time.time() - asked_at


def patch_cycle(judge, where, cwe, evidence, auto_yes=False, generate=True, prepared=False, export_dir=None):
    """Generate, judge in the sandbox, repair once on rejection, ask a human to export.

    An approved diff goes to `export_dir` (megapatch.py passes out/patches/<run name>/; by default a new
    out/patches/run_<UTC time>/ folder), created exclusively, so no earlier export is ever replaced.

    `prepared=True` means the first candidate was already generated (in parallel).
    Returns a result dict describing the last attempt, plus the earlier ones.
    """
    cand = candidate_dir(cwe)
    sandboxed = where != LOCAL_LABEL
    max_attempts = MAX_ATTEMPTS if generate else 1
    attempts, feedback, human_wait = [], None, 0.0
    exported, export_path = False, None

    for attempt in range(1, max_attempts + 1):
        if generate and not (attempt == 1 and prepared):
            generate_candidate(cwe, evidence, feedback=feedback)
        if not (cand / "app.py").exists():
            sys.exit(f"No candidate for {cwe} yet. Run without --eval-only first.")

        diff = diff_text(cwe)
        print(f"\n=== PROPOSED PATCH, attempt {attempt} (diff) ===")
        print(diff)

        if not policy.candidates_may_run():  # in the sandbox and with --local alike
            print(f"NOT RUN: {policy.NOT_RUN} ({policy.REASON}).")
            attempts.append({"attempt": attempt, "approved": False, "accepted": False, "executed": False,
                             "diff": diff, "not_run": policy.REASON})
            break

        if not sandboxed and not auto_yes:
            # Model-written code is about to run on THIS machine: a human looks first.
            ok, waited = ask(f"Run this candidate against the PoC and tests on {where}? [y/N] ")
            human_wait += waited
            if not ok:
                print("Not run. Nothing was executed.")
                attempts.append({"attempt": attempt, "approved": False, "accepted": False, "diff": diff})
                break

        poc_code, poc_out, test_code, test_out = judge(cand, CLASSES[cwe]["poc"])
        print("\n=== JUDGE ===")
        print(poc_out)
        print(f"tests: {test_out.splitlines()[-1] if test_out else 'no output'}")
        accepted = is_accepted(poc_code, test_code)
        print("VERDICT:", "PATCH ACCEPTED (red -> green)" if accepted else "PATCH REJECTED")
        attempts.append(
            {
                "attempt": attempt, "approved": True, "accepted": accepted, "diff": diff,
                "poc_exit": poc_code, "poc_output": poc_out,
                "tests_exit": test_code, "tests_output": test_out,
            }
        )
        if accepted:
            break
        feedback = {
            "previous": (cand / "app.py").read_text(encoding="utf-8"),
            "judge_output": f"{poc_out}\n{test_out}",
        }
        if attempt < max_attempts:
            print("Rejected: asking Nemotron to repair it with the judge's output.")

    last = attempts[-1]
    if last.get("accepted"):
        if auto_yes:
            exported = True
        else:
            exported, waited = ask(
                "Export this patch, accepted by the judge (write the diff to a new folder under out/patches/)? [y/N] "
            )
            human_wait += waited
        if exported:
            folder = Path(export_dir) if export_dir else EXPORTS / time.strftime("run_%Y%m%dT%H%M%SZ", time.gmtime())
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / f"{cwe}.diff"
            with open(target, "x", encoding="utf-8") as handle:  # a run's own folder; an earlier diff is never replaced
                handle.write(last["diff"])
            export_path = str(target)
            print(f"Exported {export_path}")
        else:
            print("Not exported. The judge-accepted patch stays in the evidence only.")

    if last.get("executed") is False:
        approval = f"none ({policy.NOT_RUN}: nothing was run, so there was nothing to approve)"
    elif auto_yes:
        approval = "auto (--yes)"
    elif sandboxed:
        approval = "human, on the judge-accepted patch (the sandbox ran it automatically)"
    else:
        approval = "human, before running on this machine and before export"
    return {
        **last,
        "attempts": len(attempts),
        "attempt_history": attempts[:-1],
        "human_wait_s": human_wait,
        "approval": approval,
        "exported": exported,
        "export_path": export_path,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwe", default="CWE-89", choices=sorted(CLASSES))
    parser.add_argument("--yes", action="store_true", help="skip every question")
    parser.add_argument("--eval-only", action="store_true", help="do not call the model")
    parser.add_argument("--local", action="store_true", help="judge on this machine, not in the sandbox")
    args = parser.parse_args()

    judge, where = choose_judge(args.local)
    print(f"[executor] {where} | class: {args.cwe} ({CLASSES[args.cwe]['name']})")

    evidence = ""
    if not args.eval_only:
        poc_code, evidence = confirm_vulnerability(judge, args.cwe)
        if poc_code != 1:
            sys.exit(f"Nothing to fix: the PoC did not fire on {TARGET} (exit {poc_code}).\n{evidence}")

    result = patch_cycle(judge, where, args.cwe, evidence, auto_yes=args.yes, generate=not args.eval_only)
    sys.exit(0 if result["accepted"] and result["exported"] else 1)


if __name__ == "__main__":
    main()
