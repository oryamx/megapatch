"""Patch loop: Nemotron writes a patch, then the SAME PoC and tests judge it.

If the judge rejects a patch, Nemotron gets the judge's output and tries once more
(MAX_ATTEMPTS). A human approves every candidate before it runs.

Usage:
  python run_patch_loop.py [--cwe CWE-89]   generate a patch, show diff, ask approval, judge it in the Nebius sandbox
  python run_patch_loop.py --yes            same, without the approval question
  python run_patch_loop.py --eval-only      skip the model, judge the existing candidate
  python run_patch_loop.py --local          judge on this machine instead (no sandbox credentials needed)

The model can propose; only the PoC + tests decide ("the score proposes,
execution disposes"). megapatch.py reuses these functions.
"""
import argparse
import difflib
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from catalog import CLASSES
from llm import chat

TARGET = Path("target_app")
CANDIDATES = Path("candidates")
MAX_ATTEMPTS = 2

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


def run(cmd, env=None):
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def judge_local(app_dir, poc, run_tests=True):
    """Judge on THIS machine. Same contract as judge_in_sandbox."""
    poc_code, poc_out = run([sys.executable, poc, str(app_dir)])
    if not run_tests:
        return poc_code, poc_out, None, ""
    env = {**os.environ, "APP_DIR": str(app_dir)}
    test_code, test_out = run([sys.executable, "-m", "pytest", "-q"], env=env)
    return poc_code, poc_out, test_code, test_out


def choose_judge(local):
    if local:
        return judge_local, "THIS machine"
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


def patch_cycle(judge, where, cwe, evidence, auto_yes=False, generate=True, prepared=False):
    """Generate, show the diff, ask a human, judge; on rejection repair once.

    `prepared=True` means the first candidate was already generated (in parallel).
    Returns a result dict describing the last attempt, plus the earlier ones.
    """
    cand = candidate_dir(cwe)
    max_attempts = MAX_ATTEMPTS if generate else 1
    attempts, feedback, human_wait = [], None, 0.0

    for attempt in range(1, max_attempts + 1):
        if generate and not (attempt == 1 and prepared):
            generate_candidate(cwe, evidence, feedback=feedback)
        if not (cand / "app.py").exists():
            sys.exit(f"No candidate for {cwe} yet. Run without --eval-only first.")

        diff = diff_text(cwe)
        print(f"\n=== PROPOSED PATCH, attempt {attempt} (diff) ===")
        print(diff)

        if not auto_yes:
            # The patch is model-written code: a human looks before anything runs.
            asked_at = time.time()
            answer = input(f"Run this candidate against the PoC and tests in {where}? [y/N] ")
            human_wait += time.time() - asked_at
            if answer.strip().lower() != "y":
                print("Not run. Nothing was executed.")
                attempts.append({"attempt": attempt, "approved": False, "accepted": False, "diff": diff})
                break

        poc_code, poc_out, test_code, test_out = judge(cand, CLASSES[cwe]["poc"])
        print("\n=== JUDGE ===")
        print(poc_out)
        print(f"tests: {test_out.splitlines()[-1] if test_out else 'no output'}")
        accepted = poc_code == 0 and test_code == 0
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
    return {
        **last,
        "attempts": len(attempts),
        "attempt_history": attempts[:-1],
        "human_wait_s": human_wait,
        "approval": "auto (--yes)" if auto_yes else "human",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwe", default="CWE-89", choices=sorted(CLASSES))
    parser.add_argument("--yes", action="store_true", help="skip the approval question")
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
    sys.exit(0 if result["accepted"] else 1)


if __name__ == "__main__":
    main()
