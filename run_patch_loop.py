"""Patch loop: Nemotron writes a patch, then the SAME PoC and tests judge it.

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


def candidate_dir(cwe):
    return CANDIDATES / cwe


def run(cmd, env=None):
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def judge_local(app_dir, poc):
    """Judge on THIS machine. Same contract as judge_in_sandbox."""
    poc_code, poc_out = run([sys.executable, poc, str(app_dir)])
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
    poc_code, evidence, _, _ = judge(TARGET, CLASSES[cwe]["poc"])
    return poc_code, evidence


def extract_code(text):
    match = re.search(r"```(?:python)?\s*\n(.*?)```", text, re.S)
    return (match.group(1) if match else text).strip() + "\n"


def generate_candidate(cwe, evidence):
    info = CLASSES[cwe]
    source = (TARGET / "app.py").read_text(encoding="utf-8")
    prompt = USER_TEMPLATE.format(
        name=info["name"], cwe=cwe, route=info["route"], poc_output=evidence, source=source
    )
    response = chat(
        f"generate_patch:{cwe}",
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


def patch_cycle(judge, where, cwe, evidence, auto_yes=False, generate=True):
    """Generate (optional), show the diff, ask a human, judge. Returns a result dict."""
    if generate:
        generate_candidate(cwe, evidence)
    cand = candidate_dir(cwe)
    if not (cand / "app.py").exists():
        sys.exit(f"No candidate for {cwe} yet. Run without --eval-only first.")

    diff = diff_text(cwe)
    print("\n=== PROPOSED PATCH (diff) ===")
    print(diff)

    human_wait = 0.0
    if not auto_yes:
        # The patch is model-written code: a human looks before anything runs.
        asked_at = time.time()
        answer = input(f"Run this candidate against the PoC and tests in {where}? [y/N] ")
        human_wait = time.time() - asked_at
        if answer.strip().lower() != "y":
            print("Not run. Nothing was executed.")
            return {"approved": False, "accepted": False, "diff": diff, "human_wait_s": human_wait}

    poc_code, poc_out, test_code, test_out = judge(cand, CLASSES[cwe]["poc"])
    print("\n=== JUDGE ===")
    print(poc_out)
    print(f"tests: {test_out.splitlines()[-1] if test_out else 'no output'}")
    accepted = poc_code == 0 and test_code == 0
    print("VERDICT:", "PATCH ACCEPTED (red -> green)" if accepted else "PATCH REJECTED")
    return {
        "approved": True, "accepted": accepted, "diff": diff, "human_wait_s": human_wait,
        "poc_exit": poc_code, "poc_output": poc_out,
        "tests_exit": test_code, "tests_output": test_out,
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
