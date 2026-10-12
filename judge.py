"""What decides whether a patch is accepted.

A verdict depends on: the PoCs, the functional tests, the harness, the vulnerable app,
catalog.py (which PoC belongs to which class), sandbox_judge.py (how and where it runs in
the Nebius sandbox) and THIS file (the local executor and the acceptance rule).
catalog.judge_fingerprint() hashes exactly those files.

Not covered by that fingerprint, because they are not files of this repository:
the packages installed inside the sandbox at run time (flask and pytest are installed
unpinned; rejudge.py records the versions it saw), the contree-sdk version, and Nebius's
platform behavior.
"""
import os
import subprocess
import sys


def run(cmd, env=None):
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def judge_local(app_dir, poc, run_tests=True):
    """Judge on THIS machine. Same contract as sandbox_judge.judge_in_sandbox."""
    poc_code, poc_out = run([sys.executable, poc, str(app_dir)])
    if not run_tests:
        return poc_code, poc_out, None, ""
    env = {**os.environ, "APP_DIR": str(app_dir)}
    test_code, test_out = run([sys.executable, "-m", "pytest", "-q"], env=env)
    return poc_code, poc_out, test_code, test_out


def is_accepted(poc_code, tests_code):
    """The acceptance rule: the same PoC no longer fires AND the functional tests pass."""
    return poc_code == 0 and tests_code == 0
