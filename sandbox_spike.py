"""Sandbox spike (gate of 12 Oct): can Nebius Sandboxes run our red -> green loop?

Run:  python sandbox_spike.py
Needs in .env: NEBIUS_API_KEY and NEBIUS_PROJECT_ID.
Each step prints PASS/FAIL and its duration (useful for the feedback form).
"""
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()  # contree_sdk reads NEBIUS_API_KEY / NEBIUS_PROJECT_ID from the environment

from contree_sdk import ContreeSync  # noqa: E402

BASE_IMAGE = "python:3.12-slim"
WORK = "/work"
CANDIDATE = Path("candidates/candidate_1/app.py")

# container path -> local path
FILES = {
    f"{WORK}/harness.py": "harness.py",
    f"{WORK}/poc_sqli.py": "poc_sqli.py",
    f"{WORK}/test_target_app.py": "test_target_app.py",
    f"{WORK}/target_app/app.py": "target_app/app.py",
}
if CANDIDATE.exists():
    FILES[f"{WORK}/candidate/app.py"] = str(CANDIDATE)

results = []


def step(name, fn):
    started = time.time()
    try:
        ok, detail = fn()
    except Exception as exc:  # the spike must report, not crash
        ok, detail = False, f"{type(exc).__name__}: {exc}"
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} ({time.time() - started:.1f}s) {detail}")
    return ok


def main():
    sdk = ContreeSync()
    state = {}

    def connect():
        sdk.images()  # lists images: proves the key and the project work
        return True, ""

    def hello():
        res = sdk.images.use(BASE_IMAGE).run(shell="python --version").wait()
        return res.exit_code == 0, (res.stdout or res.stderr).strip()

    def install_deps():
        # disposable=False keeps the result as a checkpoint we reuse for every judge run.
        res = sdk.images.use(BASE_IMAGE).run(
            shell="pip install -q flask pytest", disposable=False, timeout=300
        ).wait()
        state["env"] = res
        return res.exit_code == 0, (res.stderr or "").strip()[-200:]

    def judge(command, expect_code, expect_text=None):
        res = state["env"].run(shell=f"cd {WORK} && {command}", files=FILES, timeout=120).wait()
        out = (res.stdout or "") + (res.stderr or "")
        ok = res.exit_code == expect_code and (expect_text is None or expect_text in out)
        return ok, out.strip().splitlines()[-1] if out.strip() else f"exit={res.exit_code}"

    if not step("connect to Sandboxes", connect):
        sys.exit("Cannot connect. Check NEBIUS_API_KEY and NEBIUS_PROJECT_ID in .env")
    step(f"run a command in {BASE_IMAGE}", hello)
    if not step("pip install flask pytest (needs network)", install_deps):
        sys.exit("No dependencies in the sandbox: cannot continue.")

    step("RED   exploit vs vulnerable app", lambda: judge("python poc_sqli.py target_app", 1, "VULNERABLE"))
    if CANDIDATE.exists():
        step("GREEN exploit vs patched app", lambda: judge("python poc_sqli.py candidate", 0, "SAFE"))
        step("tests on patched app", lambda: judge("APP_DIR=candidate python -m pytest -q", 0, "passed"))
    else:
        print("[SKIP] no candidate patch yet: run run_patch_loop.py first")

    print("\nGATE 12 OCT:", "PASSED" if all(results) else "NOT PASSED (see FAIL lines)")


if __name__ == "__main__":
    main()
