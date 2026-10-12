"""Run a PoC and the tests for one app folder inside a Nebius Sandbox.

Nothing here executes on your machine: the code (possibly model-written) is
uploaded to an isolated environment, judged there, and only the output comes back.
"""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()  # contree_sdk reads NEBIUS_API_KEY / NEBIUS_PROJECT_ID from the environment

from contree_sdk import ContreeSync  # noqa: E402

from catalog import CLASSES  # noqa: E402

BASE_IMAGE = "python:3.12-slim"
WORK = "/work"
APP = "app_under_test"
SUPPORT_FILES = ["harness.py", "test_target_app.py"] + [c["poc"] for c in CLASSES.values()]


_env = None  # checkpoint with the dependencies installed, reused by every judge call


def _environment():
    global _env
    if _env is None:
        sdk = ContreeSync()
        # disposable=False keeps this state as a checkpoint that every judge run starts from.
        res = sdk.images.use(BASE_IMAGE).run(
            shell="pip install -q flask pytest", disposable=False, timeout=300
        ).wait()
        if res.exit_code != 0:
            raise RuntimeError(f"could not prepare the sandbox: {(res.stderr or '')[-300:]}")
        _env = res
    return _env


def describe_environment():
    """What the sandbox actually has installed (flask and pytest are installed unpinned),
    so a verdict can be tied to the versions that produced it."""
    env = _environment()
    res = env.run(
        shell=(
            "python -c \"import sys, importlib.metadata as m; "
            "print('python', sys.version.split()[0]); "
            "[print(p, m.version(p)) for p in ('flask', 'werkzeug', 'pytest')]\""
        ),
        timeout=60,
    ).wait()
    details = dict(line.split(" ", 1) for line in (res.stdout or "").strip().splitlines() if " " in line)
    return {"image": BASE_IMAGE, "install": "pip install flask pytest (unpinned)", **details}


def warm_up():
    """Create the dependency checkpoint once, before any parallel judging."""
    _environment()


def judge_in_sandbox(app_dir, poc, run_tests=True):
    """Return (poc_exit, poc_output, tests_exit, tests_output) for app_dir/app.py.

    With run_tests=False only the PoC runs (verification needs no regression tests).
    """
    env = _environment()
    files = {f"{WORK}/{name}": name for name in SUPPORT_FILES}
    files[f"{WORK}/{APP}/app.py"] = str(Path(app_dir) / "app.py")

    def run(command):
        res = env.run(shell=f"cd {WORK} && {command}", files=files, timeout=120).wait()
        return res.exit_code, ((res.stdout or "") + (res.stderr or "")).strip()

    poc_code, poc_out = run(f"python {poc} {APP}")
    if not run_tests:
        return poc_code, poc_out, None, ""
    test_code, test_out = run(f"APP_DIR={APP} python -m pytest -q")
    return poc_code, poc_out, test_code, test_out
