"""Focused check: a patch proposal for one Bandit B602 finding (propose_patch.py and the dashboard section) sends
only the target function and only with consent, is reviewed statically on a disposable copy, is never shown as
tested or accepted, is exported only after a person approves it, and never changes the project.

Offline: NVIDIA Nemotron is replaced by fake answers (nothing is sent to Nebius), pip-audit by an empty report,
and any attempt to reach another host fails at once and fails the check (no_network, here and in the child).
Bandit really runs (it only parses the code), so the pinned scanners must be installed
(pip install -r requirements-scan.txt); without them the check ends INCOMPLETE (exit code 2), not passed. Two
temporary projects, both different from target_app/: a clean one, and a synthetic service whose /backup route
passes a query-string value to a shell command (and whose /count route does too, through a pipe). Their code leaves
a marker if it ever runs. Copies of that service are edited between preparing, sending, approving and retrying, and
writes are made to fail (os.link refused) or are cut off, to check that a changed file gets no request, no diff and
no export, that an interrupted export stays pending (or stale, or a conflict) and is never shown as finished, and
that a cut-off record never stops the dashboard.

Usage: python check_patch_proposal.py   (judge_check.py runs it too)
"""
import ast
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import no_network

HERE = Path(__file__).resolve().parent
results = []
skipped_parts = []  # parts that could not run here: the check then ends INCOMPLETE (exit code 2), never ALL PASSED


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


SERVICE = '''"""Backup endpoints of a small demo service. Synthetic code written for the MegaPatch check; never run it."""
import subprocess
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)
BACKUP_SOURCE = Path(__file__).resolve().parent.parent / "shared"  # the only folder backups may read from


@app.route("/backup")
def backup():
    name = request.args.get("name", "")  # untrusted input from the query string
    code = subprocess.call("tar czf backups/latest.tgz " + name, shell=True)
    return {"exit_code": code}


@app.route("/count")
def count():
    folder = request.args.get("folder", ".")  # untrusted input from the query string
    output = subprocess.check_output("ls " + folder + " | wc -l", shell=True)
    return {"files": int(output)}
'''
GOOD = '''Here is the fix.
```python
@app.route("/backup")
def backup():
    name = request.args.get("name", "")  # untrusted input from the query string
    code = subprocess.call(["tar", "czf", "backups/latest.tgz", name])
    return {"exit_code": code}
```'''
BAD = {
    "keeps shell=True": GOOD.replace('["tar", "czf", "backups/latest.tgz", name])',
                                     '"tar czf backups/latest.tgz " + name, shell=True)'),
    "changes code outside the function": GOOD.replace('```python\n', '```python\nimport os\n\n\n'),
    "is not valid Python": GOOD.replace("def backup():", "def backup(:"),
    "drops a word of the command": GOOD.replace('"tar", "czf", ', '"tar", '),
    "re-splits the value with shlex": GOOD.replace('["tar", "czf", "backups/latest.tgz", name]',
                                                   '["tar", "czf", "backups/latest.tgz", *shlex.split(name)]'),
}
GOOD_CONFINED = '''```python
@app.route("/backup")
def backup():
    name = request.args.get("name", "")  # untrusted input from the query string
    if not name or name.startswith("-") or Path(name).is_absolute():
        return {"error": "invalid name"}, 400
    root = BACKUP_SOURCE.resolve()
    target = (root / name).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return {"error": "invalid name"}, 400
    code = subprocess.call(["tar", "czf", "backups/latest.tgz", "--", str(target)])
    return {"exit_code": code}
```'''
# Each answer omits ONE condition of the contract; the check named next to it must be the only one that fails.
OMITTED = {
    "no check for an empty value": (GOOD_CONFINED.replace("if not name or name.startswith", "if name.startswith"),
                                    "rejects_input"),
    'no check for a leading "-"': (GOOD_CONFINED.replace(' or name.startswith("-")', ""), "rejects_input"),
    "no check for an absolute path": (GOOD_CONFINED.replace(" or Path(name).is_absolute()", ""), "rejects_input"),
    "the path is not resolved": (GOOD_CONFINED.replace("(root / name).resolve()", "root / name"), "resolves"),
    "no check that it stays inside": (GOOD_CONFINED.replace("not target.is_relative_to(root) or ", ""), "inside"),
    "no check that it is a file": (GOOD_CONFINED.replace(" or not target.is_file()", ""), "is_file"),
    'no "--"': (GOOD_CONFINED.replace('"backups/latest.tgz", "--", str(target)', '"backups/latest.tgz", str(target)'),
                "after_dashdash"),
    'the raw value after "--"': (GOOD_CONFINED.replace('"--", str(target)', '"--", name'), "after_dashdash"),
}
# Rejections the review cannot prove unconditional, first and about the right names: each has the checks of the
# contract it guards fail (closed), so the answer can never be statically_reviewed, approved or exported.
GUARD = ('    if not name or name.startswith("-") or Path(name).is_absolute():\n'
         '        return {"error": "invalid name"}, 400\n')
FILE_GUARD = ('    if not target.is_relative_to(root) or not target.is_file():\n'
              '        return {"error": "invalid name"}, 400\n')
ROOT = "    root = BACKUP_SOURCE.resolve()\n"
TARGET = "    target = (root / name).resolve()\n"
CONFINED_CALL = '    code = subprocess.call(["tar", "czf", "backups/latest.tgz", "--", str(target)])\n'
INPUT = '    name = request.args.get("name", "")  # untrusted input from the query string\n'
ind = lambda text, by="    ": textwrap.indent(text, by)  # noqa: E731
UNPROVEN = {
    "a return nested under another condition": (GUARD, GUARD.replace(
        "        return", '        if request.args.get("strict"):\n            return'), {"rejects_input"}),
    "the check inside another if": (FILE_GUARD, '    if request.args.get("check"):\n' + ind(FILE_GUARD),
                                    {"inside", "is_file"}),
    "the rejection only in the else branch": (GUARD, (
        '    if name and not name.startswith("-") and not Path(name).is_absolute():\n        pass\n    else:\n'
        '        return {"error": "invalid name"}, 400\n'), {"rejects_input"}),
    "a test that also needs another condition (and)": (GUARD, GUARD.replace(
        "    if not name or name.startswith(\"-\") or Path(name).is_absolute():",
        "    if (not name or name.startswith(\"-\") or Path(name).is_absolute()) and request.args.get(\"strict\"):"),
        {"rejects_input"}),
    "a rejection raised in a try that swallows it": (GUARD, (
        '    try:\n        if not name or name.startswith("-") or Path(name).is_absolute():\n'
        '            raise LookupError\n    except LookupError:\n        pass\n'), {"rejects_input"}),
    "the check inside a for loop": (GUARD, "    for _ in range(1):\n" + ind(GUARD), {"rejects_input"}),
    "the check inside a while loop": (GUARD, "    while True:\n" + ind(GUARD) + "        break\n", {"rejects_input"}),
    "the check inside a with block": (GUARD, "    with Path(name):\n" + ind(GUARD), {"rejects_input"}),
    "the check inside a match block": (GUARD, "    match name:\n        case _:\n" + ind(GUARD, "        "),
                                       {"rejects_input"}),
    "a return only in a nested function": (FILE_GUARD, FILE_GUARD.replace(
        '        return {"error": "invalid name"}, 400\n',
        '        def deny():\n            return {"error": "invalid name"}, 400\n'), {"inside", "is_file"}),
    "the check in a nested function that is called": (GUARD, "    def check():\n" + ind(GUARD) + "    check()\n",
                                                      {"rejects_input"}),
    "the check after the command": (FILE_GUARD + CONFINED_CALL, CONFINED_CALL + FILE_GUARD, {"inside", "is_file"}),
    "the value bound again after the check (+=)": (GUARD, GUARD + '    name += ""\n', {"rejects_input", "inside"}),
    "the value bound again with :=": (GUARD, GUARD + '    (name := request.args.get("other", ""))\n',
                                      {"rejects_input", "inside"}),
    "the folder's name bound again by a loop": (ROOT, ROOT + '    for root in [Path("/")]:\n        pass\n',
                                                {"inside"}),
    "the checked path bound again by a loop": (FILE_GUARD, FILE_GUARD + '    for target in [Path("/etc/passwd")]:\n'
                                                                        "        pass\n", {"inside", "after_dashdash"}),
    "the checked path assigned inside a block": (TARGET, "    if name:\n" + ind(TARGET), {"inside", "after_dashdash"}),
    "the allowed folder assigned in the function": (INPUT, INPUT + '    BACKUP_SOURCE = Path("/")\n',
                                                    {"resolves", "inside"}),
    "a name a check relies on shadowed (Path = str)": (INPUT, INPUT + "    Path = str\n", {"rejects_input"}),
    "cyclic local aliases cannot establish the allowed folder": (
        ROOT, "    root = root_alias\n    root_alias = root\n", {"resolves", "inside", "is_file", "after_dashdash"}),
}
UNPROVEN = {name: (GOOD_CONFINED.replace(old, new), expected) for name, (old, new, expected) in UNPROVEN.items()}
# Process calls the review cannot recognize: each must fail the process check, with the reason.
AUDIT_BASE = "import subprocess\nimport os\nfrom pathlib import Path\n"
UNRECOGNIZED = {
    "from os import system": "from os import system\n" + AUDIT_BASE + "def f(n):\n    return system('ls ' + n)\n",
    "import subprocess as sp": "import subprocess as sp\n" + AUDIT_BASE + "def f(n):\n    return sp.call(['ls', n])\n",
    "getattr (dynamic call)": AUDIT_BASE + "def f(n):\n    return getattr(subprocess, 'call')(['ls', n])\n",
    "__import__": AUDIT_BASE + "def f(n):\n    return __import__('os').system('ls')\n",
    "a process function kept in a local name": AUDIT_BASE + "def f(n):\n    run = subprocess.call\n    return run(['ls', n])\n",
    "an import inside the function": AUDIT_BASE + "def f(n):\n    from os import system\n    return system('ls')\n",
    "a module-level function": AUDIT_BASE + "def helper(x):\n    pass\n\n\ndef f(n):\n    return helper(n)\n",
    "os.popen": AUDIT_BASE + "def f(n):\n    return os.popen('ls ' + n)\n",
    "subprocess.getoutput": AUDIT_BASE + "def f(n):\n    return subprocess.getoutput('ls ' + n)\n",
}
# Methods: only the ones on the explicit lists, on locals, computed values, module-level constants and request.
APP_BASE = (AUDIT_BASE + "from flask import Flask, request\n\napp = Flask(__name__)\n"
            "BACKUP_SOURCE = Path(__file__).resolve().parent / 'shared'\n")
UNRECOGNIZED_METHODS = {
    "runner.run(...) on a parameter": APP_BASE + "def f(n, runner):\n    return runner.run(['ls', n])\n",
    "runner.run(...) on a local built from a safe value": APP_BASE + "def f(n):\n    runner = Path(n)\n"
                                                                     "    return runner.run(['ls', n])\n",
    "a method on a call's result": APP_BASE + "def f(n):\n    return request.args.get('tool').run(['ls', n])\n",
    "a method on a computed path": APP_BASE + "def f(n):\n    return (Path(n) / 'x').open()\n",
    "a chain of attributes on a local": APP_BASE + "def f(n):\n    x = Path(n)\n    return x.parent.resolve()\n",
    "another method of request": APP_BASE + "def f(n):\n    return request.get_json()\n",
    "another method of a module-level constant": APP_BASE + "def f(n):\n    return BACKUP_SOURCE.unlink()\n",
}
UNRECOGNIZED.update(UNRECOGNIZED_METHODS)
RECOGNIZED = {
    "subprocess.call with a list": AUDIT_BASE + "def f(n):\n    return subprocess.call(['ls', '--', str(Path(n))])\n",
    "os.path.isabs": AUDIT_BASE + "def f(n):\n    return os.path.isabs(n)\n",
    "the example's forms": APP_BASE + '@app.route("/backup")\ndef f():\n    name = request.args.get("name", "")\n'
                           '    if not name or name.startswith("-") or Path(name).is_absolute():\n'
                           '        return {"error": "invalid name"}, 400\n    root = BACKUP_SOURCE.resolve()\n'
                           '    target = (root / name).resolve()\n'
                           '    if not target.is_relative_to(root) or not target.is_file():\n'
                           '        return {"error": "invalid name"}, 400\n'
                           '    return {"exit_code": subprocess.call(["tar", "czf", "out.tgz", "--", str(target)])}\n',
}
# The shape of the answer Nemotron gave on 2026-10-24 (a fixture here, not that answer): the list in a local
# name, errors returned without a status code, and the untrusted-input comment gone.
GOOD_LOCAL_LIST = '''```python
@app.route("/backup")
def backup():
    name = request.args.get("name", "")
    if not name or name.startswith("-") or Path(name).is_absolute():
        return {"error": "Invalid name"}
    src_path = (BACKUP_SOURCE / name).resolve()
    base_resolved = BACKUP_SOURCE.resolve()
    if not src_path.is_relative_to(base_resolved) or not src_path.is_file():
        return {"error": "Invalid name"}
    args = ["tar", "czf", "backups/latest.tgz", "--", str(src_path)]
    code = subprocess.call(args)
    return {"exit_code": code}
```'''
CALL = "    code = subprocess.call(args)\n"
BAD_LOCAL_LIST = {
    "the list is reassigned": GOOD_LOCAL_LIST.replace(CALL, '    args = ["tar", "czf", "backups/latest.tgz", "--", name]\n' + CALL),
    "the list is appended to": GOOD_LOCAL_LIST.replace(CALL, "    args.append(name)\n" + CALL),
    "an item is replaced": GOOD_LOCAL_LIST.replace(CALL, "    args[4] = name\n" + CALL),
    "the list is aliased and changed": GOOD_LOCAL_LIST.replace(CALL, "    other = args\n    other.append(name)\n" + CALL),
    "no \"--\" in the list": GOOD_LOCAL_LIST.replace('"backups/latest.tgz", "--", str(src_path)',
                                                     '"backups/latest.tgz", str(src_path)'),
    "shell=True on the call": GOOD_LOCAL_LIST.replace("subprocess.call(args)", "subprocess.call(args, shell=True)"),
    "an extra unsafe call": GOOD_LOCAL_LIST.replace(CALL, CALL + '    subprocess.call("echo " + name, shell=True)\n'),
    "an extra os.system call": GOOD_LOCAL_LIST.replace(CALL, CALL + '    os.system("echo " + name)\n'),
}
SECRET_SERVICE = SERVICE.replace('    name = request.args.get("name", "")  # untrusted input from the query string\n',
                                 '    name = request.args.get("name", "")  # untrusted input from the query string\n'
                                 '    api_token = "FAKE-token-in-function-0000"\n', 1)


def make_projects(base, markers):
    marker = "from pathlib import Path\nPath(r'{}').write_text('ran', encoding='utf-8')\n"
    projects = {
        "clean_demo": {"requirements.txt": "flask==3.1.3\n", "notes/__init__.py": marker.format(markers / "clean"),
                       "notes/store.py": "import json\n\n\ndef load(text):\n    return json.loads(text)\n"},
        "b602_demo": {"requirements.txt": "flask==3.1.3\n", "app/__init__.py": marker.format(markers / "b602"),
                      "app/backup.py": SERVICE, "shared/reports/q3.csv": "quarter,total\nq3,42\n",
                      ".env": "BACKUP_TOKEN=FAKE-dotenv-token-0000\n",
                      ".env.py": "TOKEN = 'FAKE-envpy-token-0000'\n"},
        "secret_demo": {"app/backup.py": SECRET_SERVICE},
    }
    for name, files in projects.items():
        for rel, text in files.items():
            (base / name / rel).parent.mkdir(parents=True, exist_ok=True)
            (base / name / rel).write_text(text, encoding="utf-8")
    return {name: base / name for name in projects}


def tree_hashes(folder):
    return {p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(folder).rglob("*")) if p.is_file()}


def runner(cmd, **kwargs):
    """pip-audit stands in with an empty report (no network); Bandit runs for real."""
    if len(cmd) > 2 and cmd[2] == "pip_audit":
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"dependencies": [], "fixes": []}), stderr="")
    return subprocess.run(cmd, **kwargs)


class FakeNemotron:
    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def __call__(self, messages):
        self.calls.append(messages)
        return self.answer, {"model": "fake (no request was sent)", "prompt_tokens": 0, "completion_tokens": 0}


class EditingNemotron(FakeNemotron):
    """A fake answer that comes back after the file was edited (saved by someone while the answer was awaited)."""

    def __init__(self, answer, path):
        super().__init__(answer)
        self.path = path

    def __call__(self, messages):
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write("# edited while the answer was awaited\n")
        return super().__call__(messages)


REAL_LINK = os.link


def outcome(call):
    """What call() returns, or the key of the refusal (a ProposalError) it raises."""
    try:
        return call()
    except Exception as exc:
        if hasattr(exc, "key"):
            return exc.key
        raise


def no_links(src, dst):
    """os.link on a file system without hard links (FAT32, exFAT, some network shares): simulated."""
    raise OSError(1, "simulated: hard links are not supported here")


@contextlib.contextmanager
def link_as(fake):
    """Replace os.link (how propose_patch puts a file in place) for a moment, to make one step fail."""
    os.link = fake
    try:
        yield
    finally:
        os.link = REAL_LINK


def refuse(suffix):
    """An os.link that fails for a target ending in `suffix`, as a full disk or a stopped process would."""
    def link(src, dst):
        if str(dst).endswith(suffix):
            raise OSError(5, "simulated: this step did not happen")
        return REAL_LINK(src, dst)
    return link


RENDER_CHILD = r"""
import json, sys
import no_network
no_network.install()
from streamlit import config
from streamlit.testing.v1 import AppTest
sys.argv = ["dashboard.py", "--local-scan"]
config.set_option("server.address", "127.0.0.1")
demo = r"%(demo)s"
at = AppTest.from_file("dashboard.py", default_timeout=240).run()
def view(at):
    return {
        "exceptions": [str(e.value) for e in at.exception],
        "markdown": [m.value for m in at.markdown], "warnings": [w.value for w in at.warning],
        "infos": [i.value for i in at.info], "errors": [e.value for e in at.error],
        "codes": [c.value for c in at.code], "buttons": [(b.label, b.disabled) for b in at.button],
        "checkboxes": [c.label for c in at.checkbox], "inputs": [i.label for i in at.text_input],
        "captions": [c.value for c in at.caption],
    }
out = {"first": view(at)}
at.text_input(key=[i.key for i in at.text_input if i.label.startswith("Folder of the project (only")][0]).set_value(demo).run()
at.text_input(key=[i.key for i in at.text_input if i.label.startswith("Allowed folder")][0]).set_value("BACKUP_SOURCE").run()
next(b for b in at.button if b.label == "Show what would be sent").click().run()
out["prepared"] = view(at)
next(c for c in at.checkbox if c.label.startswith("I agree to send exactly")).check().run()
out["consented"] = view(at)  # the send button is now on; it is never clicked here
next(b for b in at.button if b.label == "Approve and export the diff").click().run()
out["approved"] = view(at)
retry = [b for b in at.button if b.label == "Retry the export" and not b.disabled]
out["retried"] = view(retry[0].click().run()) if retry else {}
out["network_attempts"] = no_network.ATTEMPTS
print("PP-JSON:" + json.dumps(out))
"""


def main():
    no_network.install()
    import propose_patch as pp
    import repo_scan

    if not (importlib.util.find_spec("bandit") and importlib.util.find_spec("pip_audit")):
        print("[SKIP] the pinned scanners are not installed (pip install -r requirements-scan.txt): nothing was "
              "checked")
        print("\nCHECK-PATCH-PROPOSAL: INCOMPLETE (skipped: every case; the pinned scanners are not installed)")
        sys.exit(2)
    pins = repo_scan.pinned_scanners()

    shapes = {
        "plus": ('subprocess.call("tar czf out.tgz " + name, shell=True)', True),
        "f-string": ('subprocess.run(f"convert {src} {dst}", shell=True)', True),
        "pipe": ('subprocess.call("ls " + d + " | wc -l", shell=True)', False),
        "redirection": ('subprocess.call("echo hi > out.txt", shell=True)', False),
        "wildcard": ('subprocess.call("rm *.tmp", shell=True)', False),
        "substitution": ('subprocess.call("echo $(whoami)", shell=True)', False),
        "glued value": ('subprocess.call("tar czf out_" + name + ".tgz", shell=True)', False),
        "whole command in a variable": ("subprocess.call(cmd, shell=True)", False),
        "str.format": ('subprocess.call("ls {}".format(d), shell=True)', False),
        "program from a value": ('subprocess.call(tool + " -v", shell=True)', False),
    }
    verdicts = {}
    for name, (code, _) in shapes.items():
        try:
            pp.command_words(ast.parse(code).body[0].value)
            verdicts[name] = True
        except pp.ProposalError:
            verdicts[name] = False
    check("simple command only: words and whole values; pipes, redirections, wildcards, substitutions, glued values "
          "and commands built elsewhere are refused as not compatible",
          verdicts == {name: ok for name, (_, ok) in shapes.items()}, f"({verdicts})")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        markers = tmp / "markers"
        markers.mkdir()
        projects = make_projects(tmp / "projects", markers)
        before = {name: tree_hashes(path) for name, path in projects.items()}
        root = tmp / "analysis"
        scans = {name: repo_scan.scan(path, threat_data=False, root=root, runner=runner, installed=pins,
                                      progress=lambda step, **info: None) for name, path in projects.items()}

        clean_code = scans["clean_demo"]["findings"]["code"]
        try:
            pp.prepare(projects["clean_demo"], scans["clean_demo"], "bandit:B602:notes/store.py:1", runner=runner,
                       installed=pins)
            refused = False
        except pp.ProposalError as exc:
            refused = exc.key == "not_b602"
        check("clean project: Bandit finds nothing, so there is nothing to propose", not clean_code and refused)

        code = {f["line"]: f for f in scans["b602_demo"]["findings"]["code"] if f["test_id"] == "B602"}
        backup, count = code.get(14), code.get(21)
        try:
            pp.prepare(projects["b602_demo"], scans["b602_demo"], count["id"], runner=runner, installed=pins)
            count_refused = None
        except pp.ProposalError as exc:
            count_refused = exc
        check("B602 with a pipe (/count) is refused as not compatible, before anything is sent",
              count_refused is not None and count_refused.key == "not_simple" and "'|'" in str(count_refused))

        prepared = pp.prepare(projects["b602_demo"], scans["b602_demo"], backup["id"], runner=runner, installed=pins)
        sent = prepared["sent_text"]
        check("what would be sent: only the /backup function and Bandit's message; not the other route, the module's "
              "imports, the .env, the .env.py or any other file",
              "def backup():" in sent and "B602" in sent and "def count" not in sent and "import subprocess" not in sent
              and "FAKE-" not in sent and "Flask(__name__)" not in sent and not prepared["sensitive"]
              and prepared["messages"][1]["content"] in sent and prepared["function_lines"] == [11, 15],
              f"({len(sent)} characters)")
        check("the cost is an estimate shown before sending (input tokens, typical and maximum output, prices)",
              all(k in prepared["estimate"] for k in ("input_tokens", "typical_usd", "max_usd", "max_output_tokens")))

        model = FakeNemotron(GOOD)
        written_before = sorted(p for p in root.rglob("*") if p.is_file())
        try:
            pp.propose(projects["b602_demo"], scans["b602_demo"], prepared, consent=False, model=model, root=root)
            no_consent = False
        except pp.ProposalError as exc:
            no_consent = exc.key == "no_consent"
        check("without explicit consent nothing is sent and nothing is written",
              no_consent and not model.calls and sorted(p for p in root.rglob("*") if p.is_file()) == written_before)

        secret = pp.prepare(projects["secret_demo"], scans["secret_demo"],
                            next(f["id"] for f in scans["secret_demo"]["findings"]["code"]
                                 if f["test_id"] == "B602" and f["line"] == 15), runner=runner, installed=pins)
        try:
            pp.propose(projects["secret_demo"], scans["secret_demo"], secret, consent=True, model=model, root=root)
            blocked = False
        except pp.ProposalError as exc:
            blocked = exc.key == "sensitive" and "FAKE" not in str(exc)
        check("sensitive content in the function blocks the request (the value itself is never shown), even with "
              "consent", bool(secret["sensitive"]) and blocked and not model.calls,
              f"({[k for k, _ in secret['sensitive']]})")

        record = pp.propose(projects["b602_demo"], scans["b602_demo"], prepared, consent=True, model=model, root=root)
        checks = {c["check"]: c["passed"] for c in record["checks"]}
        diff_lines = [ln for ln in record["diff"].splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---")]
        check("one request, with exactly the text that was shown",
              len(model.calls) == 1 and model.calls[0] == prepared["messages"])
        check("a correct answer passes the static review: syntax, only the target function, no shell, no extra "
              "process, same command words, B602 gone, nothing new of medium or high severity",
              record["status"] == "statically_reviewed" and all(checks.values()) and len(checks) == 7, f"({checks})")
        check("the diff changes only the flagged line, inside /backup",
              diff_lines == ['-    code = subprocess.call("tar czf backups/latest.tgz " + name, shell=True)',
                             '+    code = subprocess.call(["tar", "czf", "backups/latest.tgz", name])'])
        check("the proposal is never presented as tested or accepted",
              record["verified_in_application"] is False and record["label"] == pp.NOT_TESTED
              and "accepted" not in record["status"])

        failed = {}
        for name, answer in BAD.items():
            bad = pp.propose(projects["b602_demo"], scans["b602_demo"], prepared, consent=True,
                             model=FakeNemotron(answer), root=root)
            try:
                pp.decide("b602_demo", bad["id"], True, repo=projects["b602_demo"], root=root)
                approvable = True
            except pp.ProposalError:
                approvable = False
            failed[name] = (bad["status"], approvable, [c["check"] for c in bad["checks"] if not c["passed"]])
        check("wrong answers fail the static review and cannot be approved",
              all(status == "failed_static_review" and not approvable and broken
                  for status, approvable, broken in failed.values()), f"({failed})")

        decision = pp.decide("b602_demo", record["id"], True, repo=projects["b602_demo"], root=root)
        exported = pp.repo_scan.project_dir("b602_demo", root) / decision["export_target"]
        try:
            pp.decide("b602_demo", record["id"], False, root=root)
            again = True
        except pp.ProposalError as exc:
            again = exc.key != "decided"
        check("approval: the decision is recorded once and only then the diff is exported (not tested in the "
              "application, decided by 'a person at this machine')",
              decision["decision"] == "approved" and exported.read_text(encoding="utf-8") == record["diff"]
              and pp.export_state("b602_demo", record["id"], decision, root) == "exported"
              and not again and decision["verified_in_application"] is False
              and decision["decided_by"] == "a person at this machine")

        rejected_record = pp.propose(projects["b602_demo"], scans["b602_demo"], prepared, consent=True,
                                     model=FakeNemotron(GOOD), root=root)
        rejected = pp.decide("b602_demo", rejected_record["id"], False, root=root)
        patches = sorted(p.name for p in (pp.repo_scan.project_dir("b602_demo", root) / "patches").iterdir())
        check("rejection: recorded, nothing exported", rejected["decision"] == "rejected"
              and rejected["export_target"] is None and patches == [f"{record['id']}.diff"]
              and pp.export_state("b602_demo", rejected_record["id"], rejected, root) is None)

        # The text is bound to the exact file it was prepared from, on a copy of the project that gets edited.
        patches_dir = pp.repo_scan.project_dir("b602_demo", root) / "patches"
        drift = tmp / "drift"
        shutil.copytree(projects["b602_demo"], drift)
        drift_file = drift / "app" / "backup.py"
        bound = pp.prepare(drift, scans["b602_demo"], backup["id"], runner=runner, installed=pins)
        with open(drift_file, "a", encoding="utf-8") as handle:  # outside the function: the text to send is the same
            handle.write("# edited after the text was prepared\n")
        model = FakeNemotron(GOOD)
        written_before = sorted(p for p in root.rglob("*") if p.is_file())
        try:
            pp.propose(drift, scans["b602_demo"], bound, consent=True, model=model, root=root)
            moved = None
        except pp.ProposalError as exc:
            moved = exc.key
        fresh = pp.prepare(drift, scans["b602_demo"], backup["id"], runner=runner, installed=pins)
        check("the prepared text is bound to the exact file (the sha256 of its bytes): a file changed after it was "
              "prepared, even outside the function, gets no request and no record",
              bound["file_sha256"]
              == hashlib.sha256((projects["b602_demo"] / "app" / "backup.py").read_bytes()).hexdigest()
              and record["file_sha256"] == bound["file_sha256"] and moved == "file_changed" and not model.calls
              and sorted(p for p in root.rglob("*") if p.is_file()) == written_before
              and fresh["sent_sha256"] == bound["sent_sha256"] and fresh["file_sha256"] != bound["file_sha256"])

        editing = EditingNemotron(GOOD, drift_file)
        late = pp.propose(drift, scans["b602_demo"], fresh, consent=True, model=editing, root=root)
        try:
            pp.decide("b602_demo", late["id"], True, repo=drift, root=root)
            late_key = None
        except pp.ProposalError as exc:
            late_key = exc.key
        check("a file changed while the answer was awaited: the answer is kept (one request), but it is not reviewed, "
              "gets no diff and cannot be approved",
              len(editing.calls) == 1 and late["status"] == "file_changed" and late["diff"] is None
              and late["checks"] == [] and late["answer"] == GOOD and late["requests_made"] == 1
              and late_key == "not_reviewable" and not (patches_dir / f"{late['id']}.diff").exists())

        current = pp.prepare(drift, scans["b602_demo"], backup["id"], runner=runner, installed=pins)
        reviewed = pp.propose(drift, scans["b602_demo"], current, consent=True, model=FakeNemotron(GOOD), root=root)
        with open(drift_file, "a", encoding="utf-8") as handle:
            handle.write("# edited before the approval\n")
        legacy = {key: value for key, value in reviewed.items() if key != "file_sha256"}
        legacy["id"] = reviewed["id"] + "-legacy"  # as recorded before the file version was kept
        pp.write_record(legacy, root)
        refusals = {}
        for label, proposal_id, folder in (("the file changed", reviewed["id"], drift),
                                           ("no folder given", reviewed["id"], None),
                                           ("a record without the file version", legacy["id"], projects["b602_demo"])):
            try:
                pp.decide("b602_demo", proposal_id, True, repo=folder, root=root)
                refusals[label] = None
            except pp.ProposalError as exc:
                refusals[label] = exc.key
        check("approval checks the file again: if it changed since the proposal, no folder is given, or the record "
              "does not hold the file version, nothing is exported or decided",
              reviewed["status"] == "statically_reviewed" and len(refusals) == 3
              and all(key == "export_changed" for key in refusals.values())
              and not any((pp.proposals_dir("b602_demo", root) / i / "decision.json").exists()
                          for i in (reviewed["id"], legacy["id"]))
              and not (patches_dir / f"{reviewed['id']}.diff").exists() and not list(patches_dir.glob(".*.partial")),
              f"({refusals})")

        # The export: the decision is saved first (complete or not at all), then the diff is put in place, never
        # replacing a file. An approval whose diff is not in place is pending: never finished, and it can be retried.
        atomic = pp.propose(projects["b602_demo"], scans["b602_demo"], prepared, consent=True,
                            model=FakeNemotron(GOOD), root=root)
        atomic_dir = pp.proposals_dir("b602_demo", root) / atomic["id"]

        def left():
            return (sorted(p.name for p in atomic_dir.iterdir()),
                    sorted(p.name for p in patches_dir.iterdir() if atomic["id"] in p.name))

        def state():
            decision_file = atomic_dir / "decision.json"
            saved = json.loads(decision_file.read_text(encoding="utf-8")) if decision_file.exists() else None
            return pp.export_state("b602_demo", atomic["id"], saved, root)

        steps = {}
        with link_as(refuse("decision.json")):
            try:
                pp.decide("b602_demo", atomic["id"], True, repo=projects["b602_demo"], root=root)
                steps["the decision cannot be saved"] = "no error"
            except pp.ProposalError as exc:
                steps["the decision cannot be saved"] = (exc.key, left(), state())
        with link_as(refuse(".diff")):
            try:
                pp.decide("b602_demo", atomic["id"], True, repo=projects["b602_demo"], root=root)
                steps["the diff cannot be put in place"] = "no error"
            except pp.ProposalError as exc:
                steps["the diff cannot be put in place"] = (exc.key, left(), state())
        decision_file = atomic_dir / "decision.json"
        decision_bytes = decision_file.read_bytes() if decision_file.exists() else None
        killed = patches_dir / f".{atomic['id']}.diff.killed.partial"  # what a process stopped mid-export leaves
        killed.write_text(atomic["diff"][:40], encoding="utf-8")

        def retry(folder):
            try:
                return pp.retry_export("b602_demo", atomic["id"], folder, root=root)
            except pp.ProposalError as exc:
                return exc.key

        steps["retry with another version of the file"] = (retry(drift), state())  # drift: not that version
        steps["retry with no folder"] = (retry(None), state())
        steps["retry"] = retry(projects["b602_demo"])
        steps["retry again"] = retry(projects["b602_demo"])
        check("export: if the decision cannot be saved, nothing is decided; if the diff cannot be put in place (or "
              "the process stops), the approval is pending, not exported; a retry checks the file version again, "
              "puts the diff in place, removes the leftovers, and is harmless when repeated",
              steps == {"the decision cannot be saved": ("decision_not_saved", (["proposal.json"], []), None),
                        "the diff cannot be put in place": ("export_pending", (["decision.json", "proposal.json"], []),
                                                            "pending"),
                        "retry with another version of the file": ("export_stale", "pending"),
                        "retry with no folder": ("export_changed", "pending"),
                        "retry": "exported", "retry again": "exported"}
              and (patches_dir / f"{atomic['id']}.diff").read_text(encoding="utf-8") == atomic["diff"]
              and left() == (["decision.json", "proposal.json"], [f"{atomic['id']}.diff"])
              and decision_file.read_bytes() == decision_bytes, f"({steps})")

        squatted = pp.propose(projects["b602_demo"], scans["b602_demo"], prepared, consent=True,
                              model=FakeNemotron(GOOD), root=root)
        foreign = "a file that is not this proposal's diff\n"

        def squat(src, dst):  # another file appears at the diff's name at the last moment
            if str(dst).endswith(".diff"):
                Path(dst).write_text(foreign, encoding="utf-8")
            return REAL_LINK(src, dst)

        race = {}
        with link_as(squat):
            try:
                pp.decide("b602_demo", squatted["id"], True, repo=projects["b602_demo"], root=root)
                race["approve"] = "no error"
            except pp.ProposalError as exc:
                race["approve"] = exc.key
        try:
            pp.retry_export("b602_demo", squatted["id"], projects["b602_demo"], root=root)
            race["retry"] = "no error"
        except pp.ProposalError as exc:
            race["retry"] = exc.key
        squatted_file = pp.proposals_dir("b602_demo", root) / squatted["id"] / "decision.json"
        squatted_decision = json.loads(squatted_file.read_text(encoding="utf-8")) if squatted_file.exists() else None
        race["state"] = pp.export_state("b602_demo", squatted["id"], squatted_decision, root)
        early = pp.propose(projects["b602_demo"], scans["b602_demo"], prepared, consent=True,
                           model=FakeNemotron(GOOD), root=root)
        (patches_dir / f"{early['id']}.diff").write_text(foreign, encoding="utf-8")
        try:
            pp.decide("b602_demo", early["id"], True, repo=projects["b602_demo"], root=root)
            race["already there"] = "no error"
        except pp.ProposalError as exc:
            race["already there"] = exc.key
        check("export: a file at the diff's name is never replaced (a hard link, on every platform): one that appears "
              "at the last moment leaves a conflict, not an export; one already there means nothing is decided",
              race == {"approve": "export_conflict", "retry": "export_conflict", "state": "conflict",
                       "already there": "exported_exists"}
              and (patches_dir / f"{squatted['id']}.diff").read_text(encoding="utf-8") == foreign
              and (patches_dir / f"{early['id']}.diff").read_text(encoding="utf-8") == foreign
              and not (pp.proposals_dir("b602_demo", root) / early["id"] / "decision.json").exists()
              and not list(patches_dir.glob(".*.partial")), f"({race})")

        # Stale: the source file changes after the approval and before the retry. Never exported, nothing to retry.
        moved = tmp / "moved"
        shutil.copytree(projects["b602_demo"], moved)
        moved_file = moved / "app" / "backup.py"
        approved_bytes = moved_file.read_bytes()
        moving = pp.propose(moved, scans["b602_demo"],
                            pp.prepare(moved, scans["b602_demo"], backup["id"], runner=runner, installed=pins),
                            consent=True, model=FakeNemotron(GOOD), root=root)
        with link_as(refuse(".diff")), contextlib.suppress(pp.ProposalError):
            pp.decide("b602_demo", moving["id"], True, repo=moved, root=root)  # stopped before the diff is in place
        moving_decision = json.loads((pp.proposals_dir("b602_demo", root) / moving["id"] / "decision.json")
                                     .read_text(encoding="utf-8"))

        def at(folder):
            return pp.export_state("b602_demo", moving["id"], moving_decision, root, record=moving, repo=folder)

        stale = {"before the change": at(moved)}
        moved_file.write_bytes(approved_bytes + b"# edited after the approval\n")
        stale["after the change"] = (at(moved), pp.source_version(moving, moved))
        stale["retry"] = outcome(lambda: pp.retry_export("b602_demo", moving["id"], moved, root=root))
        stale["no folder"] = (at(""), pp.source_version(moving, ""))
        stale["diff in place"] = pp.export_path("b602_demo", moving["id"], root).exists()
        moved_file.write_bytes(approved_bytes)  # put back byte for byte: the approved version again
        stale["put back"] = at(moved)
        check("export: a source file changed after the approval and before the retry makes the approval stale (not "
              "exported, nothing to retry); with no folder it stays pending and cannot be retried; put back byte for "
              "byte, it is pending again",
              stale == {"before the change": "pending", "after the change": ("stale", "changed"),
                        "retry": "export_stale", "no folder": ("pending", "missing"), "diff in place": False,
                        "put back": "pending"} and not list(patches_dir.glob(".*.partial")), f"({stale})")

        # proposal.json is written complete or not at all; a record that cannot be read (cut off by the earlier,
        # non-atomic write, or damaged) is skipped and listed, never changed, and loading never fails.
        kept = tmp / "analysis_records"
        model = FakeNemotron(GOOD)
        with link_as(refuse("proposal.json")):
            interrupted = outcome(lambda: pp.propose(projects["b602_demo"], scans["b602_demo"], prepared, consent=True,
                                                     model=model, root=kept))
        records_dir = pp.proposals_dir("b602_demo", kept)
        after_interruption = sorted(p.relative_to(records_dir).as_posix() for p in records_dir.rglob("*"))
        intact = pp.write_record({**record, "id": "20990101T000000000000Z-good"}, kept)
        text = (records_dir / intact["id"] / "proposal.json").read_text(encoding="utf-8")
        cut, unfinished, cut_decision = (records_dir / f"20990101T00000000000{i}Z-{n}" for i, n in
                                         ((1, "cut"), (2, "unfinished"), (3, "cutdecision")))
        for folder in (cut, unfinished, cut_decision):
            folder.mkdir()
        (cut / "proposal.json").write_text(text[:len(text) // 2], encoding="utf-8")
        (unfinished / ".proposal.json.killed.partial").write_text(text[:100], encoding="utf-8")
        (cut_decision / "proposal.json").write_text(text.replace(intact["id"], cut_decision.name), encoding="utf-8")
        (cut_decision / "decision.json").write_text('{"proposal_id": "', encoding="utf-8")
        damaged_bytes = {p: p.read_bytes() for p in records_dir.rglob("*") if p.is_file()}
        loaded = [r["id"] for r, _ in pp.load_proposals("b602_demo", kept)]
        listed = pp.damaged_records("b602_demo", kept)
        check("records: an interruption while writing proposal.json leaves no record, no folder and no temporary "
              "file, and says so (the request was made: one call); a cut-off proposal.json or decision.json is "
              "skipped and listed, never changed; loading does not fail",
              interrupted == "record_not_saved" and len(model.calls) == 1 and after_interruption == []
              and loaded == [intact["id"]]
              and listed == [f"proposals/{cut.name}/proposal.json", f"proposals/{cut_decision.name}/decision.json"]
              and all(p.read_bytes() == b for p, b in damaged_bytes.items()), f"({interrupted}, {loaded}, {listed})")

        # A file system without hard links (simulated: os.link refuses). Nothing is sent, decided or exported, and
        # every answer says so; nothing claims a success.
        bare = tmp / "analysis_no_links"
        undecided = pp.propose(projects["b602_demo"], scans["b602_demo"], prepared, consent=True,
                               model=FakeNemotron(GOOD), root=bare)
        model = FakeNemotron(GOOD)
        before_no_links = sorted(p.relative_to(bare).as_posix() for p in bare.rglob("*"))
        with link_as(no_links):
            nolinks = {
                "send": outcome(lambda: pp.propose(projects["b602_demo"], scans["b602_demo"], prepared, consent=True,
                                                   model=model, root=bare)),
                "approve": outcome(lambda: pp.decide("b602_demo", undecided["id"], True, repo=projects["b602_demo"],
                                                     root=bare)),
                "reject": outcome(lambda: pp.decide("b602_demo", undecided["id"], False, root=bare)),
            }
        check("without hard links (simulated on this file system): nothing is sent (checked before the request), and "
              "approving or rejecting saves no decision and exports nothing; each says so instead of succeeding",
              nolinks == {"send": "no_hard_links", "approve": "decision_not_saved", "reject": "decision_not_saved"}
              and not model.calls
              and sorted(p.relative_to(bare).as_posix() for p in bare.rglob("*")) == before_no_links,
              f"({nolinks})")

        # The confinement rule, on MegaPatch's reference (never on the project's code): real files and links.
        base, outside = tmp / "rule" / "shared", tmp / "rule" / "outside"
        (base / "reports").mkdir(parents=True)
        outside.mkdir(parents=True)
        (base / "reports" / "q3.csv").write_text("quarter,total\n", encoding="utf-8")
        (outside / "secret.txt").write_text("not for backups\n", encoding="utf-8")
        link = None
        try:
            os.symlink(outside, base / "link", target_is_directory=True)
            link = "a symbolic link"
        except OSError:  # Windows without the symlink privilege: a directory junction leaves the folder the same way
            if sys.platform == "win32" and subprocess.run(["cmd", "/c", "mklink", "/J", str(base / "link"), str(outside)],
                                                          capture_output=True).returncode == 0:
                link = "a directory junction"
        rejected_names = {
            "absolute POSIX path": "/etc/passwd", "absolute Windows path": "C:\\Windows\\win.ini",
            "traversal": "../outside/secret.txt", "traversal after a folder": "reports/../../outside/secret.txt",
            "option": "-rf", "long option": "--checkpoint-action=exec=sh", "empty": "", "a folder": "reports",
            "a missing file": "reports/q4.csv",
        }
        if link:
            rejected_names[f"{link} that leaves the folder"] = "link/secret.txt"
        verdicts = {what: pp.confined_path(base, name) for what, name in rejected_names.items()}
        check("confinement rule: absolute paths, traversal, options, an empty value, a folder, a missing file"
              + (f" and {link} that leaves the folder" if link else "") + " are rejected",
              all(v is None for v in verdicts.values()) and (base / "link" / "secret.txt").is_file() == bool(link),
              f"({[w for w, v in verdicts.items() if v is not None] or 'all rejected'})")
        if not link:
            skipped_parts.append("the link case of the confinement rule (no symbolic link or junction could be made)")
            print("[SKIP] no symbolic link or junction could be created here: the link case was not run")
        accepted = pp.confined_path(base, "reports/q3.csv")
        check("confinement rule: a file inside the allowed folder is accepted, as its resolved path",
              accepted == (base / "reports" / "q3.csv").resolve())

        confined = pp.prepare(projects["b602_demo"], scans["b602_demo"], backup["id"], allowed="BACKUP_SOURCE",
                              runner=runner, installed=pins)
        refusals = {}
        for name in ("NOT_DEFINED", "not a name"):
            try:
                pp.prepare(projects["b602_demo"], scans["b602_demo"], backup["id"], allowed=name, runner=runner,
                           installed=pins)
                refusals[name] = None
            except pp.ProposalError as exc:
                refusals[name] = exc.key
        check("allowed folder: the request asks for the confinement rule; a name the file does not define, or that "
              "is not a Python name, is refused",
              all(x in confined["sent_text"] for x in ('Put a "--" element', "`BACKUP_SOURCE`", "is_relative_to",
                                                         "follows", 'starts\n   with "-"', "absolute path"))
              and confined["values"] == ["name"] and "def count" not in confined["sent_text"]
              and refusals == {"NOT_DEFINED": "allowed_missing", "not a name": "allowed_name"})
        good = pp.propose(projects["b602_demo"], scans["b602_demo"], confined, consent=True,
                          model=FakeNemotron(GOOD_CONFINED), root=root)
        good_checks = {c["check"]: c["passed"] for c in good["checks"]}
        contract = ["rejects_input", "resolves", "inside", "is_file", "after_dashdash"]
        check("allowed folder: a confined answer passes 12 static checks, the five conditions of the contract each on "
              "its own, and stays 'not tested in the application'",
              good["status"] == "statically_reviewed" and all(good_checks.values()) and len(good_checks) == 12
              and all(c in good_checks for c in contract) and good["allowed_folder"] == "BACKUP_SOURCE"
              and good["verified_in_application"] is False, f"({good_checks})")
        alone = {}
        for name, (answer, expected) in OMITTED.items():
            bad = pp.propose(projects["b602_demo"], scans["b602_demo"], confined, consent=True,
                             model=FakeNemotron(answer), root=root)
            alone[name] = ([c["check"] for c in bad["checks"] if not c["passed"]], expected, bad["status"])
        check("allowed folder: each omitted condition (empty, '-', absolute, resolve, inside, file, '--', raw value) "
              "fails its own check and only that one",
              all(failed == [expected] and status == "failed_static_review"
                  for failed, expected, status in alone.values()),
              f"({ {k: v[0] for k, v in alone.items() if v[0] != [v[1]]} or 'each alone'})")
        bypass = {}
        for name, (answer, expected) in UNPROVEN.items():
            try:
                bad = pp.propose(projects["b602_demo"], scans["b602_demo"], confined, consent=True,
                                 model=FakeNemotron(answer), root=root)
            except Exception as exc:
                bypass[name] = (False, f"raised {type(exc).__name__}: {exc}", "not_checked", False)
                continue
            try:
                pp.decide("b602_demo", bad["id"], True, repo=projects["b602_demo"], root=root)
                refused = None
            except pp.ProposalError as exc:
                refused = exc.key
            failed = {c["check"] for c in bad["checks"] if not c["passed"]}
            bypass[name] = (answer != GOOD_CONFINED and "syntax" not in failed and expected <= failed,
                            bad["status"], refused, pp.export_path("b602_demo", bad["id"], root).exists()
                            or (pp.proposals_dir("b602_demo", root) / bad["id"] / "decision.json").exists())
        let_through = {k: v for k, v in bypass.items() if v != (True, "failed_static_review", "not_reviewable", False)}
        check(f"allowed folder: {len(UNPROVEN)} forms the review cannot prove (a return nested or only in an else, a "
              "test that also needs another condition, a raise caught by a try, a check in a loop, a with, a match, "
              "another if or a nested function, a check after the command, the value, the folder or the checked path "
              "bound again, a shadowed name, and cyclic local aliases) each fail closed, and none can be approved or "
              "exported",
              len(bypass) == len(UNPROVEN) == 20 and not let_through, f"({let_through or 'all refused'})")

        audited = {}
        for name, source in {**UNRECOGNIZED, **RECOGNIZED}.items():
            tree = ast.parse(source)
            function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "f")
            audited[name] = pp.process_audit(function, tree)
        check("process audit (allow-list): an unrecognized import or alias (from os import system, subprocess as sp), "
              "a dynamic call, a process function in a local name, an import inside the function, a module-level "
              "function, os.popen and subprocess.getoutput each fail, with the reason",
              all(audited[k][1] for k in UNRECOGNIZED if k not in UNRECOGNIZED_METHODS)
              and audited["subprocess.call with a list"] == (1, []) and audited["os.path.isabs"] == (0, []),
              f"({ {k: (v[1][:1] or 'NOT REJECTED') for k, v in audited.items() if k in UNRECOGNIZED} })")
        check("process audit (methods): runner.run(...) on a parameter or a local, a method on a call's result or a "
              "computed path, a chain on a local, and other methods of request or of a module-level constant each "
              "fail with the reason; the forms this example needs still pass",
              all(audited[k][1] and "not on the list of recognized" in audited[k][1][0] for k in UNRECOGNIZED_METHODS)
              and audited["the example's forms"] == (1, []),
              f"({ {k: (audited[k][1][:1] or 'NOT REJECTED') for k in UNRECOGNIZED_METHODS} })")
        sneaky = pp.propose(projects["b602_demo"], scans["b602_demo"], confined, consent=True,
                            model=FakeNemotron(GOOD_CONFINED.replace(
                                '    code = subprocess.call(["tar"',
                                '    from os import system\n    system("echo " + str(target))\n    code = subprocess.call(["tar"')),
                            root=root)
        reason = next(c["detail"] for c in sneaky["checks"] if c["check"] == "one_process")
        check("a proposal that imports and calls os.system inside the function fails the process check, which says why",
              sneaky["status"] == "failed_static_review"
              and "one_process" in [c["check"] for c in sneaky["checks"] if not c["passed"]]
              and "import inside the function" in reason and "system" in reason, f"({reason[:120]})")

        local = pp.propose(projects["b602_demo"], scans["b602_demo"], confined, consent=True,
                           model=FakeNemotron(GOOD_LOCAL_LIST), root=root)
        check("a list assigned once to a local name, unchanged before the call, is accepted like a list in the call",
              local["status"] == "statically_reviewed", f"({[c['check'] for c in local['checks'] if not c['passed']]})")
        listed = {}
        for name, answer in BAD_LOCAL_LIST.items():
            bad = pp.propose(projects["b602_demo"], scans["b602_demo"], confined, consent=True,
                             model=FakeNemotron(answer), root=root)
            listed[name] = [c["check"] for c in bad["checks"] if not c["passed"]]
        check("a local list that is reassigned, appended to, changed by item or through an alias, lacks '--', runs with "
              "shell=True, or comes with an extra unsafe call (subprocess or os.system) fails the review",
              all(listed.values()) and all("same_words" in listed[k] for k in (
                  "the list is reassigned", "the list is appended to", "an item is replaced",
                  "the list is aliased and changed"))
              and listed['no "--" in the list'] == ["after_dashdash"]
              and "no_shell" in listed["shell=True on the call"]
              and {"no_shell", "one_process"} <= set(listed["an extra unsafe call"])
              and "one_process" in listed["an extra os.system call"], f"({listed})")

        # Review a recorded answer again: a NEW record, no request, the original record untouched.
        model = FakeNemotron(GOOD_LOCAL_LIST)
        recorded = pp.propose(projects["b602_demo"], scans["b602_demo"], confined, consent=True, model=model, root=root)
        original_file = pp.proposals_dir("b602_demo", root) / recorded["id"] / "proposal.json"
        original_bytes = original_file.read_bytes()
        again = pp.rereview(projects["b602_demo"], "b602_demo", recorded["id"], runner=runner, root=root,
                            installed=pins)
        check("re-review: a new record pointing to the recorded answer (by id and hash), no request sent, the original "
              "record byte for byte unchanged, nothing approved or exported",
              again["id"] != recorded["id"] and again["review_of"] == recorded["id"] and again["requests_made"] == 0
              and len(model.calls) == 1 and original_file.read_bytes() == original_bytes
              and again["answer_sha256"] == hashlib.sha256(recorded["answer"].encode()).hexdigest()
              and again["sent_sha256"] == recorded["sent_sha256"] and "answer" not in again
              and again["file_sha256"] == recorded["file_sha256"]
              and not (original_file.parent.parent / again["id"] / "decision.json").exists()
              and again["verified_in_application"] is False and again["label"] == pp.NOT_TESTED)
        notes = " | ".join(again["observations"])
        check("observations (not checks) note the error response with HTTP 200 and the removed untrusted-input comment",
              "HTTP 200" in notes and "# untrusted input from the query string" in notes, f"({notes})")
        refused = {}
        for label, call in (("a re-review of a re-review", lambda: pp.rereview(projects["b602_demo"], "b602_demo",
                                                                              again["id"], runner=runner, root=root,
                                                                              installed=pins)),):
            try:
                call()
                refused[label] = None
            except pp.ProposalError as exc:
                refused[label] = exc.key
        changed = tmp / "changed"
        shutil.copytree(projects["b602_demo"], changed)
        (changed / "app" / "backup.py").write_text(SERVICE.replace("backups/latest.tgz", "backups/all.tgz"),
                                                   encoding="utf-8")
        try:
            pp.rereview(changed, "b602_demo", recorded["id"], runner=runner, root=root, installed=pins)
            refused["a changed file"] = None
        except pp.ProposalError as exc:
            refused["a changed file"] = exc.key
        check("re-review is refused for a re-review and for a file that changed since the request",
              refused == {"a re-review of a re-review": "rereview_original", "a changed file": "rereview_changed"},
              f"({refused})")

        stale_copy = tmp / "stale"
        shutil.copytree(projects["b602_demo"], stale_copy)
        (stale_copy / "app" / "backup.py").write_text("\n\n" + SERVICE, encoding="utf-8")
        try:
            pp.prepare(stale_copy, scans["b602_demo"], backup["id"], runner=runner, installed=pins)
            stale = False
        except pp.ProposalError as exc:
            stale = exc.key == "stale"
        check("a file that changed since the scan is refused (scan again)", stale)

        check("the projects are unchanged byte for byte and none of their code ran (markers absent)",
              {name: tree_hashes(path) for name, path in projects.items()} == before
              and not any(markers.iterdir()))
        stored = "".join(p.read_text(encoding="utf-8") for p in root.rglob("*.json"))
        check("records stay in analysis/<project>/ and hold no .env or .env.py value",
              "FAKE-dotenv-token" not in stored and "FAKE-envpy-token" not in stored
              and all(p.relative_to(root).parts[0] in projects for p in root.rglob("*") if p.is_file()))

        # The dashboard section, from a temporary copy of the project: an existing proposal, then a real
        # "Show what would be sent" (Bandit reads a copy of the file; nothing is sent), then Approve.
        copy = tmp / "project"
        copy.mkdir()
        for source in list(HERE.glob("*.py")) + [HERE / "requirements-scan.txt"]:
            shutil.copy2(source, copy / source.name)
        for name in ("data", "scans", "target_app", "reference_patch", "evidence"):
            shutil.copytree(HERE / name, copy / name, ignore=shutil.ignore_patterns("__pycache__", "run_2*"))
        shutil.copytree(root / "b602_demo" / "scans", copy / "analysis" / "b602_demo" / "scans")
        ui_record = pp.propose(projects["b602_demo"], scans["b602_demo"], confined, consent=True,
                               model=FakeNemotron(GOOD_CONFINED), root=copy / "analysis")
        # An approval whose diff never got in place, as a stopped export leaves it: it must show as pending.
        ui_pending = pp.propose(projects["b602_demo"], scans["b602_demo"], confined, consent=True,
                                model=FakeNemotron(GOOD_CONFINED), root=copy / "analysis")
        with link_as(refuse(".diff")), contextlib.suppress(pp.ProposalError):
            pp.decide("b602_demo", ui_pending["id"], True, repo=projects["b602_demo"], root=copy / "analysis")
        # An approval made from another version of the file, whose diff is not in place: with the project's folder
        # it is stale (obsolete), and there is nothing to retry.
        ui_source = tmp / "ui_source"
        shutil.copytree(projects["b602_demo"], ui_source)
        with open(ui_source / "app" / "backup.py", "a", encoding="utf-8") as handle:
            handle.write("# another version of the file\n")
        ui_stale = pp.propose(ui_source, scans["b602_demo"],
                              pp.prepare(ui_source, scans["b602_demo"], backup["id"], allowed="BACKUP_SOURCE",
                                         runner=runner, installed=pins),
                              consent=True, model=FakeNemotron(GOOD_CONFINED), root=copy / "analysis")
        with link_as(refuse(".diff")), contextlib.suppress(pp.ProposalError):
            pp.decide("b602_demo", ui_stale["id"], True, repo=ui_source, root=copy / "analysis")
        # A record cut off by an interruption (as the earlier, non-atomic write could leave): the page still loads.
        cut_ui = copy / "analysis" / "b602_demo" / "proposals" / "20990101T000000000000Z-cut"
        cut_ui.mkdir()
        (cut_ui / "proposal.json").write_text('{"id": "20990101T000000000000Z-cut", "proj', encoding="utf-8")
        child = RENDER_CHILD % {"demo": str(projects["b602_demo"])}
        # A placeholder key (not a credential) so that only the consent box decides the send button; it is never
        # clicked, so no request is made.
        env = {**os.environ, "NEBIUS_API_KEY": "placeholder-not-a-key", "PYTHONIOENCODING": "utf-8"}
        proc = subprocess.run([sys.executable, "-c", child], cwd=copy, capture_output=True, text=True, timeout=900,
                              env=env, encoding="utf-8", errors="replace")
        line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("PP-JSON:")), None)
        shown = json.loads(line.removeprefix("PP-JSON:")) if line else {}
        first, prep, done = shown.get("first", {}), shown.get("prepared", {}), shown.get("approved", {})
        consented = shown.get("consented", {})
        check("dashboard: the B602 finding offers the section, and its proposal is labeled 'not tested in the "
              "application' with the diff and Approve / Reject",
              first and not first["exceptions"]
              and any("Propose a patch with NVIDIA Nemotron" in m for m in first["markdown"])
              and any("not tested in the application" in w for w in first["warnings"])
              and any('"tar", "czf", "backups/latest.tgz", "--", str(target)' in c for c in first["codes"])
              and ("Approve and export the diff", False) in [tuple(b) for b in first["buttons"]],
              f"({(first.get('exceptions') or [proc.stderr[-300:]])[:1]})")
        check("dashboard: 'Show what would be sent' shows the exact text and the estimate; the send button stays "
              "off until the consent box is ticked",
              prep and not prep["exceptions"] and any(c == confined["sent_text"] for c in prep["codes"])
              and any(cb.startswith("I agree to send exactly the text above") for cb in prep["checkboxes"])
              and ("Send and propose a patch", True) in [tuple(b) for b in prep["buttons"]]
              and consented and ("Send and propose a patch", False) in [tuple(b) for b in consented["buttons"]])
        exported_ui = copy / "analysis" / "b602_demo" / "patches" / f"{ui_record['id']}.diff"
        check("dashboard: Approve records the decision and exports the diff, still labeled not tested",
              done and not done["exceptions"] and exported_ui.is_file()
              and any("still not tested in the application" in i for i in done["infos"]))
        retried = shown.get("retried", {})
        finished = lambda v: sum("the diff was exported to" in i for i in v["infos"])  # noqa: E731
        pending_ui = copy / "analysis" / "b602_demo" / "patches" / f"{ui_pending['id']}.diff"
        retries = lambda v: [tuple(b) for b in v["buttons"] if b[0] == "Retry the export"]  # noqa: E731
        pending_text = "Pending: approved, not exported yet"
        check("dashboard: an approval whose diff is not in place shows as pending, never as a finished approval; its "
              "retry stays off until the folder holds the approved version of the file; retrying puts the diff in "
              "place",
              first and prep and retried and not retried["exceptions"]
              and sum(pending_text in w for w in first["warnings"]) == 2 and finished(first) == 0
              and retries(first) == [("Retry the export", True)] * 2
              and any("The retry stays off until" in c for c in first["captions"])
              and retries(prep) == [("Retry the export", False)]
              and finished(done) == 1 and finished(retried) == 2 and pending_ui.is_file()
              and pending_ui.read_text(encoding="utf-8") == ui_pending["diff"]
              and not any(pending_text in w for w in retried["warnings"]),
              f"({(retried.get('exceptions') or [''])[:1]}, {retries(first) if first else ''})")
        stale_text = "Obsolete (stale): approved, not exported"
        check("dashboard: an approval whose source file changed shows as obsolete (stale), with no retry, and is not "
              "exported; a cut-off record does not stop the page and is listed as unreadable",
              prep and retried and any(stale_text in e for e in prep["errors"])
              and any(stale_text in e for e in retried["errors"])
              and not (copy / "analysis" / "b602_demo" / "patches" / f"{ui_stale['id']}.diff").exists()
              and not first["exceptions"] and any("could not be read" in w and cut_ui.name in w
                                                  for w in first["warnings"]))
        check("the projects are still unchanged after the dashboard run",
              {name: tree_hashes(path) for name, path in projects.items()} == before and not any(markers.iterdir()))
        import ui_text

        produced = {c["check"] for r in (record, good, local, sneaky) for c in r["checks"]}
        check("every check the review produces has a label in English and Spanish",
              all(ui_text.TEXT.get(f"pp_check_{c}", {}).get(lang) for c in produced for lang in ("en", "es")),
              f"({sorted(produced)})")
        texts = [f"pp_err_{key}" for key in pp.MESSAGES] + ["pp_status_file_changed", "pp_approved",
                                                            "pp_export_pending", "pp_export_stale",
                                                            "pp_export_conflict", "pp_retry_export",
                                                            "pp_retry_needs_folder", "pp_damaged"]
        check("every refusal, the file_changed status and the export states have a text in English and Spanish",
              all(ui_text.TEXT.get(key, {}).get(lang) for key in texts for lang in ("en", "es")),
              f"({[key for key in texts if not ui_text.TEXT.get(key)] or 'all present'})")

        check("no check tried to reach another host (this process and the dashboard's child)",
              not no_network.ATTEMPTS and shown.get("network_attempts") == [],
              f"({no_network.ATTEMPTS}, {shown.get('network_attempts')})")

    if not results or not all(results):
        print("\nCHECK-PATCH-PROPOSAL: FAILED")
        sys.exit(1)
    if skipped_parts:  # a part did not run: never reported as passed
        print(f"\nCHECK-PATCH-PROPOSAL: INCOMPLETE (skipped: {'; '.join(skipped_parts)})")
        sys.exit(2)
    print("\nCHECK-PATCH-PROPOSAL: ALL PASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
