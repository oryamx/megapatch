"""Focused check: the local scan of another repository (repo_scan.py and the dashboard's "Your repository
(local)" tab) is read-only, keeps the file and line of every finding, never overwrites an analysis, never
touches the demo, and ranks without made-up numbers.

Offline: pip-audit is replaced by a fake runner that returns canned JSON and records every command, and the
threat-data download is replaced too. No network is used. Bandit really runs on the sample repository when it
is installed (it only parses the code); otherwise a canned report stands in. The sample repository has a .git
repository, a .env with a FAKE secret, two virtual environments with unsafe code, and a setup.py, a package and
a test that leave a marker file if anything ever runs or imports them.

Usage: python check_repo_scan.py   (judge_check.py runs it too)
"""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import repo_scan
from scorerisk import fingerprint

HERE = Path(__file__).resolve().parent
results = []
SECRETS = ("FAKE-env-secret-0000", "FAKE-index-token", "FAKE-hunter2", "FAKE-query-token", "FAKE-signature",
           "FAKE-fragment-token", "FAKE-userinfo-token", "FAKE-option-token", "FAKE-envpy-secret")


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


REQUIREMENTS = """# sample requirements
requests==2.25.0
PyYAML[extra]==5.3.1 ; python_version >= "3.8"
Jinja2==2.11.2 \\
    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000
flask>=2.0  # not pinned
-r requirements-dev.txt
--index-url https://user:FAKE-index-token@pypi.example.invalid/simple
private-pkg @ https://pkgs.example.invalid/p-1.0.whl?token=FAKE-query-token&sig=FAKE-signature#sha256=FAKE-fragment-token
git+https://FAKE-userinfo-token@github.com/example/repo.git#egg=repo
other-pkg>=1.0 --config-settings token=FAKE-option-token
"""
SERVER = """import subprocess

PASSWORD = "FAKE-hunter2"

def archive(name):
    return subprocess.call("tar czf out.tgz " + name, shell=True)


def compute(expression):
    return eval(expression)
"""
MARKER = "from pathlib import Path\nPath(r'{marker}').write_text('ran', encoding='utf-8')\n"


def make_repo(base):
    repo = base / "sample_repo"
    markers = [base / "SETUP_RAN", base / "PACKAGE_IMPORTED", base / "TESTS_RAN"]
    files = {
        "requirements.txt": REQUIREMENTS,
        "requirements-dev.txt": "urllib3==1.26.4\n",
        "pyproject.toml": "[project]\nname = 'sample'\n",
        "setup.py": MARKER.format(marker=markers[0]),
        "app/__init__.py": MARKER.format(marker=markers[1]),
        "app/server.py": SERVER,
        "tests/test_app.py": MARKER.format(marker=markers[2]) + "\n\ndef test_one():\n    assert 1 + 1 == 2\n",
        ".env": "SECRET=FAKE-env-secret-0000\n",
        ".env.py": "SECRET = \"FAKE-envpy-secret\"\n\n\ndef load(x):\n    return eval(x)\n",
        ".venv/pyvenv.cfg": "home = /usr/bin\n",
        ".venv/lib/vendored.py": "def run(x):\n    return eval(x)\n",
        "myenv/pyvenv.cfg": "home = /usr/bin\n",
        "myenv/lib/helper.py": "def run(x):\n    return exec(x)\n",
    }
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text, encoding="utf-8")
    git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True)  # noqa: E731
    git("init", "-q")
    git("add", "-A")
    git("-c", "user.name=check", "-c", "user.email=check@example.invalid", "commit", "-q", "-m", "sample")
    return repo, markers


def tree_hashes(folder):
    return {p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(folder).rglob("*")) if p.is_file()}


def canned_pip_audit():
    vuln = {"id": "PYSEC-2023-74", "aliases": ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"], "fix_versions": ["2.31.0"],
            "description": "Requests forwards proxy credentials."}
    return {"dependencies": [
        {"name": "requests", "version": "2.25.0", "vulns": [vuln, dict(vuln)]},  # listed twice: one finding
        {"name": "pyyaml", "version": "5.3.1", "vulns": [{"id": "PYSEC-2021-142", "aliases": ["CVE-2020-14343"],
                                                          "fix_versions": ["5.4"]}]},
        {"name": "jinja2", "version": "2.11.2", "vulns": [{"id": "GHSA-0000-no-cve", "aliases": [], "fix_versions": []}]},
        {"name": "urllib3", "version": "1.26.4", "vulns": [{"id": "PYSEC-2021-108", "aliases": ["CVE-2021-33503"],
                                                            "fix_versions": ["1.26.5"]},
                                                           {"id": "PYSEC-2099-1", "aliases": ["CVE-2099-0001"],
                                                            "fix_versions": []}]},
        {"name": "private-lib", "skip_reason": "Dependency not found on PyPI and could not be audited"},
    ], "fixes": []}


THREAT = {  # what a download would return: CVE-2021-33503 in KEV without EPSS, CVE-2099-0001 without EPSS
    "fetched_at": "2026-10-21T00:00:00+00:00", "sources": {"kev_catalog_version": "test"},
    "kev": {"CVE-2021-33503": {}},
    "epss": {"CVE-2023-32681": {"epss": 0.03, "percentile": 0.8, "date": "x"},
             "CVE-2020-14343": {"epss": 0.06, "percentile": 0.9, "date": "x"}},
    "cvss": {"CVE-2023-32681": 6.1, "CVE-2020-14343": 9.8, "CVE-2021-33503": 7.5, "CVE-2099-0001": 7.5},
    "cwe": {"CVE-2020-14343": ["CWE-20"]},
}


def canned_bandit(repo):
    server, test = str(repo / "app" / "server.py"), str(repo / "tests" / "test_app.py")
    issue = lambda f, n, tid, name, text, sev, conf, cwe: {  # noqa: E731
        "filename": f, "line_number": n, "test_id": tid, "test_name": name, "issue_text": text,
        "issue_severity": sev, "issue_confidence": conf, "issue_cwe": {"id": cwe}, "code": f"{n} secret code\n"}
    return {"errors": [], "metrics": {server: {"loc": 9}, test: {"loc": 4}, "_totals": {}}, "results": [
        issue(test, 6, "B101", "assert_used", "Use of assert detected.", "LOW", "HIGH", 703),
        issue(server, 3, "B105", "hardcoded_password_string", "Possible hardcoded password: 'FAKE-hunter2'",
              "LOW", "MEDIUM", 259),
        issue(server, 9, "B307", "blacklist", "Use of possibly insecure function - consider using ast.literal_eval.",
              "MEDIUM", "HIGH", 78),
        issue(server, 6, "B602", "subprocess_popen_with_shell_equals_true", "subprocess call with shell=True.",
              "HIGH", "HIGH", 78),
    ]}


class FakeRunner:
    """Stands in for subprocess.run: canned scanner output (or the real Bandit), and a record of every command."""

    def __init__(self, repo, real_bandit=False, fail_on=None):
        self.repo, self.real_bandit, self.fail_on, self.commands = repo, real_bandit, fail_on, []

    def __call__(self, cmd, **kwargs):
        self.commands.append(list(cmd))
        module = cmd[2] if len(cmd) > 2 and cmd[1] == "-m" else None
        if module == self.fail_on:
            raise RuntimeError("stopped half-way")
        if module == "bandit" and self.real_bandit:
            return subprocess.run(cmd, **kwargs)
        payload = canned_pip_audit() if module == "pip_audit" else canned_bandit(self.repo)
        return subprocess.CompletedProcess(cmd, 1, stdout=json.dumps(payload), stderr="")


def demo_snapshot():
    files = sorted(p for d in ("scans", "data", "evidence", "out") for p in (HERE / d).rglob("*") if p.is_file())
    return {p.relative_to(HERE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


PINNED = repo_scan.pinned_scanners()
QUIET = {"progress": lambda step, **info: None}

RENDER_CHILD = r"""
import json, os, sys
from streamlit import config
from streamlit.testing.v1 import AppTest
out = {}
for case, argv, address in (("off", ["dashboard.py"], None), ("unbound", ["dashboard.py", "--local-scan"], None),
                            ("network", ["dashboard.py", "--local-scan"], "0.0.0.0"),
                            ("loopback", ["dashboard.py", "--local-scan"], "127.0.0.1")):
    sys.argv = argv
    config.set_option("server.address", address)
    at = AppTest.from_file("dashboard.py", default_timeout=240).run()
    frames = [d.value for d in at.dataframe]
    deps = [f for f in frames if "Pinned at" in f.columns]
    code = [f for f in frames if "Level" in f.columns]
    shown = [str(v) for f in frames for c in f.columns for v in f[c].tolist()]
    shown += [e.value for kind in ("markdown", "caption", "info", "warning", "success", "error") for e in getattr(at, kind)]
    options = [str(o) for box in at.selectbox for o in box.options]
    marks = (os.environ["MP_CHECK_SCAN_ID"], "sample_repo")  # this scan's id, the analyzed folder's name
    out[case] = {
        "exceptions": [str(e.value) for e in at.exception],
        "project_selector": any(box.label == "Project" for box in at.selectbox),
        "names_shown": [x for x in shown + options if any(m in x for m in marks)] + [o for o in options if o == "sample"],
        "secrets_shown": [x for x in shown if "FAKE" in x],
        "errors": [e.value for e in at.error], "buttons": [b.label for b in at.button],
        "sidebar_errors": [e.value for e in at.sidebar.error], "sidebar_infos": [i.value for i in at.sidebar.info],
        "deps": deps[0][["Advisory", "Pinned at", "ScoreRisk", "Why here"]].values.tolist() if deps else None,
        "code": code[0][["Level", "File", "Line", "Tests"]].values.tolist() if code else None,
        "inputs": [i.label for i in at.text_input],
        "infos": [i.value for i in at.info], "successes": [s.value for s in at.success],
        "warnings": [w.value for w in at.warning],
    }
print("RS-JSON:" + json.dumps(out))
"""


def main():
    demo_before, fingerprint_before = demo_snapshot(), fingerprint()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        repo, markers = make_repo(tmp)
        repo_before = tree_hashes(repo)
        root = tmp / "analysis"

        pinned, skipped, files = repo_scan.parse_requirements(repo / "requirements.txt", repo)
        check("requirements: pinned lines keep their file and line, and -r inside the repository is followed",
              [(p["name"], p["version"], p["file"], p["line"]) for p in pinned]
              == [("requests", "2.25.0", "requirements.txt", 2), ("PyYAML", "5.3.1", "requirements.txt", 3),
                  ("Jinja2", "2.11.2", "requirements.txt", 4), ("urllib3", "1.26.4", "requirements-dev.txt", 1)]
              and files == ["requirements.txt", "requirements-dev.txt"])
        check("requirements: unpinned and option lines are listed as not audited, with every credential masked "
              "(URL user and password, query parameters, fragment, option values)",
              [(s["line"], s["reason"]) for s in skipped] == [(6, "not pinned with =="), (8, "option line, not followed"),
                                                              (9, "not pinned with =="), (10, "not pinned with =="),
                                                              (11, "not pinned with ==")]
              and not any("FAKE" in s["text"] for s in skipped)
              and [s["text"] for s in skipped[2:]] == [
                  "private-pkg @ https://pkgs.example.invalid/p-1.0.whl?token=***&sig=***#***",
                  "git+https://***@github.com/example/repo.git#***", "other-pkg>=1.0 --config-settings ***"],
              f"({[s['text'] for s in skipped]})")
        masked = [repo_scan.mask_secrets(x) for x in (
            "pkg @ https://user:FAKE-pw@host.invalid/pkg.tar.gz", "pkg @ https://host.invalid/x.whl#FAKE-fragment",
            "pkg>=1 --opt=FAKE-value", "-r https://host.invalid/r.txt?token=FAKE-r", "Flask>=2.0",
            'PyYAML>=5 ; python_version >= "3.8"')]
        check("masking: credentials in every form are replaced, ordinary requirement text is kept",
              not any("FAKE" in m for m in masked) and masked[-2:] == ["Flask>=2.0", 'PyYAML>=5 ; python_version >= "3.8"'],
              f"({masked})")

        # The local scan mode: only with --local-scan AND a server bound to a loopback address; a session that
        # Streamlit reports from another address is refused too. Checked with a stand-in for Streamlit.
        import scan_view

        class FakeStreamlit:
            def __init__(self, address, ip):
                self.address, self.context = address, type("Context", (), {"ip_address": ip})()

            def get_option(self, name):
                return self.address if name == "server.address" else None

        real_st, real_argv = scan_view.st, sys.argv
        statuses = {}
        try:
            for name, argv, address, ip in (
                    ("no argument", ["dashboard.py"], "127.0.0.1", None),
                    ("address not set", ["dashboard.py", "--local-scan"], None, None),
                    ("all interfaces", ["dashboard.py", "--local-scan"], "0.0.0.0", None),
                    ("all IPv6 interfaces", ["dashboard.py", "--local-scan"], "::", None),
                    ("a network address", ["dashboard.py", "--local-scan"], "192.0.2.10", None),
                    ("a host name", ["dashboard.py", "--local-scan"], "localhost", None),
                    ("loopback, remote session", ["dashboard.py", "--local-scan"], "127.0.0.1", "192.0.2.20"),
                    ("127.0.0.1", ["dashboard.py", "--local-scan"], "127.0.0.1", None),
                    ("::1", ["dashboard.py", "--local-scan"], "::1", None)):
                scan_view.st, sys.argv = FakeStreamlit(address, ip), argv
                statuses[name] = scan_view.local_scan_status()
        finally:
            scan_view.st, sys.argv = real_st, real_argv
        check("local scan mode: on only with --local-scan and a loopback-only server; refused for every other address "
              "and for a session reported from another machine; no environment variable turns it on",
              statuses == {"no argument": "off", "address not set": "not_loopback", "all interfaces": "not_loopback",
                           "all IPv6 interfaces": "not_loopback", "a network address": "not_loopback",
                           "a host name": "not_loopback", "loopback, remote session": "remote",
                           "127.0.0.1": "on", "::1": "on"}
              and not any(x in Path(scan_view.__file__).read_text(encoding="utf-8") for x in ("os.environ", "getenv")),
              f"({statuses})")

        try:
            repo_scan.scan(repo, root=root, runner=FakeRunner(repo), installed={"bandit": "1.0", "pip-audit": None},
                           **QUIET)
            refused = False
        except repo_scan.ScanError as exc:
            refused = exc.key == "scanners"
        check("scanners: a scan refuses versions other than the ones requirements-scan.txt pins, before writing anything",
              refused and not root.exists(), f"(pins: {PINNED})")
        try:
            repo_scan.scan(tmp, root=root, runner=FakeRunner(repo), installed=PINNED, **QUIET)
            refused = False
        except repo_scan.ScanError as exc:
            refused = exc.key == "contains_analysis"
        check("a folder that contains MegaPatch's results folder is refused (scanning it would change it)",
              refused and not root.exists())

        runner, fetched = FakeRunner(repo), []

        def fake_fetch(cves, out, progress=None, with_cwe=False):
            fetched.append((sorted(cves), Path(out), with_cwe))
            Path(out).write_text(json.dumps(THREAT), encoding="utf-8")

        first = repo_scan.scan(repo, "sample", runner=runner, fetch=fake_fetch, root=root, installed=PINNED, **QUIET)
        meta, folder = first["meta"], first["folder"]
        audit = next(c for c in runner.commands if c[2] == "pip_audit")
        bandit = next(c for c in runner.commands if c[2] == "bandit")
        check("pip-audit gets only the copy of the pinned lines (--no-deps --disable-pip -s pypi), never the repository",
              audit[audit.index("-r") + 1] == str(folder / "requirements.txt")
              and all(x in audit for x in ("--no-deps", "--disable-pip")) and audit[audit.index("-s") + 1] == "pypi"
              and str(repo) not in " ".join(audit)
              and (folder / "requirements.txt").read_text(encoding="utf-8")
              == "requests==2.25.0\nPyYAML==5.3.1\nJinja2==2.11.2\nurllib3==1.26.4\n")
        excluded = bandit[bandit.index("-x") + 1].split(",")
        check("Bandit gets the repository with .git, .venv and the custom virtual environment as exclusions",
              bandit[bandit.index("-r") + 1] == str(repo)
              and {Path(x).name for x in excluded} == {".git", ".venv", "myenv", ".env", ".env.py"})
        check("only the two scanners run, as modules of this Python: no pip install, nothing from the repository",
              sorted(c[2] for c in runner.commands) == ["bandit", "pip_audit"]
              and all(c[:2] == [sys.executable, "-m"] for c in runner.commands))
        check("nothing from the repository was run or imported (setup.py, the package and the tests leave markers)",
              not any(m.exists() for m in markers))
        check("the analyzed folder is unchanged, byte for byte (.git, .venv and .env included), and the scan says so",
              tree_hashes(repo) == repo_before and meta["repository_check"]["unchanged"]
              and meta["repository_check"]["files_compared"] == len(repo_before))
        check("what was left out is recorded: .git, .env, .venv, and a virtual environment found by its pyvenv.cfg",
              {(e["path"], e["reason"]) for e in meta["excluded"]} == {
                  (".git/", "version control"), (".venv/", "virtual environment"), ("myenv/", "virtual environment"),
                  (".env", "environment file, never read"), (".env.py", "environment file, never read")})
        written = sorted(f.relative_to(root).as_posix() for f in root.rglob("*") if f.is_file())
        scan_files = ["bandit.json", "findings.json", "pip_audit.json", "requirements.txt", "scan.json",
                      "threat_data.json"]
        check("a scan writes only its own new folder analysis/PROJECT/scans/SCAN_ID/",
              written == [f"sample/scans/{meta['id']}/{name}" for name in scan_files]
              and bool(repo_scan.ITEM_ID.fullmatch(meta["id"])))
        stored = "".join(f.read_text(encoding="utf-8") for f in root.rglob("*") if f.is_file())
        check("no secret and no local path is stored: .env is never read, Bandit's code excerpts are dropped, "
              "passwords are masked, paths are relative to the repository",
              not any(s in stored for s in SECRETS) and '"code"' not in (folder / "bandit.json").read_text(encoding="utf-8")
              and tmp.name not in stored)  # the random name of the temporary folder that holds the repository
        check("the threat data is downloaded for the CVEs found, into the scan folder (never the demo's data/)",
              fetched == [(["CVE-2020-14343", "CVE-2021-33503", "CVE-2023-32681", "CVE-2099-0001"],
                           folder / "threat_data.json", True)]
              and [e["service"] for e in meta["external"]] == ["pypi", "kev", "epss", "nvd"]
              and meta["external"][0]["count"] == 4)
        check("the scanner versions and the manifests it does not read are recorded",
              meta["scanners"] == PINNED and meta["manifests_not_read"] == ["pyproject.toml", "setup.py"]
              and any("private-lib" in n["text"] and n["reason"].startswith("pip-audit") for n in meta["not_audited"]))

        ranked = repo_scan.rank_scan(first, None)
        deps = ranked["dependencies"]
        rows = {d["advisory"]: d for d in deps}
        check("dependency findings: one per advisory, with the package and the line of the manifest that pins it",
              len(deps) == 5 and (rows["PYSEC-2023-74"]["file"], rows["PYSEC-2023-74"]["line"]) == ("requirements.txt", 2)
              and (rows["PYSEC-2021-108"]["file"], rows["PYSEC-2021-108"]["line"]) == ("requirements-dev.txt", 1))
        check("undeclared exposure stays unknown: every field None, X between 0 and 1, never read as 'not exposed'",
              ranked["unknown_fields"] == list(repo_scan.EXPOSURE_FIELDS) and ranked["X"] == [0.0, 1.0]
              and all(d["X"] == [0.0, 1.0] and d["score"][0] < d["score"][1] for d in deps))
        order = [d["advisory"] for d in deps]
        # PYSEC-2099-1 has no EPSS, but even with E = 0 its CVSS 7.5 guarantees 15.0, above PYSEC-2023-74 (13.7).
        check("dependency queue: guaranteed minimum first; missing data is a range, marked provisional, never a "
              "default value",
              order == ["PYSEC-2021-108", "PYSEC-2021-142", "PYSEC-2099-1", "PYSEC-2023-74", "GHSA-0000-no-cve"]
              and rows["PYSEC-2021-108"]["E"] == [0.9, 1.0] and rows["PYSEC-2021-142"]["position"] == "exact"
              and rows["PYSEC-2099-1"]["missing"] == ["EPSS"] and rows["PYSEC-2099-1"]["E"] == [0.0, 1.0]
              and rows["GHSA-0000-no-cve"]["missing"] == ["CVE"] and rows["GHSA-0000-no-cve"]["position"] == "provisional"
              and rows["PYSEC-2021-142"]["cwe"] == ["CWE-20"], f"({order})")
        code = ranked["code"]
        check("code queue: Bandit severity, then confidence, test code last at its level; no score is computed",
              [(c["test_id"], c["file"], c["line"]) for c in code] == [
                  ("B602", "app/server.py", 6), ("B307", "app/server.py", 9), ("B101", "tests/test_app.py", 6),
                  ("B105", "app/server.py", 3)]
              and code[2]["test_code"] and not any(k in c for c in code for k in ("score", "pre_score", "E", "S")))
        check("the 25-point problem is gone: a Bandit finding gets no ScoreRisk number and never shares the "
              "dependency queue, and the assert in a test sits below the HIGH finding",
              all("score" in d for d in deps) and not any("score" in c for c in code)
              and code[0]["severity"] == "HIGH" and code[2]["test_id"] == "B101")

        first_files = tree_hashes(folder)
        declared = repo_scan.declare_exposure("sample", {"internet_facing": True, "requires_auth": None,
                                                         "environment": "production", "sensitive_data": False}, root)
        again = repo_scan.declare_exposure("sample", {"internet_facing": True, "requires_auth": False,
                                                      "environment": "production", "sensitive_data": False}, root)
        partial = repo_scan.rank_scan(first, declared)
        full = repo_scan.rank_scan(first, repo_scan.latest_exposure("sample", root))
        check("exposure: each declaration is a new file; an undeclared field keeps a range; the latest one applies",
              len(list((root / "sample" / "exposure").glob("*.json"))) == 2 and partial["X"] == [0.6, 0.85]
              and full["X"] == [0.85, 0.85] and full["exposure_id"] == again["id"]
              and [d["advisory"] for d in full["dependencies"]] == order
              and full["dependencies"][0]["bands"] == ["Act"])
        try:
            repo_scan.declare_exposure("sample", {"internet_facing": "maybe"}, root)
            rejected = False
        except ValueError:
            rejected = True
        check("exposure: a value other than yes, no or unknown is rejected", rejected)

        second = repo_scan.scan(repo, "sample", runner=FakeRunner(repo), fetch=fake_fetch, root=root,
                                installed=PINNED, **QUIET)
        try:
            repo_scan.scan(repo, "sample", runner=FakeRunner(repo, fail_on="bandit"), fetch=fake_fetch, root=root,
                           installed=PINNED, **QUIET)
        except RuntimeError:
            pass
        listed = repo_scan.list_scans("sample", root)
        check("every scan gets its own id and folder; an earlier scan is never changed; an interrupted one is not "
              "shown as complete",
              second["meta"]["id"] != meta["id"] and tree_hashes(folder) == first_files
              and len(listed) == 3 and [done for _, _, done in listed].count(False) == 1
              and repo_scan.list_projects(root) == ["sample"])

        if importlib.util.find_spec("bandit"):
            real = repo_scan.scan(repo, "real", runner=FakeRunner(repo, real_bandit=True), root=root, installed=PINNED,
                                  threat_data=False, **QUIET)
            lines = sorted((c["test_id"], c["file"], c["line"]) for c in real["findings"]["code"])
            check("real Bandit: the real file and line of each finding; virtual environments and .env* files (a "
                  ".env.py with eval included) not analyzed; nothing run",
                  ("B602", "app/server.py", 6) in lines and ("B307", "app/server.py", 10) in lines
                  and not real["meta"]["bandit"]["excluded_files_analyzed"]
                  and not any(f.startswith((".venv", "myenv", ".env")) for _, f, _ in lines)
                  and not any(m.exists() for m in markers) and tree_hashes(repo) == repo_before, f"({lines})")
        else:
            print("[SKIP] Bandit is not installed here (pip install -r requirements-scan.txt to include it)")

        # The dashboard shows the scans, read-only without the local scan mode, from a temporary copy of the project.
        copy = tmp / "project"
        copy.mkdir()
        for source in list(HERE.glob("*.py")) + [HERE / "requirements-scan.txt"]:
            shutil.copy2(source, copy / source.name)
        for name in ("data", "scans", "target_app", "reference_patch", "evidence"):
            shutil.copytree(HERE / name, copy / name, ignore=shutil.ignore_patterns("__pycache__", "run_2*"))
        shutil.copytree(root / "sample", copy / "analysis" / "sample")
        for scan_id, _, done in listed:  # keep only the first scan: the page opens the newest complete one
            if scan_id != meta["id"]:
                shutil.rmtree(copy / "analysis" / "sample" / "scans" / scan_id)
        # As a scan saved by an earlier version could: a not-audited line stored without masking (in the copy only).
        old_meta = copy / "analysis" / "sample" / "scans" / meta["id"] / "scan.json"
        saved = json.loads(old_meta.read_text(encoding="utf-8"))
        saved["not_audited"].append({"file": "requirements.txt", "line": 12, "reason": "not pinned with ==",
                                     "text": "legacy @ https://user:FAKE-legacy-token@host.invalid/x.whl?sig=FAKE-legacy"})
        old_meta.write_text(json.dumps(saved), encoding="utf-8")
        proc = subprocess.run([sys.executable, "-c", RENDER_CHILD], cwd=copy, capture_output=True, text=True,
                              timeout=600, env={**os.environ, "MP_CHECK_SCAN_ID": meta["id"]})
        line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RS-JSON:")), None)
        shown = json.loads(line.removeprefix("RS-JSON:")) if line else {}
        off, on = shown.get("off", {}), shown.get("loopback", {})
        refused = [shown.get("unbound", {}), shown.get("network", {})]
        check("dashboard (authorized local mode): the saved analysis with both queues, file and line, the latest "
              "exposure, the folder check and the scope warning",
              not on.get("exceptions") and on.get("project_selector") and bool(on.get("names_shown"))
              and bool(on.get("deps"))
              and on["deps"][0][:3] == ["CVE-2021-33503", "requirements-dev.txt:1", "85.5 – 90.5"]
              and on["deps"][1][2] == "48.1" and "provisional" in on["deps"][2][3] and " – " in on["deps"][2][2]
              and bool(on.get("code")) and on["code"][0] == ["HIGH / HIGH", "app/server.py", "6", ""]
              and any("did not change" in s for s in on["successes"])
              and any("Scanned, not verified" in w for w in on["warnings"]),
              f"({(on.get('exceptions') or [proc.stderr[-300:]])[:1]} {(on.get('deps') or [None])[0]})")
        check("dashboard: with the local mode off or refused, no saved analysis is listed or shown (no project, no "
              "scan id, no folder name, no queue)",
              all(case and not case.get("exceptions") and not case.get("project_selector") and not case.get("names_shown")
                  and case.get("deps") is None and case.get("code") is None for case in (off, *refused)),
              f"({[c.get('names_shown') for c in (off, *refused)]})")
        check("dashboard: without the local scan mode there is no folder field (the public demo stays read-only); "
              "with it on a loopback-only server, the folder can be chosen",
              not off.get("inputs") and any("streamlit run dashboard.py --server.address 127.0.0.1 -- --local-scan" in i for i in off["infos"])
              and not on.get("exceptions") and "Folder of the project (full path)" in on.get("inputs", []))
        check("dashboard: --local-scan on a server that is not bound to 127.0.0.1 is refused: no folder field, no "
              "declaration form, and an error that says how to start it",
              len(refused) == 2 and all(
                  r and not r.get("exceptions") and not r.get("inputs") and "Save the declaration" not in r.get("buttons", [])
                  and any("--server.address 127.0.0.1 -- --local-scan" in e for e in r.get("errors", []))
                  and r.get("sidebar_errors") and not r.get("sidebar_infos") for r in refused))
        check("dashboard: no credential is shown, even from a scan saved unmasked by an earlier version",
              all(case and not case.get("secrets_shown") for case in (off, on, *refused)),
              f"({[c.get('secrets_shown') for c in (off, on, *refused)]})")

    check("the demo's scans/, data/, evidence/ and out/ and its ranking fingerprint are unchanged",
          demo_snapshot() == demo_before and fingerprint() == fingerprint_before)
    print("\nCHECK-REPO-SCAN:", "ALL PASSED" if results and all(results) else "FAILED")
    sys.exit(0 if results and all(results) else 1)


if __name__ == "__main__":
    main()
