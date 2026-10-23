"""MegaPatch local scan: static analysis of a Python repository on this machine, read-only.

  streamlit run dashboard.py --server.address 127.0.0.1 -- --local-scan
      the dashboard (tab "Your repository (local)"): choose the folder, declare the exposure and read the
      results. 127.0.0.1 only limits incoming connections; the scan still makes the outgoing requests below.
  python repo_scan.py PATH/TO/REPO [--project NAME] [--requirements FILE ...] [--no-threat-data]
  python repo_scan.py --show PROJECT [--scan SCAN_ID]
  python repo_scan.py --declare PROJECT internet_facing=yes requires_auth=unknown environment=production ...

Scanners, pinned in requirements-scan.txt (a scan refuses to run with other versions):
  - pip-audit reads the lines of the repository's requirements files pinned with `==`, copied into the scan
    folder (--no-deps --disable-pip: nothing is resolved or installed). It asks PyPI's JSON API about each
    pinned name and version (vulnerability service "pypi", which publishes the PyPA/OSV advisories).
  - Bandit parses the repository's .py files without importing or running them. No network.
Threat data for the CVEs found (skipped with --no-threat-data): CISA KEV (the whole catalog is downloaded), FIRST
EPSS (the CVE ids are sent) and NVD (one CVE id per request). Nothing else leaves the machine: no source code
and no file names, and nothing is sent to Streamlit, Nebius, Tavily or a model.

Excluded (from Bandit too): version-control folders (.git ...), every file and folder whose name starts with
.env (.env, .env.local, .env.py ...), every virtual environment (.venv, venv, or any folder with a pyvenv.cfg),
build and cache folders. The scan records what it left out and why.

Storage: every scan gets a new id and a new folder, analysis/PROJECT/scans/SCAN_ID/ (never reused); every
exposure declaration is a new file in analysis/PROJECT/exposure/. Nothing is overwritten. scan.json is written
last, so a scan interrupted half-way is never shown as complete. Only the folder's name and paths relative to it
are stored, never its full local path. The analyzed folder is listed (path, size, modification time) before
and after the scan, and the scan records whether anything changed. The demo's
scans/, data/ and evidence/ are never written; analysis/ is ignored by Git.

Ranking: two queues, because a dependency advisory and a Bandit finding have no common scale (rank_scan):
  - dependencies: ScoreRisk (100 * (0.5 E + 0.3 X + 0.2 S), the demo's weights). A value that is not
    available is not replaced by a default: it is an interval (EPSS unknown: E between 0 and 1; no CVSS:
    S between 0 and 1; an exposure field not declared: X between what is declared and the maximum), so the
    score is a range. The order follows the guaranteed minimum, and a row whose position could change once
    the missing value is known says so. X is the same for every finding of one repository, so it never
    changes the order inside a scan, only the score and the action band.
  - code (Bandit): Bandit's own severity, then its confidence (HIGH, MEDIUM, LOW); at the same level, code
    outside test folders first. No number is made up and these values are not CVSS.
"""
import argparse
import json
import os
import re
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

from bands import BAND_ORDER, band_for
from scorerisk import KEV_FLOOR, W_E, W_S, W_X, X_WEIGHTS

HERE = Path(__file__).resolve().parent
ANALYSIS_ROOT = HERE / "analysis"
SCANNER_PINS = HERE / "requirements-scan.txt"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}")
ITEM_ID = re.compile(r"\d{8}T\d{12}Z-[0-9a-f]{6}")
VCS_DIRS = {".git", ".hg", ".svn", ".bzr"}
VENV_DIRS = {".venv", "venv", "virtualenv", ".virtualenv"}  # any other folder with a pyvenv.cfg too
TOOL_DIRS = {".tox", ".nox", ".eggs", "node_modules", "build", "dist", "site-packages", "__pycache__",
             ".mypy_cache", ".pytest_cache", ".ruff_cache"}
MANIFESTS_NOT_READ = ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock",
                      "uv.lock", "pdm.lock", "environment.yml")
SECRET_TESTS = {"B105", "B106", "B107"}  # Bandit quotes the suspected password in its message: it is masked
LEVEL = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
EXPOSURE_FIELDS = ("internet_facing", "requires_auth", "environment", "sensitive_data")
ENVIRONMENTS = ("production", "non-production")
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*(;.*)?$")
INCLUDE = re.compile(r"^(?:-r|--requirement)(?:\s+|=)(\S+)$")
NOT_DONE = ("No code from the repository was run. The findings come from the scanners only: they were not verified "
            "by execution, and no patch was written.")
MESSAGES = {
    "not_a_folder": "{path} is not a folder",
    "contains_analysis": "MegaPatch writes its results in {root}, which is inside {repo}: scanning it would change "
                         "the folder being analyzed. Choose the project folder itself.",
    "inside_analysis": "{repo} is inside MegaPatch's own results folder",
    "bad_project": "project name: letters, digits, '-' and '_' only, starting with a letter or digit (max 40)",
    "scanners": "the scanners are not the pinned versions ({wrong}); install them with: "
                "pip install -r requirements-scan.txt",
    "requirements_file": "{file} is not a file inside the repository",
    "tool_failed": "{tool} did not produce a result: {detail}",
    "no_project": "no scan of project {project} yet",
}


class ScanError(Exception):
    """A problem the person can fix; `key` and `values` let the dashboard say it in its language."""

    def __init__(self, key, **values):
        self.key, self.values = key, values
        super().__init__(MESSAGES[key].format(**values))


def canon(name):
    """A package name as pip and pip-audit compare it."""
    return re.sub(r"[-_.]+", "-", name).lower()


def new_id():
    """A UTC time to the microsecond plus random characters: sorts by time, and is never reused."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(3)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def project_name_for(repo):
    return re.sub(r"[^A-Za-z0-9_-]+", "-", Path(repo).name).strip("-_")[:40] or "project"


def project_dir(project, root=None):
    if not NAME.fullmatch(project or ""):
        raise ScanError("bad_project")
    return Path(root or ANALYSIS_ROOT) / project


def mask_secrets(text):
    """What a requirement line can carry as a credential is never stored or shown: the user and password of a URL
    (https://user:token@host), the values of its query parameters (?token=...&sig=...), its fragment (#...) and
    the value of an option (--option=value, --option value). Comments are already removed, so a '#' left in the
    text belongs to a URL."""
    text = re.sub(r"(//)[^/@\s]+@", r"\1***@", text)
    text = re.sub(r"([?&;][^=&;#\s]+=)[^&;#\s]*", r"\1***", text)
    text = re.sub(r"#\S*", "#***", text)
    return re.sub(r"(?<!\S)(--?[A-Za-z][\w-]*)(=|\s+)(?!-)\S+", r"\1\2***", text)


# ---------- scanners: pinned versions ----------

def pinned_scanners():
    pins = {}
    for line in SCANNER_PINS.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)==(\S+)$", line.strip())
        if match:
            pins[canon(match.group(1))] = match.group(2)
    return pins


def installed_scanners():
    found = {}
    for name in pinned_scanners():
        try:
            found[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            found[name] = None
    return found


def check_scanners(installed):
    wrong = [f"{name} {installed.get(name) or 'not installed'}, needs {version}"
             for name, version in pinned_scanners().items() if installed.get(name) != version]
    if wrong:
        raise ScanError("scanners", wrong="; ".join(wrong))


# ---------- the analyzed folder ----------

def exclusion_reason(path, name):
    if name in VCS_DIRS:
        return "version control"
    if name.startswith(".env"):
        return "environment folder (may hold secrets)"
    if name in VENV_DIRS or (path / "pyvenv.cfg").is_file():
        return "virtual environment"
    if name in TOOL_DIRS or name.endswith(".egg-info"):
        return "build or cache folder"
    return None


def survey(repo):
    """Every file under `repo` with its size and modification time (compared after the scan to show that
    nothing changed, excluded folders included), and what the scan leaves out, with the reason."""
    listing, excluded, skipped_roots = {}, [], []
    for current, dirs, files in os.walk(repo):
        here = Path(current)
        rel = here.relative_to(repo)
        inside_excluded = any(here == s or s in here.parents for s in skipped_roots)
        if not inside_excluded:
            for name in sorted(dirs):
                reason = exclusion_reason(here / name, name)
                if reason:
                    skipped_roots.append(here / name)
                    excluded.append({"path": (rel / name).as_posix() + "/", "reason": reason})
        for name in files:
            path = here / name
            try:
                info = path.lstat()
            except OSError:
                continue
            listing[(rel / name).as_posix()] = [info.st_size, info.st_mtime_ns]
            if not inside_excluded and name.startswith(".env"):
                excluded.append({"path": (rel / name).as_posix(), "reason": "environment file, never read"})
    return listing, excluded


def is_test_path(where):
    parts = where.split("/")
    name = parts[-1]
    return (any(p in ("tests", "test", "testing") for p in parts[:-1]) or name.startswith("test_")
            or name.endswith("_test.py") or name == "conftest.py")


# ---------- requirements ----------

def find_requirements(repo):
    found = sorted((p for p in repo.glob("requirements*.txt") if p.is_file()),
                   key=lambda p: (p.name != "requirements.txt", p.name))  # the main file first
    if (repo / "requirements").is_dir():
        found += sorted(p for p in (repo / "requirements").glob("*.txt") if p.is_file())
    return found


def parse_requirements(path, repo, seen=None):
    """Pinned requirements (name==version) with the file and line that pin them. `-r FILE` inside the
    repository is followed once; anything else is listed as not audited, with the reason (pip-audit checks
    exact versions only, and nothing is resolved or installed)."""
    seen = set() if seen is None else seen
    path, repo = Path(path).resolve(), Path(repo).resolve()
    if path in seen:
        return [], [], []
    seen.add(path)
    shown = path.relative_to(repo).as_posix()
    pinned, skipped, files = [], [], [shown]
    for number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        text = re.split(r"\s#", raw, maxsplit=1)[0].strip()
        if text.endswith("\\"):
            text = text[:-1].strip()
        if not text or text.startswith("#") or text.startswith("--hash"):
            continue
        include = INCLUDE.match(text)
        if include:
            target = (path.parent / include.group(1)).resolve()
            if target.is_file() and target.is_relative_to(repo):
                more = parse_requirements(target, repo, seen)
                pinned += more[0]
                skipped += more[1]
                files += more[2]
            else:
                skipped.append({"file": shown, "line": number, "text": mask_secrets(text),
                                "reason": "included file missing or outside the repository"})
            continue
        if text.startswith("-"):  # options such as --index-url may carry a token: only the option name is kept
            skipped.append({"file": shown, "line": number, "text": text.split()[0].split("=")[0],
                            "reason": "option line, not followed"})
            continue
        match = PIN.match(text)
        if match:
            pinned.append({"name": match.group(1), "version": match.group(3), "file": shown, "line": number})
        else:
            skipped.append({"file": shown, "line": number, "text": mask_secrets(text), "reason": "not pinned with =="})
    return pinned, skipped, files


def merge_pins(lists):
    """One pin per package across requirements files; a second, different version is skipped, not guessed."""
    chosen, skipped = {}, []
    for pins in lists:
        for pin in pins:
            key = canon(pin["name"])
            if key not in chosen:
                chosen[key] = pin
            elif chosen[key]["version"] != pin["version"]:
                skipped.append({"file": pin["file"], "line": pin["line"], "text": f"{pin['name']}=={pin['version']}",
                                "reason": f"conflicts with {chosen[key]['file']}:{chosen[key]['line']}"})
    return list(chosen.values()), skipped


# ---------- running the scanners ----------

def run_tool(runner, module, args):
    return runner([sys.executable, "-m", module, *args], capture_output=True, text=True)


def json_output(proc, tool):
    try:
        return json.loads(proc.stdout)
    except (TypeError, ValueError):
        raise ScanError("tool_failed", tool=tool, detail=((proc.stderr or proc.stdout or "")[-600:]).strip())


def run_pip_audit(runner, folder, pinned):
    """pip-audit on the copy of the pinned lines only: --no-deps and --disable-pip, so nothing is resolved or
    installed; the PyPI service is named explicitly."""
    copy = folder / "requirements.txt"  # name==version only: nothing else from the repository
    copy.write_text("".join(f"{x['name']}=={x['version']}\n" for x in pinned), encoding="utf-8")
    if not pinned:
        audit = {"dependencies": [], "fixes": []}
    else:
        proc = run_tool(runner, "pip_audit", ["-r", str(copy), "--no-deps", "--disable-pip", "-s", "pypi",
                                              "--progress-spinner", "off", "-f", "json"])
        audit = json_output(proc, "pip-audit")
    (folder / "pip_audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    return audit


def run_bandit(runner, folder, repo, excluded):
    """Bandit parses the .py files; it does not import or run them. Everything the survey left out is passed as an
    absolute path (Bandit leaves out every file whose path contains one): each folder, and each `.env*` file, so a
    `.env.py` is not parsed either. What is kept has paths relative to the repository (no local folder names), no
    code excerpts, and the value of a suspected hardcoded password masked."""
    args = ["-r", str(repo), "-f", "json", "-q"]
    left_out = [str(repo / e["path"].rstrip("/")) + (os.sep if e["path"].endswith("/") else "") for e in excluded]
    if left_out:
        args += ["-x", ",".join(left_out)]
    report = json_output(run_tool(runner, "bandit", args), "Bandit")
    for result in report.get("results", []):
        result.pop("code", None)
        result["filename"] = relative(result["filename"], repo)
        if result.get("test_id") in SECRET_TESTS:
            result["issue_text"] = re.sub(r"'[^']*'|\"[^\"]*\"", "'***'", result.get("issue_text", ""))
    for error in report.get("errors", []):
        error["filename"] = relative(error.get("filename", ""), repo)
    report["metrics"] = {k if k == "_totals" else relative(k, repo): v for k, v in report.get("metrics", {}).items()}
    (folder / "bandit.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def cve_of(vuln):
    ids = [vuln["id"], *vuln.get("aliases", [])]
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    return cves[0] if cves else None


def relative(filename, repo):
    """A path inside the repository, relative to it; anything else is reduced to its file name."""
    try:
        return Path(filename).resolve().relative_to(repo).as_posix()
    except ValueError:
        return Path(filename).name


def build_findings(audit, report, pinned, repo):
    """Both scanners' findings, each with the file and line it comes from: the requirement line that pins the
    package, or the line Bandit flagged."""
    pins = {canon(x["name"]): x for x in pinned}
    dependencies, seen = [], set()
    for dep in audit.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            key = (canon(dep["name"]), vuln["id"])
            if key in seen:  # pip-audit may list an advisory more than once
                continue
            seen.add(key)
            pin = pins.get(canon(dep["name"]), {})
            summary = (vuln.get("description") or "").strip().split("\n")[0]
            summary = (summary[:297] + "...") if len(summary) > 300 else (summary or None)
            dependencies.append({
                "id": f"{canon(dep['name'])}:{vuln['id']}", "package": dep["name"], "version": dep.get("version"),
                "advisory": vuln["id"], "aliases": sorted(vuln.get("aliases", [])), "cve": cve_of(vuln),
                "fix_versions": vuln.get("fix_versions", []), "summary": summary,
                "file": pin.get("file"), "line": pin.get("line"),
            })
    code, used = [], {}
    for result in report.get("results", []):
        where = result["filename"]  # already relative to the repository (run_bandit)
        base = f"bandit:{result['test_id']}:{where}:{result['line_number']}"
        used[base] = used.get(base, 0) + 1
        cwe = (result.get("issue_cwe") or {}).get("id")
        code.append({
            "id": base if used[base] == 1 else f"{base}#{used[base]}", "test_id": result["test_id"],
            "test_name": result["test_name"], "message": result["issue_text"],
            "severity": result["issue_severity"], "confidence": result["issue_confidence"],
            "cwe": f"CWE-{cwe}" if cwe else None, "file": where, "line": result["line_number"],
            "test_code": is_test_path(where), "more_info": result.get("more_info"),
        })
    return {"dependencies": dependencies, "code": code}


def no_threat_data():
    return {"fetched_at": None, "downloaded": False, "sources": {}, "kev": {}, "epss": {}, "cvss": {}, "cwe": {}}


def print_step(step, **info):
    texts = {
        "survey": "Listing the folder (exclusions; size and time of every file) ...",
        "requirements": "Requirements files: {n}",
        "pip_audit": "pip-audit: {n} pinned packages ...",
        "bandit": "Bandit: parsing the Python files ...",
        "threat": "Threat data for {n} CVEs (KEV, EPSS, NVD) ...",
        "threat_kev": "  KEV catalog ...",
        "threat_epss": "  EPSS ...",
        "threat_nvd": "  NVD {i}/{n} {cve} ...",
        "verify": "Checking that the folder did not change ...",
    }
    print(texts[step].format(**info))


def scan(repo, project=None, requirements=None, threat_data=True, *, runner=subprocess.run, fetch=None, root=None,
         progress=None, installed=None):
    """Scan `repo` read-only into a new folder analysis/PROJECT/scans/SCAN_ID/ and return the loaded scan."""
    root = Path(root or ANALYSIS_ROOT).resolve()
    say = progress or print_step
    if not str(repo or "").strip() or not Path(repo).expanduser().is_dir():
        raise ScanError("not_a_folder", path=str(repo))
    repo = Path(repo).expanduser().resolve()
    if root == repo or root.is_relative_to(repo):
        raise ScanError("contains_analysis", root=str(root), repo=str(repo))
    if repo.is_relative_to(root):
        raise ScanError("inside_analysis", repo=str(repo))
    versions = installed_scanners() if installed is None else installed
    check_scanners(versions)
    project = project or project_name_for(repo)
    base = project_dir(project, root)

    files = []
    for name in requirements or []:
        f = (repo / name).resolve()
        if not f.is_file() or not f.is_relative_to(repo):
            raise ScanError("requirements_file", file=name)
        files.append(f)
    say("survey")
    before, excluded = survey(repo)
    files = files or find_requirements(repo)
    started = now()
    scan_id = new_id()
    folder = base / "scans" / scan_id
    folder.mkdir(parents=True, exist_ok=False)  # a new folder for every scan: never an earlier one

    say("requirements", n=len(files))
    seen, parsed = set(), []
    for f in files:
        parsed.append(parse_requirements(f, repo, seen))
    pinned, conflicts = merge_pins([p[0] for p in parsed])
    not_audited = [s for p in parsed for s in p[1]] + conflicts
    read = [name for p in parsed for name in p[2]]
    say("pip_audit", n=len(pinned))
    audit = run_pip_audit(runner, folder, pinned)
    not_audited += [{"file": None, "line": None, "text": d["name"], "reason": f"pip-audit: {d['skip_reason']}"}
                    for d in audit.get("dependencies", []) if d.get("skip_reason")]
    say("bandit")
    report = run_bandit(runner, folder, repo, excluded)
    findings = build_findings(audit, report, pinned, repo)
    (folder / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")

    cves = sorted({f["cve"] for f in findings["dependencies"] if f["cve"]})
    if not threat_data:
        (folder / "threat_data.json").write_text(json.dumps(no_threat_data(), indent=2), encoding="utf-8")
    else:
        if fetch is None:
            from fetch_threat_data import fetch
        say("threat", n=len(cves))
        fetch(cves, folder / "threat_data.json", progress=lambda step, **info: say("threat_" + step, **info),
              with_cwe=True)
    threat = json.loads((folder / "threat_data.json").read_text(encoding="utf-8"))

    commit = None
    if (repo / ".git").exists():
        proc = subprocess.run(["git", "-C", str(repo), "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
        commit = proc.stdout.strip() or None
    say("verify")
    after, _ = survey(repo)
    changed = sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))
    analyzed = [f for f in report.get("metrics", {}) if f != "_totals"]
    was_left_out = lambda f: any(f.startswith(e["path"]) if e["path"].endswith("/") else f == e["path"]  # noqa: E731
                                 for e in excluded)
    external = [{"service": "pypi", "count": len(pinned)}] if pinned else []
    if threat_data:
        external += [{"service": "kev", "count": 0}] + ([{"service": "epss", "count": len(cves)},
                                                         {"service": "nvd", "count": len(cves)}] if cves else [])
    meta = {
        "id": scan_id, "project": project, "folder_name": repo.name, "commit": commit,
        "scanned_at": started, "finished_at": now(), "scanners": versions,
        "requirements_files": read, "pinned": pinned, "not_audited": not_audited,
        "manifests_not_read": [m for m in MANIFESTS_NOT_READ if (repo / m).is_file()],
        "excluded": excluded,
        "bandit": {"files_analyzed": len(analyzed),
                   "excluded_files_analyzed": sorted(a for a in analyzed if was_left_out(a)),
                   "files_not_parsed": [{"file": e.get("filename"), "reason": e.get("reason")}
                                        for e in report.get("errors", [])]},
        "threat_data": {"downloaded": bool(threat_data), "fetched_at": threat.get("fetched_at"),
                        "kev_catalog_version": (threat.get("sources") or {}).get("kev_catalog_version")},
        "external": external,
        "repository_check": {"files_compared": len(before), "unchanged": not changed, "changed": changed[:20]},
        "counts": {"dependencies": len(findings["dependencies"]), "code": len(findings["code"]), "cves": len(cves)},
        "not_done": NOT_DONE,
        "complete": True,
    }
    with open(folder / "scan.json", "x", encoding="utf-8") as handle:  # last: only a finished scan has it
        json.dump(meta, handle, indent=2)
    return load_scan(folder)


# ---------- reading scans and exposure declarations ----------

def load_scan(folder):
    folder = Path(folder)
    read = lambda name: json.loads((folder / name).read_text(encoding="utf-8"))  # noqa: E731
    return {"folder": folder, "meta": read("scan.json"), "findings": read("findings.json"),
            "threat": read("threat_data.json")}


def list_projects(root=None):
    """Projects with at least one scan folder (anything else in analysis/ is ignored)."""
    base = Path(root or ANALYSIS_ROOT)
    found = base.glob("*/scans/*") if base.is_dir() else []
    return sorted({p.parent.parent.name for p in found if ITEM_ID.fullmatch(p.name) and NAME.fullmatch(p.parent.parent.name)})


def list_scans(project, root=None):
    """(scan id, folder, complete) for every scan of the project, newest first."""
    folder = project_dir(project, root) / "scans"
    found = [p for p in folder.iterdir() if p.is_dir() and ITEM_ID.fullmatch(p.name)] if folder.is_dir() else []
    return [(p.name, p, (p / "scan.json").is_file()) for p in sorted(found, key=lambda p: p.name, reverse=True)]


def declare_exposure(project, values, root=None):
    """Save a new declaration file (never overwriting one). Each field is True, False or None (not declared);
    environment is 'production', 'non-production' or None."""
    clean = {}
    for field in EXPOSURE_FIELDS:
        value = values.get(field)
        allowed = ENVIRONMENTS if field == "environment" else (True, False)
        if value is not None and value not in allowed:
            raise ValueError(f"{field}: {value!r}")
        clean[field] = value
    folder = project_dir(project, root) / "exposure"
    folder.mkdir(parents=True, exist_ok=True)
    declaration = {"id": new_id(), "project": project, "declared_at": now(), "exposure": clean}
    with open(folder / f"{declaration['id']}.json", "x", encoding="utf-8") as handle:
        json.dump(declaration, handle, indent=2)
    return declaration


def latest_exposure(project, root=None):
    folder = project_dir(project, root) / "exposure"
    files = sorted(p for p in folder.glob("*.json") if ITEM_ID.fullmatch(p.stem)) if folder.is_dir() else []
    return json.loads(files[-1].read_text(encoding="utf-8")) if files else None


# ---------- ranking ----------

def x_interval(declared):
    """(low, high) for X: a field not declared (None) can add anything from 0 to its weight; it is never
    read as 'not exposed'."""
    weights = {"internet_facing": X_WEIGHTS["internet"], "requires_auth": X_WEIGHTS["no_auth"],
               "environment": X_WEIGHTS["production"], "sensitive_data": X_WEIGHTS["sensitive"]}
    hits = {"internet_facing": lambda v: v is True, "requires_auth": lambda v: v is False,
            "environment": lambda v: v == "production", "sensitive_data": lambda v: v is True}
    low = high = 0.0
    for field in EXPOSURE_FIELDS:
        value = declared.get(field)
        if value is None:
            high += weights[field]
        elif hits[field](value):
            low += weights[field]
            high += weights[field]
    return round(low, 3), round(high, 3)


def possible_bands(kev, epss, internet):
    """The action bands (bands.py) this finding can get given what is known: one band, or several when an
    undeclared exposure or a missing EPSS could change it."""
    found = {band_for({"kev": kev, "internet_facing": net, "epss": e})[0]
             for net in ([internet] if internet is not None else [True, False])
             for e in ([epss] if epss is not None else [None, 1.0])}
    return sorted(found, key=BAND_ORDER.get)


def rank_scan(scan, exposure=None):
    """The two queues of one scan under one exposure declaration (None: nothing declared). Pure: nothing is
    written, and the same scan and declaration always give the same queues."""
    declared = dict.fromkeys(EXPOSURE_FIELDS) | ((exposure or {}).get("exposure") or {})
    x_low, x_high = x_interval(declared)
    threat = scan["threat"]
    keyed = []
    for f in scan["findings"]["dependencies"]:
        cve = f["cve"]
        kev = bool(cve and cve in threat.get("kev", {}))
        record = (threat.get("epss") or {}).get(cve) if cve else None
        epss = record["epss"] if record else None
        cvss = (threat.get("cvss") or {}).get(cve) if cve else None
        if kev:
            e = (max(epss, KEV_FLOOR),) * 2 if epss is not None else (KEV_FLOOR, 1.0)
        else:
            e = (epss, epss) if epss is not None else (0.0, 1.0)
        s = (cvss / 10, cvss / 10) if cvss is not None else (0.0, 1.0)
        known = (100 * (W_E * e[0] + W_S * s[0]), 100 * (W_E * e[1] + W_S * s[1]))
        missing = (["CVE"] if not cve else []) + (["EPSS"] if cve and epss is None else []) + \
                  (["CVSS"] if cve and cvss is None else [])
        # The guaranteed minimum first, then the maximum; X is the same for every row, so it is left out.
        order = (-round(known[0], 6), -round(known[1], 6), canon(f["package"]), f["advisory"])
        keyed.append((order, {
            **f, "kev": kev, "epss": epss, "epss_percentile": record["percentile"] if record else None,
            "cvss": cvss, "cwe": ((threat.get("cwe") or {}).get(cve) or []) if cve else [],
            "E": [round(e[0], 3), round(e[1], 3)], "S": [round(s[0], 3), round(s[1], 3)], "X": [x_low, x_high],
            "score": [round(known[0] + 100 * W_X * x_low, 1), round(known[1] + 100 * W_X * x_high, 1)],
            "position": "exact" if known[0] == known[1] else "provisional", "missing": missing,
            "bands": possible_bands(kev, epss, declared["internet_facing"]),
        }))
    dependencies = [{**row, "rank": rank} for rank, (_, row) in enumerate(sorted(keyed, key=lambda k: k[0]), 1)]
    code = sorted(scan["findings"]["code"], key=lambda r: (LEVEL.get(r["severity"], 3), LEVEL.get(r["confidence"], 3),
                                                            r["test_code"], r["file"], r["line"], r["id"]))
    code = [{**row, "rank": rank} for rank, row in enumerate(code, 1)]
    return {
        "exposure": declared, "exposure_id": (exposure or {}).get("id"),
        "exposure_declared_at": (exposure or {}).get("declared_at"),
        "unknown_fields": [f for f in EXPOSURE_FIELDS if declared[f] is None], "X": [x_low, x_high],
        "dependencies": dependencies, "code": code,
        "counts": {
            "dependencies": len(dependencies), "cves": len({r["cve"] for r in dependencies if r["cve"]}),
            "kev": len({r["cve"] for r in dependencies if r["kev"]}),
            "provisional": sum(1 for r in dependencies if r["position"] == "provisional"),
            "code": len(code), **{f"code_{lvl.lower()}": sum(1 for r in code if r["severity"] == lvl) for lvl in LEVEL},
            "code_in_tests": sum(1 for r in code if r["test_code"]),
        },
    }


# ---------- command line ----------

def show(scan, ranked, top=20):
    meta = scan["meta"]
    check = meta["repository_check"]
    print(f"\nProject {meta['project']}, scan {meta['id']} of {meta['folder_name']}"
          + (f" (commit {meta['commit']})" if meta["commit"] else ""))
    print(f"Scanners: {', '.join(f'{k} {v}' for k, v in meta['scanners'].items())}; threat data: "
          + (meta["threat_data"]["fetched_at"] if meta["threat_data"]["downloaded"] else "not downloaded (--no-threat-data)"))
    print(f"Folder unchanged: {'yes' if check['unchanged'] else 'NO: ' + ', '.join(check['changed'])} "
          f"({check['files_compared']} files compared)")
    print("Excluded: " + (", ".join(f"{e['path']} ({e['reason']})" for e in meta["excluded"]) or "nothing"))
    if ranked["unknown_fields"]:
        print(f"Exposure not declared: {', '.join(ranked['unknown_fields'])} (unknown, not 'no'); X is "
              f"{ranked['X'][0]}-{ranked['X'][1]}")
    print(f"\nDEPENDENCIES (pip-audit): {len(ranked['dependencies'])}  ordered by ScoreRisk's guaranteed minimum")
    for r in ranked["dependencies"][:top]:
        score = f"{r['score'][0]}" if r["score"][0] == r["score"][1] else f"{r['score'][0]}-{r['score'][1]}"
        print(f"{r['rank']:>3} {score:>11}  {r['file']}:{r['line']}  {r['package']} {r['version']} "
              f"{r['cve'] or r['advisory']}  EPSS {format(r['epss'], '.3f') if r['epss'] is not None else '-'}  CVSS "
              f"{r['cvss'] if r['cvss'] is not None else '-'}  KEV {'yes' if r['kev'] else 'no'}  "
              f"{'/'.join(r['bands'])}{'  (provisional: no ' + ', '.join(r['missing']) + ')' if r['missing'] else ''}")
    print(f"\nCODE (Bandit): {len(ranked['code'])}  ordered by Bandit severity, then confidence, tests last")
    for r in ranked["code"][:top]:
        print(f"{r['rank']:>3} {r['severity']:<6}/{r['confidence']:<6} {r['file']}:{r['line']}  {r['test_id']} "
              f"{r['cwe'] or ''}  {r['message'][:70]}{'  [test code]' if r['test_code'] else ''}")
    print(f"\n{NOT_DONE}")


def parse_declaration(pairs):
    words = {"yes": True, "no": False, "unknown": None, "production": "production",
             "non-production": "non-production"}
    values = {}
    for pair in pairs:
        field, _, word = pair.partition("=")
        if field not in EXPOSURE_FIELDS or word not in words:
            raise SystemExit(f"{pair}: use FIELD=yes|no|unknown (environment=production|non-production|unknown); "
                             f"fields: {', '.join(EXPOSURE_FIELDS)}")
        values[field] = words[word]
    return values


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan a Python repository, read-only (see the module docstring).")
    parser.add_argument("repo", nargs="?", help="folder of the repository to scan")
    parser.add_argument("--project", help="project name (default: the folder name)")
    parser.add_argument("--requirements", action="append", default=[],
                        help="requirements file, relative to the repository (repeatable; default requirements*.txt)")
    parser.add_argument("--no-threat-data", action="store_true",
                        help="do not download KEV, EPSS and CVSS (pip-audit still asks PyPI)")
    parser.add_argument("--show", metavar="PROJECT", help="print the queues of a project's latest scan")
    parser.add_argument("--scan", help="with --show: a specific scan id")
    parser.add_argument("--declare", nargs="+", metavar="ARG", help="PROJECT FIELD=VALUE ...: a new exposure declaration")
    parser.add_argument("--top", type=int, default=20)
    args = parser.parse_args(argv)
    try:
        if args.declare:
            declaration = declare_exposure(args.declare[0], parse_declaration(args.declare[1:]))
            print(f"Saved a new declaration {declaration['id']}: {declaration['exposure']}")
            return
        if args.show:
            scans = [s for s in list_scans(args.show) if s[2] and (not args.scan or s[0] == args.scan)]
            if not scans:
                raise ScanError("no_project", project=args.show)
            loaded = load_scan(scans[0][1])
        else:
            if not args.repo:
                parser.error("give the repository folder, or --show PROJECT")
            loaded = scan(args.repo, args.project, args.requirements, threat_data=not args.no_threat_data)
            print(f"\nSaved {loaded['folder']}")
        show(loaded, rank_scan(loaded, latest_exposure(loaded["meta"]["project"])), args.top)
    except ScanError as exc:
        raise SystemExit(str(exc))


if __name__ == "__main__":
    main()
