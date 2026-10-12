"""Vulnerability classes the MVP can verify and patch: one mechanical PoC per class.

Anything not listed here is still ranked by ScoreRisk, but reported as
NOT_VERIFIABLE (never as "safe").
"""
import hashlib
from pathlib import Path


def judge_files():
    """The repository files whose content determines a verdict (see judge.py for the scope)."""
    fixed = [
        "harness.py",            # loads the app under test
        "test_target_app.py",    # functional + regression tests
        "target_app/app.py",     # the vulnerable app and its fixture data
        "judge.py",              # acceptance rule and local executor
        "sandbox_judge.py",      # how the code runs in the Nebius sandbox (image, install, upload)
        "catalog.py",            # which PoC belongs to which vulnerability class
    ]
    return fixed + sorted(c["poc"] for c in CLASSES.values())


def judge_fingerprint():
    """Short hash of the content of every file in judge_files(). Stored in each evidence
    file so a reader can tell which version of the judge produced a verdict. Line endings
    are normalized so Windows and Linux agree. It does NOT cover what is installed inside
    the sandbox at run time (flask, pytest, contree-sdk) nor Nebius's platform behavior."""
    digest = hashlib.sha256()
    for name in judge_files():
        digest.update(name.encode("utf-8"))
        digest.update(Path(name).read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()[:16]


CLASSES = {
    "CWE-89": {"name": "SQL injection", "poc": "poc_sqli.py", "route": "/users/search"},
    "CWE-78": {"name": "OS command injection", "poc": "poc_cmdi.py", "route": "/lookup"},
    "CWE-22": {"name": "path traversal", "poc": "poc_path.py", "route": "/files"},
}
