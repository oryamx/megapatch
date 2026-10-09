"""Vulnerability classes the MVP can verify and patch: one mechanical PoC per class.

Anything not listed here is still ranked by ScoreRisk, but reported as
NOT_VERIFIABLE (never as "safe").
"""
CLASSES = {
    "CWE-89": {"name": "SQL injection", "poc": "poc_sqli.py", "route": "/users/search"},
    "CWE-78": {"name": "OS command injection", "poc": "poc_cmdi.py", "route": "/lookup"},
    "CWE-22": {"name": "path traversal", "poc": "poc_path.py", "route": "/files"},
}
