"""Turn real scanner output into the findings ScoreRisk ranks.

Inputs (frozen fixtures, so results are reproducible):
  scans/pip_audit.json   pip-audit (SCA) run over scans/requirements.txt
  scans/bandit.json      Bandit (SAST) run over target_app/
  data/assets.json       DECLARED context: which asset each package/file belongs to and
                         how exposed it is (a fictional practice project)

Refresh the scanner outputs with the commands in the README.
"""
import json
from pathlib import Path

from catalog import CLASSES

PIP_AUDIT = Path("scans/pip_audit.json")
BANDIT = Path("scans/bandit.json")
ASSETS = Path("data/assets.json")

CWE_BY_ID = {89: "CWE-89", 78: "CWE-78", 22: "CWE-22"}
SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _upper_first(text):
    return text[:1].upper() + text[1:]  # str.capitalize() would turn "SQL" into "Sql"


def _cve_of(vuln):
    ids = [vuln["id"], *vuln.get("aliases", [])]
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    return cves[0] if cves else None


def _sca_findings(assets):
    findings = []
    seen = set()  # pip-audit may list the same advisory more than once; keep one finding each
    data = json.loads(PIP_AUDIT.read_text(encoding="utf-8"))
    for dep in data["dependencies"]:
        for vuln in dep.get("vulns", []):
            key = (dep["name"].lower(), vuln["id"])
            if key in seen:
                continue
            seen.add(key)
            asset = assets["package_to_asset"][dep["name"].lower()]
            findings.append(
                {
                    "id": f"{dep['name']}:{vuln['id']}",
                    "title": f"{dep['name']} {dep['version']}: {vuln['id']}",
                    "scanner": "pip-audit (SCA)",
                    "package": f"{dep['name']}=={dep['version']}",
                    "cve": _cve_of(vuln),
                    "cwe": None,
                    "asset": asset,
                    "exposure": assets["assets"][asset],
                    "fix_versions": vuln.get("fix_versions", []),
                }
            )
    return findings


def _code_finding(cwe, title, scanner, assets):
    cvss = assets["code_cvss"][cwe]
    asset = assets["code_asset"]
    return {
        "id": f"{scanner.split()[0].lower()}:{cwe}",
        "title": title,
        "scanner": scanner,
        "package": "target_app/app.py",
        "cve": None,
        "cwe": cwe,
        "cvss_override": cvss["score"],
        "cvss_vector": cvss["vector"],
        "asset": asset,
        "exposure": assets["assets"][asset],
    }


def _sast_findings(assets):
    """One finding per vulnerability class we know how to verify (highest-severity hit)."""
    best = {}
    for result in json.loads(BANDIT.read_text(encoding="utf-8"))["results"]:
        cwe = CWE_BY_ID.get(result["issue_cwe"]["id"])
        rank = SEVERITY_RANK[result["issue_severity"]]
        if cwe and rank >= 2 and (cwe not in best or rank > SEVERITY_RANK[best[cwe]["issue_severity"]]):
            best[cwe] = result
    findings = []
    for cwe, result in sorted(best.items()):
        info = CLASSES[cwe]
        title = f"{_upper_first(info['name'])} in {info['route']} (Bandit {result['test_id']}, line {result['line_number']})"
        findings.append(_code_finding(cwe, title, "Bandit (SAST)", assets))
    for manual in assets["manual_findings"]:
        info = CLASSES[manual["cwe"]]
        title = f"{_upper_first(info['name'])} in {info['route']} ({manual['note']})"
        findings.append(_code_finding(manual["cwe"], title, "manual review", assets))
    return findings


def build_findings():
    assets = json.loads(ASSETS.read_text(encoding="utf-8"))
    return _sca_findings(assets) + _sast_findings(assets)


def scanner_counts():
    """How raw scanner output becomes the findings ScoreRisk ranks, counted from the files
    themselves (no number is typed by hand anywhere it is shown)."""
    raw = json.loads(PIP_AUDIT.read_text(encoding="utf-8"))
    findings = build_findings()

    def from_scanner(name):
        return sum(1 for f in findings if f["scanner"] == name)

    return {
        "pip_audit_entries": sum(len(dep.get("vulns", [])) for dep in raw["dependencies"]),
        "pip_audit_packages": sum(1 for dep in raw["dependencies"] if dep.get("vulns")),
        "pip_audit_findings": from_scanner("pip-audit (SCA)"),
        "bandit_results": len(json.loads(BANDIT.read_text(encoding="utf-8"))["results"]),
        "bandit_findings": from_scanner("Bandit (SAST)"),
        "manual_findings": from_scanner("manual review"),
        "findings": len(findings),
        "unique_cves": len({f["cve"] for f in findings if f["cve"]}),
    }


if __name__ == "__main__":
    items = build_findings()
    sca = [f for f in items if f["scanner"].startswith("pip-audit")]
    print(f"{len(items)} findings: {len(sca)} from pip-audit, {len(items) - len(sca)} from code review")
    print(f"unique CVEs: {len({f['cve'] for f in items if f['cve']})} | without CVE: {sum(1 for f in sca if not f['cve'])}")
