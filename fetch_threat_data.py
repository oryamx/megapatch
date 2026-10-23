"""Download public threat data once and freeze it in data/threat_data.json.

Sources: CISA KEV, FIRST EPSS, NVD (CVSS base score). The snapshot is committed so
ScoreRisk is deterministic (same input -> same score) and judge-check runs offline.

What each source receives: KEV, nothing (the whole catalog is downloaded); EPSS, the list of CVE ids;
NVD, one CVE id per request (plus the key in NVD_API_KEY, if that variable is set, to allow faster requests).

Usage: python fetch_threat_data.py
"""
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
OUT = Path("data/threat_data.json")
NVD_PAUSE_S = 6.5  # NVD allows 5 requests per 30 s without an API key
NVD_PAUSE_WITH_KEY_S = 0.7  # and 50 per 30 s with one
EPSS_BATCH = 50  # CVE ids per EPSS request (the API returns at most 100 rows per page)


def get_json(url, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": "megapatch-hackathon", **(headers or {})})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except Exception:
            if attempt == 2:
                raise
            time.sleep(10)


def cvss_from_nvd(data):
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    metrics = vulns[0]["cve"].get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        primary = [m for m in entries if m.get("type") == "Primary"]
        chosen = (primary or entries or [None])[0]
        if chosen:
            return chosen["cvssData"]["baseScore"]
    return None


def cwes_from_nvd(data):
    """The CWE ids NVD lists for the CVE, e.g. ["CWE-79"] (NVD-CWE-Other and NVD-CWE-noinfo are left out)."""
    vulns = data.get("vulnerabilities", [])
    found = []
    for weakness in (vulns[0]["cve"].get("weaknesses", []) if vulns else []):
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value.startswith("CWE-") and value not in found:
                found.append(value)
    return found


def print_progress(step, **info):
    print({"kev": "KEV catalog ...", "epss": "EPSS ...", "nvd": "NVD {i}/{n} {cve} ..."}[step].format(**info))


def main():
    """The demo's snapshot: the CVEs of its frozen scanner output, into data/threat_data.json."""
    from ingest import build_findings

    fetch(sorted({f["cve"] for f in build_findings() if f["cve"]}), OUT)


def fetch(cves, out, progress=None, with_cwe=False):
    """Download KEV, EPSS and CVSS for `cves` and write the snapshot to `out` (repo_scan.py passes its own
    analysis folder, so the demo's snapshot is never touched). CVSS values already in `out` are reused.
    `progress(step, **info)` replaces the printed progress (the dashboard shows it). `with_cwe` also stores
    the CWE ids NVD lists for each CVE (repo_scan.py); without it the snapshot has the demo's format."""
    cves = sorted(set(cves))
    out = Path(out)
    say = progress or print_progress
    previous = json.loads(out.read_text(encoding="utf-8")).get("cvss", {}) if out.exists() else {}

    say("kev")
    kev_raw = get_json(KEV_URL)
    kev_index = {v["cveID"]: v for v in kev_raw["vulnerabilities"]}
    kev = {
        c: {
            "date_added": kev_index[c]["dateAdded"],
            "ransomware_use": kev_index[c].get("knownRansomwareCampaignUse"),
        }
        for c in cves
        if c in kev_index
    }

    say("epss")
    epss = {}
    for start in range(0, len(cves), EPSS_BATCH):  # no request at all for no CVEs: an empty query lists every CVE
        for r in get_json(EPSS_URL + ",".join(cves[start:start + EPSS_BATCH]))["data"]:
            epss[r["cve"]] = {"epss": float(r["epss"]), "percentile": float(r["percentile"]), "date": r["date"]}

    key = os.environ.get("NVD_API_KEY")
    headers, pause = ({"apiKey": key}, NVD_PAUSE_WITH_KEY_S) if key else ({}, NVD_PAUSE_S)
    cvss, cwe = {}, {}
    for i, cve in enumerate(cves, 1):
        if previous.get(cve) is not None and not with_cwe:  # already frozen in an earlier snapshot
            cvss[cve] = previous[cve]
            continue
        say("nvd", i=i, n=len(cves), cve=cve)
        data = get_json(NVD_URL + cve, headers)
        cvss[cve] = cvss_from_nvd(data)
        cwe[cve] = cwes_from_nvd(data)
        time.sleep(pause)

    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": {"kev_catalog_version": kev_raw.get("catalogVersion"), "kev_total": len(kev_index)},
        "kev": kev,
        "epss": epss,
        "cvss": cvss,
    }
    if with_cwe:
        snapshot["cwe"] = cwe
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")

    missing = [c for c in cves if c not in epss or cvss.get(c) is None]
    if progress is None:
        print(f"\nSaved {out}. CVEs: {len(cves)} | in KEV: {len(kev)} | missing data: {missing or 'none'}")
    return snapshot


if __name__ == "__main__":
    main()
