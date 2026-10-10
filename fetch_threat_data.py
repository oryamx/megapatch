"""Download public threat data once and freeze it in data/threat_data.json.

Sources: CISA KEV, FIRST EPSS, NVD (CVSS base score). The snapshot is committed so
ScoreRisk is deterministic (same input -> same score) and judge-check runs offline.

Usage: python fetch_threat_data.py
"""
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
OUT = Path("data/threat_data.json")
NVD_PAUSE_S = 6.5  # NVD allows 5 requests per 30 s without an API key


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "megapatch-hackathon"})
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


def main():
    from ingest import build_findings

    cves = sorted({f["cve"] for f in build_findings() if f["cve"]})
    previous = json.loads(OUT.read_text(encoding="utf-8")).get("cvss", {}) if OUT.exists() else {}

    print(f"KEV catalog ...")
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

    print("EPSS ...")
    epss_raw = get_json(EPSS_URL + ",".join(cves))
    epss = {
        r["cve"]: {"epss": float(r["epss"]), "percentile": float(r["percentile"]), "date": r["date"]}
        for r in epss_raw["data"]
    }

    cvss = {}
    for i, cve in enumerate(cves, 1):
        if previous.get(cve) is not None:  # already frozen in an earlier snapshot
            cvss[cve] = previous[cve]
            continue
        print(f"NVD {i}/{len(cves)} {cve} ...")
        cvss[cve] = cvss_from_nvd(get_json(NVD_URL + cve))
        time.sleep(NVD_PAUSE_S)

    snapshot = {
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": {"kev_catalog_version": kev_raw.get("catalogVersion"), "kev_total": len(kev_index)},
        "kev": kev,
        "epss": epss,
        "cvss": cvss,
    }
    OUT.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")

    missing = [c for c in cves if c not in epss or cvss.get(c) is None]
    print(f"\nSaved {OUT}. CVEs: {len(cves)} | in KEV: {len(kev)} | missing data: {missing or 'none'}")


if __name__ == "__main__":
    main()
