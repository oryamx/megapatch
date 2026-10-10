"""ScoreRisk: a deterministic, auditable risk score. A rule, not a model.

  pre-score = 100 * (W_E * E + W_X * X + W_S * S)

  E  exploitability: EPSS; floored at KEV_FLOOR when the CVE is in CISA KEV;
     UNKNOWN_E when there is no CVE (no public exploitation data to read).
  X  exposure: asset context (internet, authentication, production, sensitive data).
  S  severity: CVSS base score / 10 (weighted low on purpose: it is the source of the noise).

Same input files -> same output, always. No network, no model.
Usage: python scorerisk.py        (writes evidence/ranking.json)
"""
import json
from pathlib import Path

W_E, W_X, W_S = 0.50, 0.30, 0.20
KEV_FLOOR = 0.90   # a CVE known to be exploited in the wild is never "unlikely"
UNKNOWN_E = 0.30   # no CVE: no EPSS/KEV data; the sandbox PoC settles it later
# Exposure weights (sum to 1.0). Starting point, meant to be tuned per environment.
X_WEIGHTS = {"internet": 0.40, "no_auth": 0.25, "production": 0.20, "sensitive": 0.15}

FINDINGS = Path("data/findings.json")
THREAT = Path("data/threat_data.json")
OUT = Path("evidence/ranking.json")


def exploitability(finding, threat):
    cve = finding["cve"]
    if not cve:
        return UNKNOWN_E, "no CVE: unknown"
    epss = threat["epss"][cve]["epss"]
    if cve in threat["kev"]:
        return max(epss, KEV_FLOOR), "in KEV"
    return epss, "not in KEV"


def exposure(finding):
    x = finding["exposure"]
    return (
        X_WEIGHTS["internet"] * x["internet_facing"]
        + X_WEIGHTS["no_auth"] * (not x["requires_auth"])
        + X_WEIGHTS["production"] * (x["environment"] == "production")
        + X_WEIGHTS["sensitive"] * x["sensitive_data"]
    )


def severity(finding, threat):
    cvss = finding.get("cvss_override") or threat["cvss"][finding["cve"]]
    return cvss, cvss / 10


def score_all():
    findings = json.loads(FINDINGS.read_text(encoding="utf-8"))["findings"]
    threat = json.loads(THREAT.read_text(encoding="utf-8"))
    rows = []
    for f in findings:
        e, e_note = exploitability(f, threat)
        x = exposure(f)
        cvss, s = severity(f, threat)
        rows.append(
            {
                "id": f["id"], "title": f["title"], "cve": f["cve"], "cwe": f.get("cwe"), "asset": f["asset"],
                "internet_facing": f["exposure"]["internet_facing"],
                "cvss": cvss, "epss": threat["epss"][f["cve"]]["epss"] if f["cve"] else None,
                "kev": bool(f["cve"] and f["cve"] in threat["kev"]),
                "E": round(e, 3), "X": round(x, 3), "S": round(s, 3), "E_note": e_note,
                "pre_score": round(100 * (W_E * e + W_X * x + W_S * s), 1),
            }
        )
    by_cvss = sorted(rows, key=lambda r: (-r["cvss"], r["id"]))
    for rank, r in enumerate(by_cvss, 1):
        r["cvss_rank"] = rank
    ranked = sorted(rows, key=lambda r: (-r["pre_score"], r["id"]))
    for rank, r in enumerate(ranked, 1):
        r["rank"] = rank
    return ranked, threat


def main():
    ranked, threat = score_all()
    print(f"Threat data snapshot: {threat['fetched_at']} | KEV catalog {threat['sources']['kev_catalog_version']}")
    print(f"{'#':>2} {'id':<5}{'score':>6} {'E':>5}{'X':>5}{'S':>5} {'CVSS':>5}{'(rank)':>7} {'EPSS':>6} {'KEV':<4} title")
    for r in ranked:
        epss = f"{r['epss']:.3f}" if r["epss"] is not None else "  n/a"
        print(
            f"{r['rank']:>2} {r['id']:<5}{r['pre_score']:>6} {r['E']:>5}{r['X']:>5}{r['S']:>5} "
            f"{r['cvss']:>5}{'(#' + str(r['cvss_rank']) + ')':>7} {epss:>6} {'YES' if r['kev'] else '-':<4} {r['title']}"
        )
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(ranked, indent=2), encoding="utf-8")
    print(f"\nWritten {OUT}")


if __name__ == "__main__":
    main()
