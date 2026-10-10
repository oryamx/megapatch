"""ScoreRisk: a deterministic, auditable risk score. A rule, not a model.

  pre-score = 100 * (W_E * E + W_X * X + W_S * S)

  E  exploitability: EPSS; floored at KEV_FLOOR when the CVE is in CISA KEV;
     UNKNOWN_E when there is no CVE or no EPSS value (no public exploitation data to read).
  X  exposure: asset context (internet, authentication, production, sensitive data).
  S  severity: CVSS base score / 10 (weighted low on purpose: it is the source of the noise);
     a neutral 0.5 when no CVSS is available.

Same input files -> same output, always. No network, no model.
Usage: python scorerisk.py        (writes evidence/ranking.json)
"""
import hashlib
import json
from pathlib import Path

from ingest import build_findings

W_E, W_X, W_S = 0.50, 0.30, 0.20
KEV_FLOOR = 0.90   # a CVE known to be exploited in the wild is never "unlikely"
UNKNOWN_E = 0.30   # no CVE / no EPSS: no exploitation data; the sandbox PoC settles it later
UNKNOWN_S = 0.50   # no CVSS available: neutral
# Exposure weights (sum to 1.0). Starting point, meant to be tuned per environment.
X_WEIGHTS = {"internet": 0.40, "no_auth": 0.25, "production": 0.20, "sensitive": 0.15}

THREAT = Path("data/threat_data.json")
OUT = Path("evidence/ranking.json")


def exploitability(finding, threat):
    cve = finding["cve"]
    if not cve:
        return UNKNOWN_E, "no CVE: unknown"
    epss = (threat["epss"].get(cve) or {}).get("epss")
    if cve in threat["kev"]:
        return max(epss or 0.0, KEV_FLOOR), "in KEV"
    if epss is None:
        return UNKNOWN_E, "no EPSS value: unknown"
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
    cvss = finding.get("cvss_override") or threat["cvss"].get(finding["cve"] or "")
    if cvss is None:
        return None, UNKNOWN_S
    return cvss, cvss / 10


FINGERPRINT_VERSION = 2  # v1 hashed ids + dates + weights only; v2 hashes the full inputs and the ranking


def fingerprint():
    """Short hash of everything that determines the ranking: every finding with all of its
    fields (CVE, exposure, CVSS overrides...), the complete frozen threat-data snapshot
    (EPSS, KEV, CVSS), the scoring parameters, and the computed ranking itself. A run is
    only comparable to the current ranking when this value matches."""
    ranked, threat = score_all()
    material = {
        "version": FINGERPRINT_VERSION,
        "findings": build_findings(),
        "threat_data": threat,
        "parameters": {
            "weights": [W_E, W_X, W_S],
            "constants": [KEV_FLOOR, UNKNOWN_E, UNKNOWN_S],
            "exposure_weights": X_WEIGHTS,
        },
        "ranking": [
            {k: r[k] for k in ("id", "rank", "pre_score", "E", "X", "S", "cvss", "epss", "kev")} for r in ranked
        ],
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def score_all():
    findings = build_findings()
    threat = json.loads(THREAT.read_text(encoding="utf-8"))
    rows = []
    for f in findings:
        e, e_note = exploitability(f, threat)
        x = exposure(f)
        cvss, s = severity(f, threat)
        epss = (threat["epss"].get(f["cve"]) or {}).get("epss") if f["cve"] else None
        rows.append(
            {
                "id": f["id"], "title": f["title"], "scanner": f["scanner"], "cve": f["cve"],
                "cwe": f.get("cwe"), "asset": f["asset"],
                "internet_facing": f["exposure"]["internet_facing"],
                "cvss": cvss, "epss": epss,
                "kev": bool(f["cve"] and f["cve"] in threat["kev"]),
                "E": round(e, 3), "X": round(x, 3), "S": round(s, 3), "E_note": e_note,
                "pre_score": round(100 * (W_E * e + W_X * x + W_S * s), 1),
            }
        )
    by_cvss = sorted(rows, key=lambda r: (-(r["cvss"] if r["cvss"] is not None else -1), r["id"]))
    for rank, r in enumerate(by_cvss, 1):
        r["cvss_rank"] = rank
    ranked = sorted(rows, key=lambda r: (-r["pre_score"], r["id"]))
    for rank, r in enumerate(ranked, 1):
        r["rank"] = rank
    return ranked, threat


def main(show=15):
    ranked, threat = score_all()
    print(
        f"Threat data snapshot: {threat['fetched_at']} | KEV catalog {threat['sources']['kev_catalog_version']} "
        f"| {len(ranked)} findings"
    )
    print(f"{'#':>3} {'id':<34}{'score':>6} {'E':>5}{'X':>5}{'S':>5} {'CVSS':>5}{'(rank)':>8} {'EPSS':>6} {'KEV':<4}")
    for r in ranked[:show]:
        epss = f"{r['epss']:.3f}" if r["epss"] is not None else "  n/a"
        cvss = f"{r['cvss']:.1f}" if r["cvss"] is not None else "n/a"
        print(
            f"{r['rank']:>3} {r['id'][:33]:<34}{r['pre_score']:>6} {r['E']:>5}{r['X']:>5}{r['S']:>5} "
            f"{cvss:>5}{'(#' + str(r['cvss_rank']) + ')':>8} {epss:>6} {'YES' if r['kev'] else '-':<4}"
        )
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(ranked, indent=2), encoding="utf-8")
    print(f"\n(showing the top {show} of {len(ranked)}) Written {OUT}")


if __name__ == "__main__":
    main()
