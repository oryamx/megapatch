"""Robustness check for ScoreRisk: does the story survive different weights?

The weights are a starting point, not truth. This script re-scores the findings
under many reasonable parameter choices and reports which conclusions hold in
all of them and which depend on the choice.

It varies the weights and constants, NOT the inputs: the exposure of each asset
is still a declared assumption.

Usage: python sensitivity.py          (prints the conclusions; writes nothing)
       python sensitivity.py --write  (also regenerates the demo's evidence/sensitivity.json)
"""
import itertools
import json
from pathlib import Path

import scorerisk as sr

W_PAIRS = [(e, x) for e in (0.4, 0.5, 0.6) for x in (0.2, 0.3, 0.4) if 0.1 <= round(1 - e - x, 2) <= 0.4]
KEV_FLOORS = (0.7, 0.9, 1.0)
UNKNOWN_ES = (0.2, 0.3, 0.5)
X_VARIANTS = {
    "baseline": {"internet": 0.40, "no_auth": 0.25, "production": 0.20, "sensitive": 0.15},
    "internet-heavy": {"internet": 0.50, "no_auth": 0.20, "production": 0.20, "sensitive": 0.10},
    "balanced": {"internet": 0.25, "no_auth": 0.25, "production": 0.25, "sensitive": 0.25},
}
BASELINE = (sr.W_E, sr.W_X, sr.W_S, sr.KEV_FLOOR, sr.UNKNOWN_E, dict(sr.X_WEIGHTS))

RARE_CVE = "CVE-2023-37920"   # certifi: CVSS 9.8, almost never exploited, internal asset
KEV_CVE = "CVE-2023-4863"     # libwebp via Pillow: lower CVSS, in KEV, internet-facing asset
CODE_IDS = ("bandit:CWE-89", "bandit:CWE-78", "manual:CWE-22")


def ranks_under(w_e, w_x, kev_floor, unknown_e, x_weights):
    sr.W_E, sr.W_X, sr.W_S = w_e, w_x, round(1 - w_e - w_x, 2)
    sr.KEV_FLOOR, sr.UNKNOWN_E, sr.X_WEIGHTS = kev_floor, unknown_e, x_weights
    ranked, _ = sr.score_all()
    by_key = {r["id"]: r["rank"] for r in ranked}
    by_key.update({r["cve"]: r["rank"] for r in ranked if r["cve"]})
    return by_key, len(ranked)


def main(write=False):
    runs, total = [], 0
    for (e, x), kf, ue, xw in itertools.product(W_PAIRS, KEV_FLOORS, UNKNOWN_ES, X_VARIANTS.values()):
        ranks, total = ranks_under(e, x, kf, ue, xw)
        runs.append(ranks)
    sr.W_E, sr.W_X, sr.W_S, sr.KEV_FLOOR, sr.UNKNOWN_E, sr.X_WEIGHTS = BASELINE
    n = len(runs)

    def share(predicate):
        return sum(1 for r in runs if predicate(r)) / n

    results = {
        "configurations_tested": n,
        "findings_ranked": total,
        f"{RARE_CVE} (CVSS 9.8, rarely exploited) ranks below {KEV_CVE} (in KEV)": share(
            lambda r: r[RARE_CVE] > r[KEV_CVE]
        ),
        f"{RARE_CVE} stays outside the top 20": share(lambda r: r[RARE_CVE] > 20),
        f"{KEV_CVE} (in KEV, internet-facing) stays in the top 3": share(lambda r: r[KEV_CVE] <= 3),
        "our 3 code findings all stay inside the top 8": share(lambda r: max(r[i] for i in CODE_IDS) <= 8),
        "bandit:CWE-89 rank range (min, max)": [min(r["bandit:CWE-89"] for r in runs), max(r["bandit:CWE-89"] for r in runs)],
        "manual:CWE-22 rank range (min, max)": [min(r["manual:CWE-22"] for r in runs), max(r["manual:CWE-22"] for r in runs)],
    }
    print(f"Configurations tested: {n} (weights, KEV floor, unknown-E constant, exposure weights) on {total} findings\n")
    for key, value in list(results.items())[2:]:
        text = f"{value:.0%}" if isinstance(value, float) else str(value)
        print(f"  {text:>9}  {key}")

    if write:
        out = Path("evidence/sensitivity.json")
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nWritten {out}")


if __name__ == "__main__":
    import sys

    main(write="--write" in sys.argv[1:])
