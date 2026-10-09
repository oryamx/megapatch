"""Robustness check for ScoreRisk: does the story survive different weights?

The weights are a starting point, not truth. This script re-scores the findings
under many reasonable parameter choices and reports which conclusions hold in
all of them and which depend on the choice.

Usage: python sensitivity.py        (writes evidence/sensitivity.json)
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


def ranks_under(w_e, w_x, kev_floor, unknown_e, x_weights):
    sr.W_E, sr.W_X, sr.W_S = w_e, w_x, round(1 - w_e - w_x, 2)
    sr.KEV_FLOOR, sr.UNKNOWN_E, sr.X_WEIGHTS = kev_floor, unknown_e, x_weights
    ranked, _ = sr.score_all()
    return {r["id"]: r["rank"] for r in ranked}


def main():
    runs = [
        ranks_under(e, x, kf, ue, xw)
        for (e, x), kf, ue, xw in itertools.product(W_PAIRS, KEV_FLOORS, UNKNOWN_ES, X_VARIANTS.values())
    ]
    sr.W_E, sr.W_X, sr.W_S, sr.KEV_FLOOR, sr.UNKNOWN_E, sr.X_WEIGHTS = BASELINE
    n = len(runs)

    def share(predicate):
        return sum(1 for r in runs if predicate(r)) / n

    results = {
        "configurations_tested": n,
        "F-11 (CVSS 9.8, rarely exploited) ranks below F-04 (CVSS 7.5, in KEV)": share(lambda r: r["F-11"] > r["F-04"]),
        "F-11 stays outside the top 8": share(lambda r: r["F-11"] > 8),
        "internet-facing KEV findings F-01, F-03, F-04 all in the top 4": share(
            lambda r: max(r["F-01"], r["F-03"], r["F-04"]) <= 4
        ),
        "our 3 code findings F-12, F-13, F-14 all inside the top 8": share(
            lambda r: max(r["F-12"], r["F-13"], r["F-14"]) <= 8
        ),
        "F-12 rank range (min, max)": [min(r["F-12"] for r in runs), max(r["F-12"] for r in runs)],
        "F-14 rank range (min, max)": [min(r["F-14"] for r in runs), max(r["F-14"] for r in runs)],
    }
    print(f"Configurations tested: {n} (weights, KEV floor, unknown-E constant, exposure weights)\n")
    for key, value in list(results.items())[1:]:
        text = f"{value:.0%}" if isinstance(value, float) else str(value)
        print(f"  {text:>9}  {key}")

    out = Path("evidence/sensitivity.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nWritten {out}")


if __name__ == "__main__":
    main()
