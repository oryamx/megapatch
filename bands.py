"""Action bands: a SIMPLIFIED, project-specific mapping inspired by CISA's SSVC.

This is NOT CISA's SSVC decision tree. CISA's outcomes are Track, Track*, Attend
and Act; we borrow those four names for a small rule table over the signals this
project actually has. Asset exposure is DECLARED in the practice inventory
(data/assets.json), not discovered, so a band is only as good as those inputs.

Every band comes with its basis, so a reader can see why it was assigned.
"""

EPSS_ATTEND = 0.50  # project parameter (set 2026-10-09), not an SSVC value; tune per environment
BAND_ORDER = {"Act": 0, "Attend": 1, "Track*": 2, "Track": 3}


def band_for(row, verdict=None):
    """Return (band, basis) for a ScoreRisk row and an optional sandbox verdict."""
    if verdict == "CONFIRMED":
        return "Act", "exploit confirmed in the sandbox (demo app)"
    if row["kev"] and row["internet_facing"]:
        return "Act", "in CISA KEV + internet-facing (declared)"
    if row["kev"]:
        return "Attend", "in CISA KEV, internal asset (declared)"
    if row["epss"] is not None and row["epss"] >= EPSS_ATTEND:
        return "Attend", f"EPSS {row['epss']:.2f} is at or above {EPSS_ATTEND:.2f}; not in KEV"
    if row["internet_facing"]:
        return "Track*", "internet-facing (declared); no exploitation evidence"
    return "Track", "no strong exploitation or exposure signal"
