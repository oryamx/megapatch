"""MegaPatch dashboard: the prioritized queue and the before/after evidence.

Run:  streamlit run dashboard.py
Shows evidence/golden_run.json by default and re-computes ScoreRisk offline from the
frozen scanner outputs and threat-data snapshot. A sidebar selector lists the other
local evidence/run_*.json files, but only runs that describe the CURRENT inventory and
scoring set-up (same fingerprint; older files without one must have exactly the same
finding ids). Incompatible runs are hidden and exact duplicates are dropped. In a clean
clone (and on the public demo) only golden_run.json exists, so no selector appears.
No API keys needed, and nothing here calls a model or the sandbox.
"""
import hashlib
import json
import os
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

os.chdir(Path(__file__).resolve().parent)  # data/ and evidence/ are relative to this folder

from bands import EPSS_ATTEND, band_for  # noqa: E402
from scorerisk import FINGERPRINT_VERSION, fingerprint, score_all  # noqa: E402

EVIDENCE = Path("evidence")

st.set_page_config(page_title="MegaPatch", layout="wide")


@st.cache_data(ttl=600)
def current_state():
    """The ids and the fingerprint of the ranking this page is about to show."""
    ranked_now, _ = score_all()
    return {r["id"] for r in ranked_now}, fingerprint()


def is_compatible(path):
    """A run is comparable to the current ranking only when it describes the SAME inputs and
    scoring set-up: a matching current-version fingerprint (full findings, threat data,
    parameters and ranking). Older files, whose fingerprint covered less, must have exactly
    the same finding ids instead."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        ids_now, fp_now = current_state()
        if data.get("fingerprint_version") == FINGERPRINT_VERSION:
            return data.get("inventory_fingerprint") == fp_now
        return {item["id"] for item in data["final_order"]} == ids_now  # equal sets, not a subset
    except (OSError, ValueError, KeyError):
        return False


def chosen_run_path():
    """The recorded demo run by default; a sidebar selector appears only when other
    compatible, distinct runs exist. Incompatible runs are hidden, not mixed in; exact
    duplicates of an earlier option are dropped."""
    golden = EVIDENCE / "golden_run.json"
    others = sorted((p for p in EVIDENCE.glob("*run*.json") if p != golden), reverse=True)
    found = ([golden] if golden.exists() else []) + others
    options, seen_content, hidden = [], set(), 0
    for path in found:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if not is_compatible(path):
            hidden += 1
        elif digest not in seen_content:
            seen_content.add(digest)
            options.append(path)
    if hidden:
        st.sidebar.caption(
            f"{hidden} other run(s) hidden: they describe a different findings inventory or scoring set-up."
        )
    if not options:
        return None
    if len(options) == 1:
        return options[0]
    known = {
        "golden_run.json": "Recorded demo run (golden_run.json)",
        "run_with_repair.json": "Recorded run with a rejected-then-repaired patch",
    }
    names = {p: known.get(p.name, p.name) for p in options}
    return st.sidebar.selectbox("Run to display", options, format_func=lambda p: names[p])


def status_label(raw):
    if "PATCHED" in raw:
        return "Confirmed, patched and re-tested"
    if "REJECTED" in raw:
        return "Confirmed, patch rejected"
    if "not run" in raw:
        return "Confirmed, patch awaiting approval"
    if raw == "NOT_VERIFIABLE":
        return "Not verifiable (no PoC for this class)"
    if raw == "NOT_REPRODUCIBLE":
        return "Not reproducible"
    return raw


def run_signature():
    """Cache key: changes whenever the evidence file changes, so a new deploy shows new data."""
    path = chosen_run_path()
    if path is None:
        return None
    stat = path.stat()
    return (str(path), stat.st_mtime_ns, stat.st_size)


@st.cache_data(ttl=600)
def load(signature):
    ranked, threat = score_all()
    path = Path(signature[0]) if signature else None
    run = json.loads(path.read_text(encoding="utf-8")) if path else None
    sens_path = EVIDENCE / "sensitivity.json"
    sens = json.loads(sens_path.read_text(encoding="utf-8")) if sens_path.exists() else None
    return ranked, threat, run, path, sens


ranked, threat, run, run_path, sensitivity = load(run_signature())
by_id = {r["id"]: r for r in ranked}

st.title("MegaPatch")
st.caption(
    "Rank what matters, prove it is exploitable by running the exploit, patch it, "
    "and re-run the same exploit. The score proposes; execution disposes."
)

# ---------- headline numbers ----------
if run:
    verdicts = run["verdicts"]
    confirmed = [i for i, v in verdicts.items() if v["verdict"] == "CONFIRMED"]
    patched = [i for i, p in run["patches"].items() if p.get("accepted")]
    cols = st.columns(5)
    cols[0].metric("Findings ranked", len(ranked))
    cols[1].metric("Verified by execution", len(confirmed))
    cols[2].metric("Patched", len(patched), help="Fixed by Nemotron and re-tested with the same exploit")
    cols[3].metric("Nemotron cost (est.)", f"${run['usage']['est_cost_usd']:.4f}")
    cols[4].metric("Machine time", f"{run['duration_s']:.0f} s")
    legacy = (
        ""
        if run.get("fingerprint_version") == FINGERPRINT_VERSION
        else " This run predates the full inputs fingerprint; it is matched to the current ranking by "
        "identical finding ids, and its recorded ranks and scores equal the current ones."
    )
    st.caption(
        f"Run `{run_path.name}` on {run['executor']} with {run['model']}. "
        f"Top {run['top_n']} entered verification.{legacy}"
    )
else:
    st.info("No run found yet. Run `python megapatch.py` to create one.")

tab_queue, tab_proof, tab_evidence, tab_why, tab_repro = st.tabs(
    ["Priority queue", "Before / after", "Public evidence", "Why this order", "Reproduce it"]
)

# ---------- 1. queue ----------
with tab_queue:
    # The two contrast cases, chosen by rule so the page never needs hand-picking:
    # the critical-looking finding ScoreRisk ranks lowest, and the lower-CVSS finding in KEV it ranks highest.
    critical = [r for r in ranked if (r["cvss"] or 0) >= 9.0]
    minor_but_kev = [r for r in ranked if r["kev"] and (r["cvss"] is None or r["cvss"] < 9.0)]
    drop = max(critical, key=lambda r: r["rank"]) if critical else ranked[-1]
    rise = min(minor_but_kev, key=lambda r: r["rank"]) if minor_but_kev else ranked[0]

    def describe(r):
        where = "internet-facing (declared)" if r["internet_facing"] else "internal asset (declared)"
        epss = f"{r['epss']:.3f}" if r["epss"] is not None else "n/a"
        return f"EPSS {epss}, {'in' if r['kev'] else 'not in'} CISA KEV, {where}"

    n_cves = len({r["cve"] for r in ranked if r["cve"]})
    n_kev = len({r["cve"] for r in ranked if r["kev"]})
    n_rare = len({r["cve"] for r in ranked if r["cve"] and r["epss"] is not None and r["epss"] < 0.05})
    st.markdown(
        f"**The scanners produced {len(ranked)} distinct findings ({n_cves} unique CVEs). "
        f"{n_kev} {'is' if n_kev == 1 else 'are'} in CISA KEV; {n_rare} have an EPSS below 0.05.**"
    )
    left, right = st.columns(2)
    left.markdown(
        f"**Looks urgent, is not.** {drop['title']} has CVSS {drop['cvss']} "
        f"(#{drop['cvss_rank']} by severity) but ScoreRisk puts it at **#{drop['rank']}**: {describe(drop)}."
    )
    right.markdown(
        f"**Looks minor, is not.** {rise['title']} has CVSS {rise['cvss']} "
        f"(#{rise['cvss_rank']} by severity) but ScoreRisk puts it at **#{rise['rank']}**: {describe(rise)}."
    )

    statuses = {}
    final_pos = {}
    if run:
        for item in run["final_order"]:
            statuses[item["id"]] = status_label(item["status"])
            final_pos[item["id"]] = item["position"]
    verdict_of = {fid: v["verdict"] for fid, v in (run or {}).get("verdicts", {}).items()}
    rows = []
    for r in sorted(ranked, key=lambda x: final_pos.get(x["id"], 1000 + x["rank"])):
        band, basis = band_for(r, verdict_of.get(r["id"]))
        rows.append(
            {
                "Queue #": final_pos.get(r["id"], r["rank"]),
                "Finding": r["id"],
                "Title": r["title"],
                "Band": band,
                "Basis for the band": basis,
                "ScoreRisk": r["pre_score"],
                "ScoreRisk rank": r["rank"],
                "CVSS": r["cvss"],
                "CVSS rank": r["cvss_rank"],
                "In KEV": "yes" if r["kev"] else "no",
                "EPSS": r["epss"],
                "Status": statuses.get(r["id"], "Ranked, outside verification budget"),
            }
        )
    df = pd.DataFrame(rows)
    st.dataframe(
        df,
        hide_index=True,
        width="stretch",
        column_config={
            "ScoreRisk": st.column_config.ProgressColumn("ScoreRisk", min_value=0, max_value=100, format="%.1f"),
            "EPSS": st.column_config.NumberColumn("EPSS", format="%.3f"),
        },
    )
    st.caption(
        "Confirmed findings jump to the top of the queue regardless of their pre-score. "
        "Findings without a PoC are ranked but reported as not verifiable, never as safe. "
        "Bands are a simplified mapping inspired by CISA's SSVC, not the official decision tree; "
        "asset exposure is declared in a fictional practice inventory."
    )

    def short_label(r):
        head, _, tail = r["id"].partition(":")
        return head if r["scanner"].startswith("pip-audit") else tail

    labelled = {r["id"] for r in ranked[:10]} | {drop["id"], rise["id"]}
    chart_df = pd.DataFrame(
        [
            {
                "Finding": r["id"], "CVSS": r["cvss"], "ScoreRisk": r["pre_score"], "Label": short_label(r),
                "Show label": r["id"] in labelled,
                "CISA KEV": "in KEV" if r["kev"] else "not in KEV", "Title": r["title"],
            }
            for r in ranked
            if r["cvss"] is not None
        ]
    )
    base = alt.Chart(chart_df).encode(
        x=alt.X("CVSS:Q", scale=alt.Scale(domain=[2, 10.4]), title="CVSS base score (severity)"),
        y=alt.Y("ScoreRisk:Q", scale=alt.Scale(domain=[0, 108]), title="ScoreRisk (exploitability + exposure)"),
    )
    points = base.mark_circle(size=90, opacity=0.75).encode(
        color=alt.Color(
            "CISA KEV:N", scale=alt.Scale(domain=["in KEV", "not in KEV"], range=["#e8710a", "#4c78a8"])
        ),
        tooltip=["Finding", "Title", "CVSS", "ScoreRisk", "CISA KEV"],
    )
    # Label only the interesting points, one label per cluster so none hides another.
    shown = chart_df[chart_df["Show label"]].copy()
    shown["cluster"] = list(zip(shown["CVSS"], (shown["ScoreRisk"] / 4).round()))
    label_df = (
        shown.groupby("cluster")
        .agg(CVSS=("CVSS", "first"), ScoreRisk=("ScoreRisk", "max"), Label=("Label", lambda s: ", ".join(sorted(set(s)))))
        .reset_index(drop=True)
    )
    labels = (
        alt.Chart(label_df)
        .mark_text(dy=-14, fontSize=11)
        .encode(x="CVSS:Q", y="ScoreRisk:Q", text="Label:N")
    )
    st.altair_chart((points + labels).properties(height=380), width="stretch")
    st.caption(
        "Each dot is a finding. Severity alone (left to right) says little about urgency (bottom to top); "
        "most of the scanner's output sits low on the vertical axis."
    )

# ---------- 2. before / after ----------
with tab_proof:
    if not run or not run["patches"]:
        st.info("No patched findings in this run.")
    for fid, patch in (run or {"patches": {}})["patches"].items():
        finding = by_id.get(fid, {"title": fid})
        accepted = patch.get("accepted")
        st.subheader(f"{fid}: {finding['title']}")
        st.markdown(
            f"**Result: {'patch accepted (red to green)' if accepted else 'patch not accepted'}** · "
            f"approval: {patch.get('approval', 'human (older run format)')}"
        )
        for earlier in patch.get("attempt_history", []):
            with st.expander(f"Attempt {earlier['attempt']} was rejected by the judge, then Nemotron repaired it"):
                st.markdown(
                    "Same exploit, same tests. The judge's output was handed back to the model, "
                    "which wrote the next attempt."
                )
                st.code(
                    (earlier.get("poc_output") or "") + "\n\ntests: "
                    + ((earlier.get("tests_output") or "").strip().splitlines() or ["n/a"])[-1],
                    language="text",
                    wrap_lines=True,
                )
                st.code(earlier["diff"], language="diff")
        before, after = st.columns(2)
        before.markdown("**Before: the exploit runs on the vulnerable app (sandbox)**")
        before.code(run["verdicts"][fid]["evidence"], language="text", wrap_lines=True)
        after.markdown("**After: the same exploit and the functional tests on the patched app**")
        after.code(
            (patch.get("poc_output") or "") + "\n\ntests: "
            + ((patch.get("tests_output") or "").splitlines() or ["n/a"])[-1],
            language="text",
            wrap_lines=True,
        )
        with st.expander("Patch written by Nemotron (diff)"):
            st.code(patch["diff"], language="diff")
        st.download_button(
            "Download this patch (.diff)",
            data=patch["diff"],
            file_name=f"{by_id.get(fid, {}).get('cwe') or fid}.diff".replace(":", "_"),
            mime="text/plain",
            key=f"dl_{fid}",
        )

# ---------- 2b. public evidence (Tavily) ----------
with tab_evidence:
    st.markdown(
        "What execution cannot verify (no PoC for that class) is backed with **public evidence**: "
        "Tavily searches the web at runtime and Nemotron summarizes only what the sources support. "
        "This never changes the ScoreRisk number. Web results and summaries can differ between runs, "
        "which is exactly why this evidence is shown next to the score and never inside it."
    )
    enrichment = (run or {}).get("enrichment") or {}
    if not enrichment:
        st.info("This run has no public-evidence step. Set TAVILY_API_KEY and run `python megapatch.py`.")
    for fid, info in enrichment.items():
        finding = by_id.get(fid, {"title": fid})
        st.subheader(f"{fid}: {finding['title']}")
        if "skipped" in info or "error" in info:
            st.warning(f"Skipped: {info.get('skipped') or info.get('error')}")
            continue
        assessment = info.get("assessment")
        if assessment:
            shown = {"yes": "yes", "no": "no", "unclear": "not stated in sources"}
            c1, c2, c3 = st.columns(3)
            c1.metric("Exploited in the wild", shown[assessment["exploited_in_the_wild"]])
            c2.metric("Public exploit code", shown[assessment["public_exploit_code"]])
            c3.metric("Vendor fix available", shown[assessment["vendor_fix_available"]])
            st.markdown(assessment["summary"])
        else:
            st.write("No public sources found.")
        for i, source in enumerate(info.get("sources", []), 1):
            st.markdown(f"[{i}] [{source['title'] or source['url']}]({source['url']})")
        st.caption(f"Query: {info['query']}")

# ---------- 3. why ----------
with tab_why:
    st.markdown(
        """
**ScoreRisk is a rule, not a model.** `100 x (0.50 E + 0.30 X + 0.20 S)`

| Signal | Weight | Source | Question it answers |
|---|---|---|---|
| E, exploitability | 50% | EPSS, CISA KEV (floor 0.90 when listed) | Can someone exploit it today? |
| X, exposure | 30% | Asset context: internet, authentication, production, sensitive data | If exploited, how reachable and how bad? |
| S, severity | 20% | CVSS base score | How bad is the bug in itself? |

CVSS weighs little on purpose: over-weighting it is exactly what creates the noise.
The same input always produces the same ranking, so the number is auditable.
"""
    )
    st.markdown(
        f"""
**Action bands** (names borrowed from CISA's SSVC: Act, Attend, Track\\*, Track). This is a **simplified,
project-specific rule table, not CISA's decision tree**:

| Band | Rule | Meaning |
|---|---|---|
| Act | Exploit confirmed in the sandbox, or in KEV and internet-facing | Handle first |
| Attend | In KEV but internal, or EPSS at or above {EPSS_ATTEND:.2f} | Handle sooner than the normal cycle |
| Track\\* | Internet-facing with no exploitation evidence | Watch closely |
| Track | No strong signal | Normal patch cycle |

The EPSS threshold ({EPSS_ATTEND:.2f}) is a project parameter, not an SSVC value. A band is only as
reliable as its inputs, and asset exposure is declared in a fictional practice inventory.
"""
    )
    st.markdown(
        f"**Data snapshot:** fetched {threat['fetched_at'][:10]}, CISA KEV catalog "
        f"{threat['sources']['kev_catalog_version']} ({threat['sources']['kev_total']} entries). "
        "The findings are real scanner output (pip-audit over deliberately outdated pinned packages, "
        "Bandit over our practice app) and the CVE, EPSS, KEV and CVSS values are real. Which asset each "
        "finding belongs to and how exposed it is are declared assumptions of a fictional project, and the "
        "weights are starting points, not validated values."
    )
    if sensitivity:
        st.markdown(f"**Robustness check:** {sensitivity['configurations_tested']} weight/constant combinations")
        shown = {k: v for k, v in sensitivity.items() if isinstance(v, float)}
        st.table(pd.DataFrame({"Conclusion": list(shown), "Holds in": [f"{v:.0%}" for v in shown.values()]}))
        st.caption("This varies the weights, not the inputs: the exposure of each asset is still an assumption.")

# ---------- 4. reproduce ----------
with tab_repro:
    st.markdown(
        """
Verify the red to green claim yourself, with no API keys and no network:

```bash
git clone https://github.com/oryamx/megapatch
cd megapatch
pip install -r requirements.txt
python judge_check.py
```

Run the whole pipeline (needs Nebius Token Factory credentials and Sandboxes access):

```bash
python megapatch.py
```

**Runtime services:** NVIDIA Nemotron 3 Super through Nebius Token Factory writes the patches;
Nebius Token Factory Sandboxes run every exploit, test and model-written patch in isolation.
Live execution is not exposed in this public page, to protect the credits behind it.
"""
    )
    isolation_path = EVIDENCE / "isolation_check.json"
    if isolation_path.exists():
        isolation = json.loads(isolation_path.read_text(encoding="utf-8"))
        with st.expander("What the sandbox can see (observed, not promised)"):
            st.caption(
                f"Recorded {isolation['checked_at'][:10]} by `isolation_check.py`, inside the same sandbox the judge uses. "
                "Network egress is not blocked and code runs as root inside the VM; "
                "isolation here means nothing sensitive is placed in it."
            )
            for name, output in isolation["results"].items():
                st.markdown(f"**{name}**")
                st.code(output or "(empty)", language="text", wrap_lines=True)
