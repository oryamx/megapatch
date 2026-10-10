"""MegaPatch dashboard: the prioritized queue and the before/after evidence.

Run:  streamlit run dashboard.py
Reads the latest evidence/golden_run.json (or the newest evidence/run_*.json) and
re-computes ScoreRisk offline from the frozen threat-data snapshot. No API keys
needed, and nothing here calls a model or the sandbox.
"""
import json
import os
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

os.chdir(Path(__file__).resolve().parent)  # data/ and evidence/ are relative to this folder

from scorerisk import score_all  # noqa: E402

EVIDENCE = Path("evidence")

st.set_page_config(page_title="MegaPatch", layout="wide")


def latest_run_path():
    golden = EVIDENCE / "golden_run.json"
    if golden.exists():
        return golden
    runs = sorted(EVIDENCE.glob("run_*.json"))
    return runs[-1] if runs else None


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


@st.cache_data
def load():
    ranked, threat = score_all()
    path = latest_run_path()
    run = json.loads(path.read_text(encoding="utf-8")) if path else None
    sens_path = EVIDENCE / "sensitivity.json"
    sens = json.loads(sens_path.read_text(encoding="utf-8")) if sens_path.exists() else None
    return ranked, threat, run, path, sens


ranked, threat, run, run_path, sensitivity = load()
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
    st.caption(
        f"Run `{run_path.name}` on {run['executor']} with {run['model']}. "
        f"Top {run['top_n']} entered verification."
    )
else:
    st.info("No run found yet. Run `python megapatch.py` to create one.")

tab_queue, tab_proof, tab_evidence, tab_why, tab_repro = st.tabs(
    ["Priority queue", "Before / after", "Public evidence", "Why this order", "Reproduce it"]
)

# ---------- 1. queue ----------
with tab_queue:
    drop = max(ranked, key=lambda r: r["rank"] - r["cvss_rank"])
    # Biggest climb; on a tie prefer the lowest CVSS (the clearest "looks minor" example).
    rise = min(ranked, key=lambda r: (r["rank"] - r["cvss_rank"], r["cvss"]))
    left, right = st.columns(2)
    left.markdown(
        f"**Looks urgent, is not.** {drop['id']} has CVSS {drop['cvss']} "
        f"(#{drop['cvss_rank']} by severity) but ScoreRisk puts it at **#{drop['rank']}**: "
        f"EPSS {drop['epss']:.3f}, {'in' if drop['kev'] else 'not in'} CISA KEV, internal asset.  \n"
        f"_{drop['title']}_"
    )
    right.markdown(
        f"**Looks minor, is not.** {rise['id']} has CVSS {rise['cvss']} "
        f"(#{rise['cvss_rank']} by severity) but ScoreRisk puts it at **#{rise['rank']}**: "
        f"EPSS {rise['epss']:.3f}, {'in' if rise['kev'] else 'not in'} CISA KEV, internet-facing.  \n"
        f"_{rise['title']}_"
    )

    statuses = {}
    final_pos = {}
    if run:
        for item in run["final_order"]:
            statuses[item["id"]] = status_label(item["status"])
            final_pos[item["id"]] = item["position"]
    rows = []
    for r in sorted(ranked, key=lambda x: final_pos.get(x["id"], 1000 + x["rank"])):
        rows.append(
            {
                "Queue #": final_pos.get(r["id"], r["rank"]),
                "Finding": r["id"],
                "Title": r["title"],
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
        "Findings without a PoC are ranked but reported as not verifiable, never as safe."
    )

    chart_df = pd.DataFrame(
        [
            {
                "Finding": r["id"], "CVSS": r["cvss"], "ScoreRisk": r["pre_score"],
                "CISA KEV": "in KEV" if r["kev"] else "not in KEV", "Title": r["title"],
            }
            for r in ranked
        ]
    )
    base = alt.Chart(chart_df).encode(
        x=alt.X("CVSS:Q", scale=alt.Scale(domain=[7, 10.3]), title="CVSS base score (severity)"),
        y=alt.Y("ScoreRisk:Q", scale=alt.Scale(domain=[0, 108]), title="ScoreRisk (exploitability + exposure)"),
    )
    points = base.mark_circle(size=150).encode(
        color=alt.Color(
            "CISA KEV:N", scale=alt.Scale(domain=["in KEV", "not in KEV"], range=["#e8710a", "#4c78a8"])
        ),
        tooltip=["Finding", "Title", "CVSS", "ScoreRisk", "CISA KEV"],
    )
    # One label per cluster of overlapping points, so no label hides another.
    chart_df["cluster"] = list(zip(chart_df["CVSS"], (chart_df["ScoreRisk"] / 4).round()))
    label_df = (
        chart_df.groupby("cluster")
        .agg(CVSS=("CVSS", "first"), ScoreRisk=("ScoreRisk", "max"), Finding=("Finding", ", ".join))
        .reset_index(drop=True)
    )
    labels = (
        alt.Chart(label_df)
        .mark_text(dy=-14, fontSize=11)
        .encode(x="CVSS:Q", y="ScoreRisk:Q", text="Finding:N")
    )
    st.altair_chart((points + labels).properties(height=360), width="stretch")
    st.caption("Same CVSS, very different urgency: severity alone is the source of the noise.")

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
        f"**Data snapshot:** fetched {threat['fetched_at'][:10]}, CISA KEV catalog "
        f"{threat['sources']['kev_catalog_version']} ({threat['sources']['kev_total']} entries). "
        "CVE, EPSS, KEV and CVSS values are real. The inventory and the exposure of its assets are a "
        "fictional practice project, and the weights are starting points, not validated values."
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
