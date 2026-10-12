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
import time
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

os.chdir(Path(__file__).resolve().parent)  # data/ and evidence/ are relative to this folder

from bands import EPSS_ATTEND, band_for  # noqa: E402
from catalog import CLASSES, judge_fingerprint  # noqa: E402
from evidence_utils import describe_export  # noqa: E402
from scorerisk import FINGERPRINT_VERSION, fingerprint, score_all  # noqa: E402

EVIDENCE = Path("evidence")

st.set_page_config(page_title="MegaPatch", layout="wide")


def approvals_of(data):
    """How each patch of a run was approved, read from the data, never from the file name."""
    return [str(p.get("approval", "")) for p in data.get("patches", {}).values()]


def approval_kind(path):
    """Short label for the selector: 'human approval', 'automatic approval (--yes)' or 'mixed'."""
    try:
        approvals = approvals_of(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return "unreadable"
    if not approvals:
        return "no patches"
    if all(a.startswith("human") for a in approvals):
        return "human approval"
    if all(a.startswith("auto") for a in approvals):
        return "automatic approval (--yes)"
    if all(a.startswith("none") for a in approvals):
        return "no export decision (judge rejected)"
    return "mixed or unrecorded approval"


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
        "golden_run.json": "Recorded demo run",
        "run_with_repair.json": "Recorded run with a repaired patch",
        "human_approved_run.json": "Run approved by a person",
        "human_approved_run_b.json": "Recorded run with the current judge",
    }
    def title_of(p):
        if p.name in known:
            return known[p.name]
        if p.name.startswith("interactive_run_"):
            return "Interactive session " + p.stem.removeprefix("interactive_run_")
        return p.name

    names = {p: f"{title_of(p)} - {approval_kind(p)}" for p in options}
    return st.sidebar.selectbox("Run to display", options, format_func=lambda p: names[p])


def status_label(raw):
    if "export not approved" in raw:  # historic wording said "verified in the sandbox"
        return "Judge accepted it; the person declined to export"
    if "export pending" in raw:
        return "Judge accepted it; the export was never confirmed (the session stopped before finishing)"
    if "export FAILED" in raw:
        return "Judge accepted it; the export failed and was not recorded as exported"
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
    exported_ids = [i for i, p in run["patches"].items() if p.get("exported")]
    cols = st.columns(6)
    cols[0].metric("Findings ranked", len(ranked))
    cols[1].metric("Confirmed by exploit", len(confirmed), help="The exploit fired in the sandbox (practice app)")
    recorded_judge = run.get("judge_fingerprint") or "not recorded"
    cols[2].metric(
        "Accepted by judge", len(patched),
        help=f"Accepted by the judge version RECORDED IN THIS RUN (judge fingerprint: {recorded_judge}; "
        f"the current judge is {judge_fingerprint()}). The patch stopped the same exploit and the "
        "functional tests passed; the judge only covers what its PoCs and tests cover.",
    )
    cols[3].metric("Exported", len(exported_ids), help="Patches that were exported after the approval step of this run")
    cols[4].metric("Nemotron cost (est.)", f"${run['usage']['est_cost_usd']:.4f}")
    cols[5].metric("Machine time", f"{run['duration_s']:.0f} s")
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
    judge_now = judge_fingerprint()
    if run.get("judge_fingerprint") != judge_now:
        st.info(
            "**Judge version.** This run "
            + ("did not record which version of the judge produced it" if not run.get("judge_fingerprint")
               else "was judged with a different version of the PoCs and tests")
            + ". The path traversal check was strengthened afterwards to also catch an escape into a sibling "
            "directory whose name starts with `public` (a `startswith` comparison lets it through). "
            "Its patches were **not** re-judged inside this run, so read its path traversal verdict with that "
            f"in mind. Judge recorded in this run: `{run.get('judge_fingerprint') or 'not recorded'}`; "
            f"current judge: `{judge_now}`. A separate re-judge record, when present, is shown in the "
            "*Before / after* tab."
        )
    approvals = approvals_of(run)
    kinds = [describe_export(p)[0] for p in run["patches"].values()]
    exported, pending, failed = kinds.count("exported"), kinds.count("pending"), kinds.count("failed")
    if approvals and all(a.startswith("human") for a in approvals):
        # A pending or failed export was still approved by the person; it just did not finish.
        unfinished = (
            f" ({exported} exported, {pending} pending, {failed} failed)" if pending or failed else ""
        )
        st.success(
            f"**Human approval.** A person was asked about each patch the judge accepted before export: "
            f"{exported + pending + failed} of {len(approvals)} were approved{unfinished}. "
            "Model-written code ran automatically, but only inside the sandbox."
        )
    elif approvals and all(a.startswith("auto") for a in approvals):
        st.warning(
            "**Automatic approval (`--yes`).** This run does not show a person approving any patch; "
            "every question was skipped by the flag."
        )
    elif approvals and all(a.startswith("none") for a in approvals):
        st.info(
            "**No export decision.** The judge did not accept the patch, so no person was asked to approve "
            "anything and nothing was exported."
        )
    elif approvals:
        st.info("**Mixed or unrecorded approval.** Check the `approval` field of each patch below.")
else:
    st.info("No run found yet. Run `python megapatch.py` to create one.")

tab_queue, tab_proof, tab_evidence, tab_why, tab_repro, tab_live = st.tabs(
    ["Priority queue", "Before / after", "Public evidence", "Why this order", "Reproduce it", "Analyze (local)"]
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
def rejudge_records_for(path):
    """Separate re-judge records that cover the selected run (matched by the run's content hash)."""
    if path is None:
        return []
    run_hash = hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    found = []
    for record_path in sorted(EVIDENCE.glob("rejudge_*.json")):
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        mine = [r for r in record.get("results", []) if r.get("run_sha256") == run_hash]
        if mine:
            found.append((record_path, record, mine))
    return found


rejudge_records = rejudge_records_for(run_path)
flipped = {r["finding_id"] for _, _, mine in rejudge_records for r in mine if r.get("verdict_changed")}

with tab_proof:
    for record_path, record, mine in rejudge_records:
        with st.expander("Re-judged with a later judge (a separate record, NOT part of this run)", expanded=True):
            current = record.get("judge_fingerprint") == judge_fingerprint()
            st.markdown(
                f"`{record_path.name}` · judge `{record.get('judge_fingerprint')}` "
                f"({'matches the current judge' if current else 'made with an older judge version than the current one'}) · "
                f"sandbox: Python {record['sandbox_environment'].get('python')}, "
                f"Flask {record['sandbox_environment'].get('flask')}, "
                f"pytest {record['sandbox_environment'].get('pytest')}.  \n"
                "The patch stored in this run was rebuilt from its diff, applied to the current vulnerable app and "
                "judged again in the sandbox. This run itself was not modified, and nothing was exported."
            )
            st.table(
                pd.DataFrame(
                    [
                        {
                            "Finding": r["finding_id"],
                            "Judge in this run": "accepted" if r["original"]["accepted"] else "rejected",
                            "Later judge": "accepted" if r["rejudged"].get("accepted") else "REJECTED",
                            "Changed": "yes" if r.get("verdict_changed") else "no",
                            "Diff rebuilt exactly": "yes" if r.get("diff_roundtrip_ok") else "NO",
                        }
                        for r in mine
                    ]
                )
            )
            for r in mine:
                if r.get("verdict_changed"):
                    st.markdown(f"**{r['finding_id']}**: output of the later judge ({r['rejudged']['poc']}):")
                    st.code(r["rejudged"]["poc_output"], language="text", wrap_lines=True)
    if not run or not run["patches"]:
        st.info("No patched findings in this run.")
    for fid, patch in (run or {"patches": {}})["patches"].items():
        finding = by_id.get(fid, {"title": fid})
        accepted = patch.get("accepted")
        st.subheader(f"{fid}: {finding['title']}")
        approval = str(patch.get("approval") or "not recorded")
        # export_status decides when the record has it; exported=false alone is never read as a refusal.
        _, export_state = describe_export(patch)
        recorded_status = f" · export_status: {patch['export_status']}" if patch.get("export_status") else ""
        st.markdown(
            f"**Judge: {'patch accepted (red to green)' if accepted else 'patch not accepted'}** · "
            f"{export_state}  \n_approval field: {approval}{recorded_status}_"
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
        if fid in flipped:
            st.warning(
                "A later, stricter judge REJECTS this patch (see the re-judge record at the top of this tab). "
                "The 'SAFE' output below is what the judge of this run saw."
            )
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


# ---------- 6. interactive analysis (local opt-in) ----------
def _stage_lines(stages):
    """One line per stage: status, label, detail, duration. Rendered while the analysis runs."""
    marks = {"running": "running", "done": "done", "failed": "FAILED", "pending": "waiting for you"}
    lines = []
    for s in stages:
        took = ""
        if s.get("finished_at") and s.get("started_at"):
            took = f" ({s['finished_at'] - s['started_at']:.1f} s)"
        detail = f" - {s['detail']}" if s.get("detail") else ""
        lines.append(f"- **{marks.get(s['status'], s['status'])}** {s['label']}{detail}{took}")
    return "\n".join(lines) or "starting..."


def _decide(approve, ia_module, finding):
    """Callback of the two buttons: the ONLY place a person's decision is recorded."""
    from datetime import datetime, timezone

    state = st.session_state["ia"]
    result = state["result"]
    waited = time.time() - result.get("awaiting_since", time.time())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    st.session_state["ia_decision"] = ia_module.decide(
        result, approve, finding=finding, ranked=ranked, stamp=stamp, model=state["model"],
        usage=state["usage"],
        fingerprints={"inventory": fingerprint(), "version": FINGERPRINT_VERSION, "judge": judge_fingerprint()},
        human_wait_s=waited,
    )


def render_interactive(ia_module):
    rows = [r for r in ranked if r.get("cwe") in CLASSES]
    labels = {r["id"]: f"{r['title']}  [{r['id']}]" for r in rows}
    choice = st.selectbox("Finding to analyze", list(labels), format_func=labels.get, key="ia_choice")
    finding = next(r for r in rows if r["id"] == choice)
    st.caption(f"Judge version used for this analysis: `{judge_fingerprint()}`")

    if st.button("Run analysis in the sandbox", type="primary"):
        st.session_state.pop("ia_decision", None)
        box = st.status("Analysis in progress", expanded=True)
        view = box.empty()
        deps = ia_module.default_dependencies()
        calls_before = len(deps.usage_lines())
        started = time.time()
        result = ia_module.analyze(
            finding["cwe"], judge=deps.judge, generate=deps.generate, diff_of=deps.diff_of,
            read_candidate=deps.read_candidate, prepare=deps.prepare,
            notify=lambda stages: view.markdown(_stage_lines(stages)),
        )
        new_calls = deps.usage_lines()[calls_before:]
        usage = {
            "nemotron_calls": len(new_calls),
            "tokens": sum(c["prompt_tokens"] + c["completion_tokens"] for c in new_calls),
            "est_cost_usd": round(sum(c["est_cost_usd"] for c in new_calls), 6),
        }
        st.session_state["ia"] = {"result": result, "finding_id": finding["id"], "model": deps.model,
                                  "usage": usage, "elapsed": time.time() - started}
        box.update(
            label={"awaiting_approval": "Analysis finished: waiting for your decision",
                   "rejected_by_judge": "Analysis finished: the judge did not accept the patch",
                   "not_confirmed": "The exploit did not fire: nothing to fix",
                   "error": "The analysis stopped with an error"}[result["state"]],
            state="error" if result["state"] == "error" else "complete",
        )

    state = st.session_state.get("ia")
    if not state or state["finding_id"] != finding["id"]:
        return
    result = state["result"]
    st.markdown("**Progress**")
    st.markdown(_stage_lines(result["stages"]))
    if result.get("error"):
        st.error(result["error"])

    if result["before"] is not None:
        left, right = st.columns(2)
        left.markdown(f"**Before:** `{result['poc']}` on the vulnerable app (exit {result['before']['poc_exit']})")
        left.code(result["before"]["poc_output"], language="text", wrap_lines=True)
        if result["attempts"]:
            last = result["attempts"][-1]
            tail = ((last.get("tests_output") or "").strip().splitlines() or ["n/a"])[-1]
            right.markdown(
                f"**After:** the same `{result['poc']}` and the tests on the patched app "
                f"(PoC exit {last['poc_exit']}, tests exit {last['tests_exit']})"
            )
            right.code(f"{last['poc_output']}\n\ntests: {tail}", language="text", wrap_lines=True)
            st.code(last["diff"], language="diff")

    decision = st.session_state.get("ia_decision")
    if decision:
        if decision["exported"]:
            st.success(f"Approved and exported: `{decision['export_path']}`. Record: `{decision['evidence_path']}`.")
        else:
            st.info(f"Nothing was exported. Record: `{decision['evidence_path']}`.")
    elif result["state"] == "awaiting_approval":
        st.warning(
            "The judge accepted this patch, and **nothing has been exported**. Read the diff above; the export "
            "happens only if you approve it."
        )
        a, b = st.columns(2)
        a.button("Approve export of this patch", type="primary", on_click=_decide, args=(True, ia_module, finding))
        b.button("Reject (export nothing)", on_click=_decide, args=(False, ia_module, finding))
    elif result["state"] in ("rejected_by_judge", "not_confirmed", "error"):
        st.error("There is no patch to approve. Nothing was exported.")
        st.button("Save a record of this analysis (exports nothing)", on_click=_decide,
                  args=(False, ia_module, finding))


with tab_live:
    import interactive as ia

    st.markdown(
        "Run the loop on **one** finding from this page: confirm it with the exploit, let Nemotron write a "
        "patch, judge it with the **same** exploit and the tests, and decide whether to export it. "
        "Nothing is exported until you approve."
    )
    st.caption(
        "This tab is independent of the recorded run selected in the sidebar: it makes a new analysis of one finding."
    )
    st.caption(
        "Read this before trusting a result: the PoCs call the app in-process (Flask's test client), not over "
        "HTTP; the sandbox's outbound network is not blocked; and the judge only covers what its PoCs and tests "
        "cover, so 'accepted by the judge' does not mean 'safe in production'."
    )
    if not ia.is_enabled():
        st.info(
            "**Live runs are off here.** They spend model and sandbox credits, so they are a local opt-in: set "
            "`NEBIUS_API_KEY`, `NEBIUS_PROJECT_ID` and `MEGAPATCH_ENABLE_INTERACTIVE=1` in your own `.env` and "
            "run `streamlit run dashboard.py` on your machine. This public page only shows recorded runs."
        )
    else:
        render_interactive(ia)
