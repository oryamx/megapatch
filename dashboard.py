"""MegaPatch dashboard: the prioritized queue and the before/after evidence.

Run:  streamlit run dashboard.py
Opens on evidence/human_approved_run_b.json (the run made with the current judge, approved
by a person), falling back to golden_run.json, and re-computes ScoreRisk offline from the
frozen scanner outputs and threat-data snapshot. A sidebar selector lists the other
recorded runs, but only runs that describe the CURRENT inventory and scoring set-up (same
fingerprint; older files without one must have exactly the same finding ids). Incompatible
runs are hidden and exact duplicates are dropped.
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
from ingest import scanner_counts  # noqa: E402
from scorerisk import FINGERPRINT_VERSION, fingerprint, score_all  # noqa: E402

EVIDENCE = Path("evidence")
# The page opens on the first of these that exists: the run made with the current judge and approved
# by a person tells the whole story without caveats about an older judge or automatic approval.
DEFAULT_RUNS = ("human_approved_run_b.json", "golden_run.json")

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
    """The first of DEFAULT_RUNS by default; a sidebar selector appears only when other
    compatible, distinct runs exist. Incompatible runs are hidden, not mixed in; exact
    duplicates of an earlier option are dropped."""
    first = [EVIDENCE / name for name in DEFAULT_RUNS if (EVIDENCE / name).exists()]
    others = sorted((p for p in EVIDENCE.glob("*run*.json") if p not in first), reverse=True)
    found = first + others
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
    if raw.startswith("not verified (outside top N)"):
        return "Ranked, outside verification budget"
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
    return ranked, threat, run, path, sens, scanner_counts()


ranked, threat, run, run_path, sensitivity, counts = load(run_signature())
by_id = {r["id"]: r for r in ranked}

st.title("MegaPatch")
st.caption(
    "Rank what matters, prove it is exploitable by running the exploit, patch it, "
    "and re-run the same exploit. The score proposes; execution disposes."
)

# ---------- the loop at a glance: what a first-time visitor needs before any table ----------
n_kev_cves = len({r["cve"] for r in ranked if r["kev"]})


def story_steps(run):
    """The five steps of the loop as short headlines, plus one line of detail, all from the selected run.
    Headlines stay short so five columns remain legible on a laptop; the numbers go in the detail line."""
    funnel = (
        f"{counts['pip_audit_entries']} pip-audit entries and {counts['bandit_results']} Bandit results became "
        f"{counts['findings']} distinct findings ({counts['unique_cves']} unique CVEs, {n_kev_cves} in CISA KEV)."
    )
    if not run:
        return [("Prioritize", f"**{counts['findings']} findings** ranked by ScoreRisk")], funnel
    verdicts = run["verdicts"]
    confirmed = sum(1 for v in verdicts.values() if v["verdict"] == "CONFIRMED")
    unverifiable = sum(1 for v in verdicts.values() if v["verdict"] == "NOT_VERIFIABLE")
    patches = list(run["patches"].values())
    accepted = sum(1 for p in patches if p.get("accepted"))
    repaired = sum(1 for p in patches if p.get("accepted") and p.get("attempts", 1) > 1)
    approvals = approvals_of(run)
    kinds = [describe_export(p)[0] for p in patches]
    if approvals and all(a.startswith("human") for a in approvals):
        approved = sum(1 for k in kinds if k in ("exported", "pending", "failed"))
        last = f"**{approved} of {len(approvals)} approved** by a person before export"
    elif approvals and all(a.startswith("auto") for a in approvals):
        last = "**Automatic (`--yes`)**: no person approved these exports"
    elif approvals:
        last = "Mixed or unrecorded approval: see each patch in the *Walkthrough* tab"
    else:
        last = "No patch reached the approval step"
    usage = run["usage"]
    steps = [
        ("Prioritize", f"**{counts['findings']} findings** ranked by ScoreRisk; the top {run['top_n']} verified"),
        ("Prove", f"**{confirmed} confirmed** by an exploit in a Nebius sandbox"),
        ("Patch", f"**{len(patches)} patch(es)** written by NVIDIA Nemotron on Nebius Token Factory"),
        ("Re-test", f"Same PoC and tests: **{accepted} accepted**"
                    + (f" ({repaired} after one repair)" if repaired else "")
                    + f", {len(patches) - accepted} rejected"),
        ("Approve", last),
    ]
    detail = (
        f"{funnel} Of the top {run['top_n']}, {unverifiable} have no PoC and are reported as not verifiable, "
        f"never as safe. Patches by `{run['model']}`: {usage['nemotron_calls']} calls, about "
        f"${usage['est_cost_usd']:.4f}."
    )
    return steps, detail


steps, story_detail = story_steps(run)
for column, (number, (title, text)) in zip(st.columns(len(steps)), enumerate(steps, 1)):
    column.markdown(f"**{number} · {title}**  \n{text}")
st.caption(story_detail)
st.caption(
    "Recorded runs on our own practice app, not real-world code. The PoCs call the app in-process (Flask's test "
    "client) inside the sandbox, whose outbound network is not blocked. \"Accepted by the judge\" means the same "
    "PoC and the functional tests passed, not \"safe in production\". The *Walkthrough* tab follows one finding "
    "through all five steps."
)
with st.expander("What you are looking at, and what it does not show"):
    st.markdown(
        f"""
- **Input:** real scanner output on deliberately chosen input. pip-audit over {counts['pip_audit_packages']}
  outdated pinned packages reported {counts['pip_audit_entries']} entries, {counts['pip_audit_findings']} distinct
  advisories once repeats are removed. Bandit over our practice app reported {counts['bandit_results']} results,
  kept as {counts['bandit_findings']} findings (one per class we can verify), and {counts['manual_findings']} finding
  comes from manual review. Total: {counts['findings']} distinct findings, {counts['unique_cves']} unique CVEs,
  {n_kev_cves} of them in CISA KEV.
- **Declared, not discovered:** which asset each finding belongs to and how exposed it is (a fictional inventory).
- **Verifiable by execution:** three vulnerability classes, only in our own practice app. Everything else is
  ranked and reported as not verifiable, never as safe.
- **The PoCs run in-process** inside the sandbox; they do not test network reachability.
- **Isolation means no secrets and not our machine:** the sandbox's outbound network is not blocked and code runs
  as root inside it.
- **Approval:** runs made with `--yes` skipped every human approval question. Each run's banner says which kind it
  is, read from its own data.
- **Not measured:** there is no precision figure for the ranking.
"""
    )

# ---------- headline numbers ----------
if run:
    verdicts = run["verdicts"]
    confirmed = [i for i, v in verdicts.items() if v["verdict"] == "CONFIRMED"]
    patched = [i for i, p in run["patches"].items() if p.get("accepted")]
    exported_ids = [i for i, p in run["patches"].items() if p.get("exported")]
    cols = st.columns(6)
    cols[0].metric("Findings ranked", len(ranked))
    cols[1].metric("Confirmed", len(confirmed), help="Confirmed by exploit: the PoC fired in the sandbox (practice app)")
    recorded_judge = run.get("judge_fingerprint") or "not recorded"
    cols[2].metric(
        "Judge accepted", len(patched),
        help=f"Accepted by the judge version RECORDED IN THIS RUN (judge fingerprint: {recorded_judge}; "
        f"the current judge is {judge_fingerprint()}). The patch stopped the same exploit and the "
        "functional tests passed; the judge only covers what its PoCs and tests cover.",
    )
    cols[3].metric("Exported", len(exported_ids), help="Patches that were exported after the approval step of this run")
    cols[4].metric("Nemotron cost", f"${run['usage']['est_cost_usd']:.4f}",
                   help="Estimated from the token counts of this run's Nemotron calls")
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

tab_walk, tab_queue, tab_proof, tab_evidence, tab_why, tab_repro, tab_live = st.tabs(
    ["Walkthrough", "Priority queue", "Before / after", "Public evidence", "Why this order", "Reproduce it",
     "Analyze (local)"]
)

# ---------- 0. one finding, end to end ----------
with tab_walk:
    if not run or not run["patches"]:
        st.info("This run has no patched finding to follow. Pick another run in the sidebar.")
    else:
        followed = [i["id"] for i in run["final_order"] if i["id"] in run["patches"]]
        fid = st.selectbox(
            "Follow one finding through the loop", followed, key="walk_choice",
            format_func=lambda i: f"{i}: {by_id.get(i, {}).get('title', i)}",
        )
        r, patch = by_id.get(fid, {}), run["patches"][fid]
        poc = CLASSES[r["cwe"]]["poc"] if r.get("cwe") in CLASSES else "the PoC"
        verdict = run["verdicts"].get(fid, {})
        band, basis = band_for(r, verdict.get("verdict")) if r else ("n/a", "")
        cvss = f"{r['cvss']}" if r.get("cvss") is not None else "n/a (code finding)"

        st.markdown("##### Step 1 · Prioritized by ScoreRisk (a rule, not a model)")
        st.markdown(
            f"ScoreRisk rank **#{r.get('rank', '?')} of {len(ranked)}** (score {r.get('pre_score', '?')}), band "
            f"**{band}**: {basis}. Source: {r.get('scanner', 'n/a')}. CVSS {cvss}; "
            f"{'in' if r.get('kev') else 'not in'} CISA KEV; asset "
            f"{'internet-facing' if r.get('internet_facing') else 'internal'} (declared)."
        )
        st.markdown(f"##### Step 2 · Proven by execution: `{poc}` against the vulnerable app, in the sandbox")
        st.caption(f"Verdict: **{verdict.get('verdict', 'n/a')}** (exit 1 means the exploit fired).")
        st.code(verdict.get("evidence", ""), language="text", wrap_lines=True)

        st.markdown("##### Step 3 · Patched by Nemotron")
        history = patch.get("attempt_history", [])
        st.caption(
            f"`{run['model']}` through Nebius Token Factory. "
            + (f"Attempt 1 was rejected by the judge; its output went back to the model, which wrote attempt "
               f"{patch.get('attempts')}. The *Before / after* tab shows the rejected attempt."
               if history else "Accepted at the first attempt." if patch.get("accepted") else "")
        )
        st.code(patch["diff"], language="diff")

        st.markdown(f"##### Step 4 · Re-tested with the same `{poc}` and the functional tests")
        tests_tail = ((patch.get("tests_output") or "").strip().splitlines() or ["n/a"])[-1]
        st.code(f"{patch.get('poc_output') or ''}\n\ntests: {tests_tail}", language="text", wrap_lines=True)
        st.caption(
            ("Accepted: the PoC no longer fires (exit 0) and the functional tests pass (exit 0)."
             if patch.get("accepted") else
             f"Rejected: PoC exit {patch.get('poc_exit')}, tests exit {patch.get('tests_exit')}.")
            + " The judge only covers what its PoC and tests cover."
            + ("" if run.get("judge_fingerprint") == judge_fingerprint() else
               " This run was judged by an older version of the judge (see the note at the top).")
        )

        st.markdown("##### Step 5 · Approval before export")
        _, export_text = describe_export(patch)
        st.markdown(f"{export_text[:1].upper()}{export_text[1:]}.  \n_approval field: {patch.get('approval', 'n/a')}_")

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
                "Id": r["id"],
                "Finding": r["title"],
                "Status": statuses.get(r["id"], "Ranked, outside verification budget"),
                "Band": band,
                "Basis for the band": basis,
                "ScoreRisk": r["pre_score"],
                "ScoreRisk rank": r["rank"],
                "CVSS": f"{r['cvss']:.1f}" if r["cvss"] is not None else "n/a",
                "CVSS rank": r["cvss_rank"],
                "In KEV": "yes" if r["kev"] else "no",
                "EPSS": f"{r['epss']:.3f}" if r["epss"] is not None else "n/a",  # code findings have no CVE
            }
        )
    df = pd.DataFrame(rows)
    # Fixed widths that add up to under 800 px, so every column is visible on a 1280 px desktop with the
    # sidebar open; the long columns (ids, band basis, both ranks) are in the full table below.
    queue_columns = {
        "Queue #": st.column_config.NumberColumn("#", width=40, help="Position in the final queue"),
        "Finding": st.column_config.TextColumn("Finding", width=220),
        "Status": st.column_config.TextColumn("Status", width=240),
        "Band": st.column_config.TextColumn("Band", width=60, help="Simplified, SSVC-inspired; basis in the full table"),
        "ScoreRisk": st.column_config.ProgressColumn("ScoreRisk", min_value=0, max_value=100, format="%.1f", width=86),
        "CVSS": st.column_config.TextColumn("CVSS", width=50),
        "In KEV": st.column_config.TextColumn("KEV", width=44, help="Listed in CISA's Known Exploited Vulnerabilities catalog"),
        "EPSS": st.column_config.TextColumn("EPSS", width=56),
    }
    st.dataframe(df[list(queue_columns)], hide_index=True, column_config=queue_columns)
    with st.expander("Full table: finding ids, the basis of each band, and both ranks"):
        full_columns = {
            "Queue #": st.column_config.NumberColumn("#", width=40),
            "Id": st.column_config.TextColumn("Id", width=190),
            "Band": st.column_config.TextColumn("Band", width=60),
            "Basis for the band": st.column_config.TextColumn("Basis for the band", width=330),
            "ScoreRisk rank": st.column_config.NumberColumn("ScoreRisk rank", width=90),
            "CVSS rank": st.column_config.NumberColumn("CVSS rank", width=90),
        }
        st.dataframe(df[list(full_columns)], hide_index=True, column_config=full_columns)
    st.caption(
        "Confirmed findings jump to the top of the queue regardless of their pre-score. "
        "Findings without a PoC are ranked but reported as not verifiable, never as safe. "
        "Bands are a simplified mapping inspired by CISA's SSVC, not the official decision tree; "
        "asset exposure is declared in a fictional practice inventory."
    )

    def short_label(r):
        head, _, tail = r["id"].partition(":")
        return head if r["scanner"].startswith("pip-audit") else tail

    # Label only the findings this page talks about: the ones a PoC can verify, the KEV-listed one that rises
    # and the critical-looking one that drops. Every other dot keeps its details in the tooltip and the table.
    story_ids = {r["id"] for r in ranked if r.get("cwe") in CLASSES} | {drop["id"], rise["id"]}
    chart_df = pd.DataFrame(
        [
            {
                "Finding": r["id"], "CVSS": r["cvss"], "ScoreRisk": r["pre_score"], "Rank": r["rank"],
                "Tag": f"#{r['rank']} {short_label(r)}" + (" (in KEV)" if r["kev"] else ""),
                "Story": r["id"] in story_ids,
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
            "CISA KEV:N", scale=alt.Scale(domain=["in KEV", "not in KEV"], range=["#e8710a", "#4c78a8"]),
            legend=alt.Legend(orient="top", title=None),  # on top, so a narrow screen keeps the full plot width
        ),
        tooltip=["Finding", "Title", "CVSS", "ScoreRisk", alt.Tooltip("Rank:Q", title="ScoreRisk rank"), "CISA KEV"],
    )
    # Findings at the same point share one label. Labels sit beside their dot, never on it: to its left in the
    # right half of the chart (where the plot edge is close), to its right otherwise.
    label_df = (
        chart_df[chart_df["Story"]].sort_values("Rank")
        .groupby(["CVSS", "ScoreRisk"], sort=False)
        .agg(Label=("Tag", ", ".join))
        .reset_index()
    )

    def label_layer(data, align, dx):
        return (
            alt.Chart(data)
            .mark_text(align=align, dx=dx, baseline="middle", fontSize=11)
            .encode(x="CVSS:Q", y="ScoreRisk:Q", text="Label:N")
        )

    layers = [points]
    for side, align, dx in ((label_df["CVSS"] >= 6, "right", -9), (label_df["CVSS"] < 6, "left", 9)):
        if side.any():
            layers.append(label_layer(label_df[side], align, dx))
    st.altair_chart(alt.layer(*layers).properties(height=380), width="stretch")
    st.caption(
        "Each dot is a finding. Severity alone (left to right) says little about urgency (bottom to top); "
        "most of the scanner's output sits low on the vertical axis. Labels show the findings discussed on this "
        "page with their ScoreRisk rank; hover any dot for its details."
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
Verify the red to green claim yourself, with no API keys (the network is only needed to install the packages):

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
