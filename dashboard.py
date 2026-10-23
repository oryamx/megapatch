"""MegaPatch dashboard: the prioritized queue and the before/after evidence.

Run:  streamlit run dashboard.py --server.address 127.0.0.1
      streamlit run dashboard.py --server.address 127.0.0.1 -- --local-scan   (also scan a Python repository of this machine)
The address only limits incoming connections (the page answers on this machine only); it does not stop the
outgoing requests a local scan makes (see repo_scan.py).
Opens on evidence/human_approved_run_b.json (the run made with the current judge, approved
by a person), falling back to golden_run.json, and re-computes ScoreRisk offline from the
frozen scanner outputs and threat-data snapshot. A sidebar selector lists the other
recorded runs, but only runs that describe the CURRENT inventory and scoring set-up (same
fingerprint; older files without one must have exactly the same finding ids). Incompatible
runs are hidden and exact duplicates are dropped.
No API keys needed, and nothing here calls a model or the sandbox.

The interface is in English or Spanish (sidebar selector, English first). Every text comes from
ui_text.py; the language never changes data, scores or results.
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
import scan_view  # noqa: E402
from ui_text import (  # noqa: E402
    LANGS, QUICKSTART_COMMANDS, QUICKSTART_STEPS, band_basis, data_label, export_text, stage_label, status_label, tr,
)

EVIDENCE = Path("evidence")
# The page opens on the first of these that exists: the run made with the current judge and approved
# by a person tells the whole story without caveats about an older judge or automatic approval.
DEFAULT_RUNS = ("human_approved_run_b.json", "golden_run.json")

st.set_page_config(page_title="MegaPatch", layout="wide")

# The language only changes words. Its label is the same in both languages, so switching never resets it.
lang = st.sidebar.radio(tr("en", "lang_label"), list(LANGS), format_func=LANGS.get, horizontal=True, key="lang")


def t(key, **values):
    return tr(lang, key, **values)


local_scan = scan_view.local_scan_status()
if local_scan == "on":
    st.sidebar.info(t("rp_sidebar_on"))
elif local_scan != "off":  # asked for, but refused (see scan_view.local_scan_status)
    st.sidebar.error(t("rp_sidebar_refused"))


def remembered_index(options, memory_key, name_of=lambda option: option):
    """Index of the option chosen before (kept in session state), so a selector whose label changes with
    the language keeps its choice instead of resetting."""
    previous = st.session_state.get(memory_key)
    return next((i for i, option in enumerate(options) if name_of(option) == previous), 0)


def approvals_of(data):
    """How each patch of a run was approved, read from the data, never from the file name."""
    return [str(p.get("approval", "")) for p in data.get("patches", {}).values()]


def approval_kind(path):
    """Kind of approval for the selector, read from the run's data."""
    try:
        approvals = approvals_of(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return "unreadable"
    if not approvals:
        return "no_patches"
    if all(a.startswith("human") for a in approvals):
        return "human"
    if all(a.startswith("auto") for a in approvals):
        return "auto"
    if all(a.startswith("none") for a in approvals):
        return "none"
    return "mixed"


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
        st.sidebar.caption(t("hidden_runs", n=hidden))
    if not options:
        return None
    if len(options) == 1:
        return options[0]
    known = {
        "golden_run.json": "run_golden",
        "run_with_repair.json": "run_repair",
        "human_approved_run.json": "run_human",
        "human_approved_run_b.json": "run_b",
    }

    def title_of(p):
        if p.name in known:
            return t(known[p.name])
        if p.name.startswith("interactive_run_"):
            return t("run_session", sid=p.stem.removeprefix("interactive_run_"))
        return p.name

    names = {p: f"{title_of(p)} - {t('kind_' + approval_kind(p))}" for p in options}
    choice = st.sidebar.selectbox(
        t("run_to_display"), options, index=remembered_index(options, "run_selected", lambda p: p.name),
        format_func=lambda p: names[p], key=f"run_choice_{lang}",
    )
    st.session_state["run_selected"] = choice.name
    return choice


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
st.caption(t("tagline"))
if run_path is not None:
    st.info(t("recorded_notice", file=run_path.name))

# ---------- how to use: what the team brings, what MegaPatch does and produces, what a person reviews ----------
with st.expander(t("howto_title"), expanded=True):
    top_left, top_right = st.columns(2)
    top_left.markdown(t("howto_provides"))
    top_right.markdown(t("howto_does"))
    bottom_left, bottom_right = st.columns(2)
    bottom_left.markdown(t("howto_produces"))
    bottom_right.markdown(t("howto_review"))
    # Quick start: the explanation follows the language; the commands are shown exactly as they must be typed.
    st.markdown(t("qs_title"))
    st.warning(t("qs_scope"))
    for step in QUICKSTART_STEPS:
        st.markdown(t(step))
        if step in QUICKSTART_COMMANDS:
            st.code(QUICKSTART_COMMANDS[step], language="bash")

# ---------- the loop at a glance: what a first-time visitor needs before any table ----------
n_kev_cves = len({r["cve"] for r in ranked if r["kev"]})


def story_steps(run):
    """The five steps of the loop as short headlines, plus one line of detail, all from the selected run.
    Headlines stay short so five columns remain legible on a laptop; the numbers go in the detail line."""
    funnel = t("funnel", pip=counts["pip_audit_entries"], bandit=counts["bandit_results"],
               findings=counts["findings"], cves=counts["unique_cves"], kev=n_kev_cves)
    if not run:
        return [(t("step_prioritize"), t("s_prioritize_norun", findings=counts["findings"]))], funnel
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
        last = t("s_approve_human", a=approved, b=len(approvals))
    elif approvals and all(a.startswith("auto") for a in approvals):
        last = t("s_approve_auto")
    elif approvals:
        last = t("s_approve_mixed")
    else:
        last = t("s_approve_none")
    usage = run["usage"]
    steps = [
        (t("step_prioritize"), t("s_prioritize", findings=counts["findings"], top=run["top_n"])),
        (t("step_prove"), t("s_prove", n=confirmed)),
        (t("step_patch"), t("s_patch", n=len(patches))),
        (t("step_retest"), t("s_retest_head", n=accepted)
         + (t("s_retest_repair", n=repaired) if repaired else "")
         + t("s_retest_tail", n=len(patches) - accepted)),
        (t("step_approve"), last),
    ]
    detail = t("story_detail", funnel=funnel, top=run["top_n"], unv=unverifiable, model=run["model"],
               calls=usage["nemotron_calls"], cost=f"{usage['est_cost_usd']:.4f}")
    return steps, detail


steps, story_detail = story_steps(run)
for column, (number, (title, text)) in zip(st.columns(len(steps)), enumerate(steps, 1)):
    column.markdown(f"**{number} · {title}**  \n{text}")
st.caption(story_detail)
st.caption(t("limits_caption"))
with st.expander(t("limits_title")):
    st.markdown(
        t("limits_body", pkgs=counts["pip_audit_packages"], pip=counts["pip_audit_entries"],
          advisories=counts["pip_audit_findings"], bandit=counts["bandit_results"],
          bandit_findings=counts["bandit_findings"], manual=counts["manual_findings"], findings=counts["findings"],
          cves=counts["unique_cves"], kev=n_kev_cves)
    )

# ---------- headline numbers ----------
if run:
    verdicts = run["verdicts"]
    confirmed = [i for i, v in verdicts.items() if v["verdict"] == "CONFIRMED"]
    patched = [i for i, p in run["patches"].items() if p.get("accepted")]
    exported_ids = [i for i, p in run["patches"].items() if p.get("exported")]
    cols = st.columns(6)
    cols[0].metric(t("m_findings"), len(ranked))
    cols[1].metric(t("m_confirmed"), len(confirmed), help=t("m_confirmed_help"))
    recorded_judge = run.get("judge_fingerprint") or t("not_recorded")
    cols[2].metric(t("m_accepted"), len(patched), help=t("m_accepted_help", rec=recorded_judge, now=judge_fingerprint()))
    cols[3].metric(t("m_exported"), len(exported_ids), help=t("m_exported_help"))
    cols[4].metric(t("m_cost"), f"${run['usage']['est_cost_usd']:.4f}", help=t("m_cost_help"))
    cols[5].metric(t("m_time"), f"{run['duration_s']:.0f} s")
    legacy = "" if run.get("fingerprint_version") == FINGERPRINT_VERSION else t("legacy")
    st.caption(t("run_caption", file=run_path.name, executor=data_label(run["executor"], lang), model=run["model"],
                 top=run["top_n"], legacy=legacy))
    judge_now = judge_fingerprint()
    if run.get("judge_fingerprint") != judge_now:
        what = t("judge_what_missing") if not run.get("judge_fingerprint") else t("judge_what_other")
        st.info(t("judge_note", what=what, rec=run.get("judge_fingerprint") or t("not_recorded"), now=judge_now))
    approvals = approvals_of(run)
    kinds = [describe_export(p)[0] for p in run["patches"].values()]
    exported, pending, failed = kinds.count("exported"), kinds.count("pending"), kinds.count("failed")
    if approvals and all(a.startswith("human") for a in approvals):
        # A pending or failed export was still approved by the person; it just did not finish.
        unfinished = t("banner_unfinished", e=exported, p=pending, f=failed) if pending or failed else ""
        st.success(t("banner_human", approved=exported + pending + failed, total=len(approvals), unfinished=unfinished))
    elif approvals and all(a.startswith("auto") for a in approvals):
        st.warning(t("banner_auto"))
    elif approvals and all(a.startswith("none") for a in approvals):
        st.info(t("banner_none"))
    elif approvals:
        st.info(t("banner_mixed"))
else:
    st.info(t("no_run"))

tab_walk, tab_queue, tab_proof, tab_evidence, tab_why, tab_repro, tab_repo, tab_live = st.tabs(
    [t("tab_walk"), t("tab_queue"), t("tab_proof"), t("tab_evidence"), t("tab_why"), t("tab_repro"), t("tab_repo"),
     t("tab_live")]
)

# ---------- 0. one finding, end to end ----------
with tab_walk:
    if not run or not run["patches"]:
        st.info(t("walk_none"))
    else:
        followed = [i["id"] for i in run["final_order"] if i["id"] in run["patches"]]
        fid = st.selectbox(
            t("walk_select"), followed, index=remembered_index(followed, "walk_selected"),
            key="walk_choice" if lang == "en" else f"walk_choice_{lang}",
            format_func=lambda i: f"{i}: {by_id.get(i, {}).get('title', i)}",
        )
        st.session_state["walk_selected"] = fid
        r, patch = by_id.get(fid, {}), run["patches"][fid]
        poc = CLASSES[r["cwe"]]["poc"] if r.get("cwe") in CLASSES else t("the_poc")
        verdict = run["verdicts"].get(fid, {})
        band, basis = band_for(r, verdict.get("verdict")) if r else ("n/a", "")
        cvss = f"{r['cvss']}" if r.get("cvss") is not None else t("cvss_code")

        st.markdown(t("step1_h"))
        st.markdown(
            t("step1_body", rank=r.get("rank", "?"), total=len(ranked), score=r.get("pre_score", "?"), band=band,
              basis=band_basis(basis, lang), source=data_label(r.get("scanner", "n/a"), lang), cvss=cvss,
              kev=t("in_kev") if r.get("kev") else t("not_in_kev"),
              exposure=t("internet_facing") if r.get("internet_facing") else t("internal"))
        )
        st.markdown(t("step2_h", poc=poc))
        st.caption(t("verdict_caption", v=verdict.get("verdict", "n/a")))
        st.code(verdict.get("evidence", ""), language="text", wrap_lines=True)

        st.markdown(t("step3_h"))
        history = patch.get("attempt_history", [])
        st.caption(
            t("step3_via", model=run["model"])
            + (t("step3_repaired", n=patch.get("attempts")) if history
               else t("step3_first") if patch.get("accepted") else "")
        )
        st.code(patch["diff"], language="diff")

        st.markdown(t("step4_h", poc=poc))
        tests_tail = ((patch.get("tests_output") or "").strip().splitlines() or ["n/a"])[-1]
        st.code(f"{patch.get('poc_output') or ''}\n\ntests: {tests_tail}", language="text", wrap_lines=True)
        st.caption(
            (t("step4_accepted") if patch.get("accepted")
             else t("step4_rejected", pe=patch.get("poc_exit"), te=patch.get("tests_exit")))
            + t("step4_coverage")
            + ("" if run.get("judge_fingerprint") == judge_fingerprint() else t("step4_older"))
        )

        st.markdown(t("step5_h"))
        export_state = export_text(patch, lang)
        st.markdown(f"{export_state[:1].upper()}{export_state[1:]}.  \n"
                    f"_{t('approval_field')}: {patch.get('approval', 'n/a')}_")

# ---------- 1. queue ----------
with tab_queue:
    # The two contrast cases, chosen by rule so the page never needs hand-picking:
    # the critical-looking finding ScoreRisk ranks lowest, and the lower-CVSS finding in KEV it ranks highest.
    critical = [r for r in ranked if (r["cvss"] or 0) >= 9.0]
    minor_but_kev = [r for r in ranked if r["kev"] and (r["cvss"] is None or r["cvss"] < 9.0)]
    drop = max(critical, key=lambda r: r["rank"]) if critical else ranked[-1]
    rise = min(minor_but_kev, key=lambda r: r["rank"]) if minor_but_kev else ranked[0]

    def describe(r):
        where = t("where_internet") if r["internet_facing"] else t("where_internal")
        epss = f"{r['epss']:.3f}" if r["epss"] is not None else "n/a"
        return t("describe", epss=epss, kev=t("in_kev") if r["kev"] else t("not_in_kev"), where=where)

    n_cves = len({r["cve"] for r in ranked if r["cve"]})
    n_kev = len({r["cve"] for r in ranked if r["kev"]})
    n_rare = len({r["cve"] for r in ranked if r["cve"] and r["epss"] is not None and r["epss"] < 0.05})
    st.markdown(t("queue_summary", n=len(ranked), cves=n_cves, kev=n_kev,
                  verb=t("verb_is") if n_kev == 1 else t("verb_are"), rare=n_rare))
    left, right = st.columns(2)
    left.markdown(t("looks_urgent", title=drop["title"], cvss=drop["cvss"], crank=drop["cvss_rank"],
                    rank=drop["rank"], desc=describe(drop)))
    right.markdown(t("looks_minor", title=rise["title"], cvss=rise["cvss"], crank=rise["cvss_rank"],
                     rank=rise["rank"], desc=describe(rise)))

    statuses = {}
    final_pos = {}
    if run:
        for item in run["final_order"]:
            statuses[item["id"]] = status_label(item["status"], lang)
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
                "Status": statuses.get(r["id"], t("st_outside_budget")),
                "Band": band,
                "Basis for the band": band_basis(basis, lang),
                "ScoreRisk": r["pre_score"],
                "ScoreRisk rank": r["rank"],
                "CVSS": f"{r['cvss']:.1f}" if r["cvss"] is not None else "n/a",
                "CVSS rank": r["cvss_rank"],
                "In KEV": t("yes") if r["kev"] else t("no"),
                "EPSS": f"{r['epss']:.3f}" if r["epss"] is not None else "n/a",  # code findings have no CVE
            }
        )
    df = pd.DataFrame(rows)
    # Fixed widths that add up to under 800 px, so every column is visible on a 1280 px desktop with the
    # sidebar open; the long columns (ids, band basis, both ranks) are in the full table below.
    queue_columns = {
        "Queue #": st.column_config.NumberColumn("#", width=40, help=t("col_queue_help")),
        "Finding": st.column_config.TextColumn(t("col_finding"), width=220),
        "Status": st.column_config.TextColumn(t("col_status"), width=240),
        "Band": st.column_config.TextColumn(t("col_band"), width=60, help=t("col_band_help")),
        "ScoreRisk": st.column_config.ProgressColumn("ScoreRisk", min_value=0, max_value=100, format="%.1f", width=86),
        "CVSS": st.column_config.TextColumn("CVSS", width=50),
        "In KEV": st.column_config.TextColumn("KEV", width=44, help=t("col_kev_help")),
        "EPSS": st.column_config.TextColumn("EPSS", width=56),
    }
    st.dataframe(df[list(queue_columns)], hide_index=True, column_config=queue_columns)
    with st.expander(t("full_table")):
        full_columns = {
            "Queue #": st.column_config.NumberColumn("#", width=40),
            "Id": st.column_config.TextColumn("Id", width=190),
            "Band": st.column_config.TextColumn(t("col_band"), width=60),
            "Basis for the band": st.column_config.TextColumn(t("col_basis"), width=330),
            "ScoreRisk rank": st.column_config.NumberColumn(t("col_rank"), width=90),
            "CVSS rank": st.column_config.NumberColumn(t("col_cvss_rank"), width=90),
        }
        st.dataframe(df[list(full_columns)], hide_index=True, column_config=full_columns)
    st.caption(t("queue_caption"))

    def short_label(r):
        head, _, tail = r["id"].partition(":")
        return head if r["scanner"].startswith("pip-audit") else tail

    # Label only the findings this page talks about: the ones a PoC can verify, the KEV-listed one that rises
    # and the critical-looking one that drops. Every other dot keeps its details in the tooltip and the table.
    story_ids = {r["id"] for r in ranked if r.get("cwe") in CLASSES} | {drop["id"], rise["id"]}
    kev_in, kev_out = t("legend_kev"), t("legend_not_kev")
    chart_df = pd.DataFrame(
        [
            {
                "Finding": r["id"], "CVSS": r["cvss"], "ScoreRisk": r["pre_score"], "Rank": r["rank"],
                "Tag": f"#{r['rank']} {short_label(r)}" + (t("tag_kev") if r["kev"] else ""),
                "Story": r["id"] in story_ids,
                "CISA KEV": kev_in if r["kev"] else kev_out, "Title": r["title"],
            }
            for r in ranked
            if r["cvss"] is not None
        ]
    )
    base = alt.Chart(chart_df).encode(
        x=alt.X("CVSS:Q", scale=alt.Scale(domain=[2, 10.4]), title=t("axis_x")),
        y=alt.Y("ScoreRisk:Q", scale=alt.Scale(domain=[0, 108]), title=t("axis_y")),
    )
    points = base.mark_circle(size=90, opacity=0.75).encode(
        color=alt.Color(
            "CISA KEV:N", scale=alt.Scale(domain=[kev_in, kev_out], range=["#e8710a", "#4c78a8"]),
            legend=alt.Legend(orient="top", title=None),  # on top, so a narrow screen keeps the full plot width
        ),
        tooltip=[
            alt.Tooltip("Finding:N", title=t("col_finding")), alt.Tooltip("Title:N", title=t("tt_title")),
            "CVSS", "ScoreRisk", alt.Tooltip("Rank:Q", title=t("col_rank")), "CISA KEV",
        ],
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
    st.caption(t("chart_caption"))

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
        with st.expander(t("rejudge_title"), expanded=True):
            current = record.get("judge_fingerprint") == judge_fingerprint()
            environment = record["sandbox_environment"]
            st.markdown(
                t("rejudge_body", name=record_path.name, fp=record.get("judge_fingerprint"),
                  matches=t("rejudge_matches") if current else t("rejudge_older"), py=environment.get("python"),
                  fl=environment.get("flask"), pt=environment.get("pytest"))
            )
            st.table(
                pd.DataFrame(
                    [
                        {
                            t("col_finding"): r["finding_id"],
                            t("rj_col_judge"): t("accepted") if r["original"]["accepted"] else t("rejected"),
                            t("rj_col_later"): t("accepted") if r["rejudged"].get("accepted") else t("rejected_upper"),
                            t("rj_col_changed"): t("yes") if r.get("verdict_changed") else t("no"),
                            t("rj_col_diff"): t("yes") if r.get("diff_roundtrip_ok") else t("no_upper"),
                        }
                        for r in mine
                    ]
                )
            )
            for r in mine:
                if r.get("verdict_changed"):
                    st.markdown(t("rejudge_output", fid=r["finding_id"], poc=r["rejudged"]["poc"]))
                    st.code(r["rejudged"]["poc_output"], language="text", wrap_lines=True)
    if not run or not run["patches"]:
        st.info(t("no_patched"))
    for fid, patch in (run or {"patches": {}})["patches"].items():
        finding = by_id.get(fid, {"title": fid})
        accepted = patch.get("accepted")
        st.subheader(f"{fid}: {finding['title']}")
        approval = str(patch.get("approval") or t("not_recorded"))
        # export_status decides when the record has it; exported=false alone is never read as a refusal.
        recorded_status = f" · export_status: {patch['export_status']}" if patch.get("export_status") else ""
        st.markdown(
            t("judge_line", verdict=t("verdict_accepted") if accepted else t("verdict_not_accepted"),
              export=export_text(patch, lang), field=t("approval_field"), approval=approval, status=recorded_status)
        )
        for earlier in patch.get("attempt_history", []):
            with st.expander(t("attempt_rejected", n=earlier["attempt"])):
                st.markdown(t("attempt_body"))
                st.code(
                    (earlier.get("poc_output") or "") + "\n\ntests: "
                    + ((earlier.get("tests_output") or "").strip().splitlines() or ["n/a"])[-1],
                    language="text",
                    wrap_lines=True,
                )
                st.code(earlier["diff"], language="diff")
        if fid in flipped:
            st.warning(t("flipped_warning"))
        before, after = st.columns(2)
        before.markdown(t("before_h"))
        before.code(run["verdicts"][fid]["evidence"], language="text", wrap_lines=True)
        after.markdown(t("after_h"))
        after.code(
            (patch.get("poc_output") or "") + "\n\ntests: "
            + ((patch.get("tests_output") or "").splitlines() or ["n/a"])[-1],
            language="text",
            wrap_lines=True,
        )
        with st.expander(t("patch_expander")):
            st.code(patch["diff"], language="diff")
        st.download_button(
            t("download"),
            data=patch["diff"],
            file_name=f"{by_id.get(fid, {}).get('cwe') or fid}.diff".replace(":", "_"),
            mime="text/plain",
            key=f"dl_{fid}",
        )

# ---------- 2b. public evidence (Tavily) ----------
with tab_evidence:
    st.markdown(t("evidence_intro"))
    if t("evidence_recorded_note"):
        st.caption(t("evidence_recorded_note"))
    enrichment = (run or {}).get("enrichment") or {}
    if not enrichment:
        st.info(t("no_enrichment"))
    for fid, info in enrichment.items():
        finding = by_id.get(fid, {"title": fid})
        st.subheader(f"{fid}: {finding['title']}")
        if "skipped" in info or "error" in info:
            st.warning(t("skipped", why=info.get("skipped") or info.get("error")))
            continue
        assessment = info.get("assessment")
        if assessment:
            shown = {"yes": t("yes"), "no": t("no"), "unclear": t("ev_unclear")}
            c1, c2, c3 = st.columns(3)
            c1.metric(t("ev_exploited"), shown[assessment["exploited_in_the_wild"]])
            c2.metric(t("ev_public_code"), shown[assessment["public_exploit_code"]])
            c3.metric(t("ev_vendor_fix"), shown[assessment["vendor_fix_available"]])
            st.markdown(assessment["summary"])
        else:
            st.write(t("no_sources"))
        for i, source in enumerate(info.get("sources", []), 1):
            st.markdown(f"[{i}] [{source['title'] or source['url']}]({source['url']})")
        st.caption(t("query", q=info["query"]))

# ---------- 3. why ----------
with tab_why:
    st.markdown(t("why_score"))
    st.markdown(t("why_bands", epss=f"{EPSS_ATTEND:.2f}"))
    st.markdown(t("why_snapshot", fetched=threat["fetched_at"][:10], version=threat["sources"]["kev_catalog_version"],
                  total=threat["sources"]["kev_total"]))
    if sensitivity:
        st.markdown(t("sens_title", n=sensitivity["configurations_tested"]))
        shown = {k: v for k, v in sensitivity.items() if isinstance(v, float)}
        st.table(pd.DataFrame({t("sens_col_conclusion"): [data_label(k, lang) for k in shown],
                               t("sens_col_holds"): [f"{v:.0%}" for v in shown.values()]}))
        st.caption(t("sens_caption"))

# ---------- 4. reproduce ----------
with tab_repro:
    st.markdown(
        f"""
{t("repro_intro")}

```bash
git clone https://github.com/oryamx/megapatch
cd megapatch
pip install -r requirements.txt
python judge_check.py
```

{t("repro_full")}

```bash
python megapatch.py
```

{t("repro_services")}
"""
    )
    isolation_path = EVIDENCE / "isolation_check.json"
    if isolation_path.exists():
        isolation = json.loads(isolation_path.read_text(encoding="utf-8"))
        with st.expander(t("isolation_title")):
            st.caption(t("isolation_caption", date=isolation["checked_at"][:10]))
            for name, output in isolation["results"].items():
                st.markdown(f"**{data_label(name, lang)}**")
                st.code(output or t("empty"), language="text", wrap_lines=True)


# ---------- 6. interactive analysis (local opt-in) ----------
def _stage_lines(stages, poc):
    """One line per stage: status, label, detail, duration. Rendered while the analysis runs.
    Labels follow the interface language; the engine's details are recorded results and stay as they are."""
    marks = {"running": t("stage_running"), "done": t("stage_done"), "failed": t("stage_failed"),
             "pending": t("stage_pending")}
    lines = []
    for s in stages:
        took = ""
        if s.get("finished_at") and s.get("started_at"):
            took = f" ({s['finished_at'] - s['started_at']:.1f} s)"
        detail = f" - {s['detail']}" if s.get("detail") else ""
        lines.append(f"- **{marks.get(s['status'], s['status'])}** {stage_label(s, poc, lang)}{detail}{took}")
    return "\n".join(lines) or t("live_starting")


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
    ids = list(labels)
    choice = st.selectbox(t("live_select"), ids, index=remembered_index(ids, "ia_selected"), format_func=labels.get,
                          key=f"ia_choice_{lang}")
    st.session_state["ia_selected"] = choice
    finding = next(r for r in rows if r["id"] == choice)
    poc = CLASSES[finding["cwe"]]["poc"]
    st.caption(t("live_judge_version", fp=judge_fingerprint()))

    if st.button(t("live_run"), type="primary"):
        st.session_state.pop("ia_decision", None)
        box = st.status(t("live_in_progress"), expanded=True)
        view = box.empty()
        deps = ia_module.default_dependencies()
        calls_before = len(deps.usage_lines())
        started = time.time()
        result = ia_module.analyze(
            finding["cwe"], judge=deps.judge, generate=deps.generate, diff_of=deps.diff_of,
            read_candidate=deps.read_candidate, prepare=deps.prepare,
            notify=lambda stages: view.markdown(_stage_lines(stages, poc)),
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
            label={"awaiting_approval": t("live_done_awaiting"),
                   "rejected_by_judge": t("live_done_rejected"),
                   "not_confirmed": t("live_not_confirmed"),
                   "error": t("live_error")}[result["state"]],
            state="error" if result["state"] == "error" else "complete",
        )

    state = st.session_state.get("ia")
    if not state or state["finding_id"] != finding["id"]:
        return
    result = state["result"]
    st.markdown(t("live_progress"))
    st.markdown(_stage_lines(result["stages"], result.get("poc", poc)))
    if result.get("error"):
        st.error(result["error"])

    if result["before"] is not None:
        left, right = st.columns(2)
        left.markdown(t("live_before", poc=result["poc"], code=result["before"]["poc_exit"]))
        left.code(result["before"]["poc_output"], language="text", wrap_lines=True)
        if result["attempts"]:
            last = result["attempts"][-1]
            tail = ((last.get("tests_output") or "").strip().splitlines() or ["n/a"])[-1]
            right.markdown(t("live_after", poc=result["poc"], pe=last["poc_exit"], te=last["tests_exit"]))
            right.code(f"{last['poc_output']}\n\ntests: {tail}", language="text", wrap_lines=True)
            st.code(last["diff"], language="diff")

    decision = st.session_state.get("ia_decision")
    if decision:
        if decision["exported"]:
            st.success(t("live_exported", path=decision["export_path"], record=decision["evidence_path"]))
        else:
            st.info(t("live_not_exported", record=decision["evidence_path"]))
    elif result["state"] == "awaiting_approval":
        st.warning(t("live_awaiting"))
        a, b = st.columns(2)
        a.button(t("live_approve"), type="primary", on_click=_decide, args=(True, ia_module, finding))
        b.button(t("live_reject"), on_click=_decide, args=(False, ia_module, finding))
    elif result["state"] in ("rejected_by_judge", "not_confirmed", "error"):
        st.error(t("live_no_patch"))
        st.button(t("live_save_record"), on_click=_decide, args=(False, ia_module, finding))


# ---------- 7. your repository: local scan (scan_view.py) ----------
with tab_repo:
    scan_view.render(t, lang)

with tab_live:
    import interactive as ia

    st.subheader(t("live_title"))
    st.markdown(t("live_intro"))
    st.caption(t("live_independent"))
    st.caption(t("live_trust"))
    if not ia.is_enabled():
        st.info(t("live_off"))
    else:
        render_interactive(ia)
