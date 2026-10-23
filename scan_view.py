"""The dashboard tab "Your repository (local)": scan a folder of this machine, declare its exposure, read the
two queues. Everything it shows comes from repo_scan.py; the texts come from ui_text.py.

Scanning and declaring write files (a new scan folder, a new declaration file), so they are only offered in
the local scan mode: `streamlit run dashboard.py --server.address 127.0.0.1 -- --local-scan`. Both parts are
required (local_scan_status):
  - the `--local-scan` argument. There is no environment variable for it: Streamlit Community Cloud exposes
    its secrets as environment variables, and the public demo is started without arguments;
  - a server that listens on a loopback address only (server.address 127.0.0.1 or ::1). That is what keeps
    every remote network interface out: the operating system refuses their connections. A connection that
    Streamlit still reports from another address is refused too, but only as a second line: Streamlit warns
    that this client address can be spoofed, so the bind address is the guarantee.
    It only blocks direct connections: a proxy, a tunnel or port forwarding, or other users of a shared machine
    can still reach 127.0.0.1, so the mode must not be enabled in such deployments (README).
The address only limits incoming connections; a scan still makes the outgoing requests listed in repo_scan.py.
"""
import ipaddress
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

import repo_scan
from scorerisk import KEV_FLOOR
from ui_text import data_label

DASH = "—"  # a value that is not available


def _is_loopback(address):
    try:
        return ipaddress.ip_address(str(address or "").strip("[]")).is_loopback
    except ValueError:
        return False


def listens_on_loopback_only():
    """True when the server is bound to a loopback address. Streamlit binds to server.address; when it is
    empty it listens on every interface, and a host name is not accepted (it could resolve to anything)."""
    return _is_loopback(st.get_option("server.address"))


def local_scan_status():
    """'off' (not asked for), 'on', 'not_loopback' (asked for, but the server also listens on other interfaces)
    or 'remote' (asked for, but this session comes from another address)."""
    if "--local-scan" not in sys.argv[1:]:
        return "off"
    if not listens_on_loopback_only():
        return "not_loopback"
    client = st.context.ip_address  # None for 127.0.0.1 and ::1; a text address otherwise
    if isinstance(client, str) and not _is_loopback(client):
        return "remote"
    return "on"


def local_scan_enabled():
    return local_scan_status() == "on"


def _choice(t, label, options, memory, key, format_func=str):
    """A selector that keeps its choice across languages and reruns (its widget key changes with the language)."""
    if st.session_state.get(key) in options:
        index = 0  # the widget's own state (set by a new scan, or the person's choice) wins
    else:
        st.session_state.pop(key, None)
        previous = st.session_state.get(memory)
        index = options.index(previous) if previous in options else 0
    value = st.selectbox(label, options, index=index, key=key, format_func=format_func)
    st.session_state[memory] = value
    return value


def _error_text(t, exc):
    try:
        return t("rp_err_" + exc.key, **exc.values)
    except KeyError:
        return str(exc)


def scan_form(t, lang):
    st.markdown(f"**{t('rp_step1')}**")
    with st.form("rp_scan_form"):
        path = st.text_input(t("rp_path"), placeholder=r"C:\projects\my-app")
        project = st.text_input(t("rp_project"))
        threat = st.checkbox(t("rp_threat"), value=True)
        st.caption(t("rp_sent"))
        submitted = st.form_submit_button(t("rp_scan_button"), type="primary")
    if not submitted:
        return
    folder = Path(path.strip().strip('"')).name or path
    with st.status(t("rp_running", folder=folder), expanded=True) as status:
        progress = lambda step, **info: st.write(t("rp_step_" + step, **info))  # noqa: E731
        try:
            done = repo_scan.scan(path.strip().strip('"'), project.strip() or None, threat_data=threat,
                                  progress=progress)
        except repo_scan.ScanError as exc:
            status.update(label=t("rp_failed", error=_error_text(t, exc)), state="error")
            return
        meta = done["meta"]
        status.update(label=t("rp_done", id=meta["id"], deps=meta["counts"]["dependencies"], code=meta["counts"]["code"]),
                      state="complete", expanded=False)
    # Open the new scan: set the selectors' memory and their current widgets (not rendered yet in this run).
    st.session_state["rp_project_memory"] = meta["project"]
    st.session_state["rp_scan_memory"] = meta["id"]
    st.session_state[f"rp_project_{lang}"] = meta["project"]
    st.session_state[f"rp_scan_{lang}_{meta['project']}"] = meta["id"]


def _yes_no(t, value):
    return {None: t("rp_x_unknown"), True: t("rp_x_yes"), False: t("rp_x_no"), "production": t("rp_x_production"),
            "non-production": t("rp_x_non_production")}[value]


def exposure_summary(t, declared):
    labels = (("internet_facing", "rp_x_internet"), ("requires_auth", "rp_x_auth"), ("environment", "rp_x_env"),
              ("sensitive_data", "rp_x_sensitive"))
    return "; ".join(f"{t(label).rstrip('?').lstrip('¿')}: {_yes_no(t, declared.get(field))}" for field, label in labels)


def exposure_form(t, lang, project):
    st.markdown(f"**{t('rp_step2', project=project)}**")
    current = repo_scan.latest_exposure(project)
    declared = (current or {}).get("exposure") or dict.fromkeys(repo_scan.EXPOSURE_FIELDS)
    if current:
        st.caption(t("rp_x_current", when=current["declared_at"][:16].replace("T", " "),
                     summary=exposure_summary(t, declared)))
    else:
        st.caption(t("rp_x_none", project=project))
    st.caption(t("rp_x_intro"))
    # Options are words, not None/True/False: a selectbox reads None as "nothing chosen".
    word = {None: "unknown", True: "yes", False: "no", "production": "production", "non-production": "non-production"}
    value_of = {w: v for v, w in word.items()}
    fields = (("internet_facing", "rp_x_internet", [None, True, False]),
              ("requires_auth", "rp_x_auth", [None, True, False]),
              ("environment", "rp_x_env", [None, "production", "non-production"]),
              ("sensitive_data", "rp_x_sensitive", [None, True, False]))
    with st.form(f"rp_exposure_{project}"):
        columns = st.columns(4)
        values = {}
        for column, (field, label, options) in zip(columns, fields):
            with column:
                words = [word[o] for o in options]
                chosen = st.selectbox(t(label), words, index=words.index(word[declared.get(field)]),
                                      format_func=lambda w: _yes_no(t, value_of[w]),
                                      key=f"rp_x_{field}_{project}_{lang}_{(current or {}).get('id')}")
                values[field] = value_of[chosen]
        saved = st.form_submit_button(t("rp_x_save"))
    if saved:  # rerun, so the caption above and the form show the declaration just saved
        st.session_state["rp_x_just_saved"] = repo_scan.declare_exposure(project, values)["id"]
        st.rerun()
    just_saved = st.session_state.pop("rp_x_just_saved", None)
    if just_saved:
        st.success(t("rp_x_saved", id=just_saved))
    return current


def _num(value, digits):
    return DASH if value is None else f"{value:.{digits}f}"


def _score(row):
    low, high = row["score"]
    return f"{low:.1f}" if low == high else f"{low:.1f} – {high:.1f}"


def _basis(t, row):
    if not row["cve"]:
        parts = [t("rp_b_nocve")]
    else:
        parts = [t("rp_b_kev")] if row["kev"] else []
        parts.append(t("rp_b_epss", v=f"{row['epss']:.3f}") if row["epss"] is not None
                     else t("rp_b_missing", what="EPSS"))
        parts.append(t("rp_b_cvss", v=f"{row['cvss']:.1f}") if row["cvss"] is not None
                     else t("rp_b_missing", what="CVSS"))
    if row["position"] == "provisional":
        parts.append(t("rp_b_provisional"))
    return " · ".join(parts)


def dependency_table(t, ranked):
    rows = [{
        "#": r["rank"],
        "Package": f"{r['package']} {r['version']}",
        "Advisory": r["cve"] or r["advisory"],
        "Pinned at": f"{r['file']}:{r['line']}" if r["file"] else DASH,
        "ScoreRisk": _score(r),
        "KEV": t("yes") if r["kev"] else (t("no") if r["cve"] else DASH),
        "EPSS": _num(r["epss"], 3),
        "CVSS": _num(r["cvss"], 1),
        "Band": " / ".join(r["bands"]),
        "Why here": _basis(t, r),
        "Fixed in": ", ".join(r["fix_versions"]) or DASH,
    } for r in ranked["dependencies"]]
    st.dataframe(pd.DataFrame(rows), hide_index=True, column_config={
        "#": st.column_config.NumberColumn("#", width=36),
        "Package": st.column_config.TextColumn(t("rp_col_package"), width=120),
        "Advisory": st.column_config.TextColumn(t("rp_col_advisory"), width=130),
        "Pinned at": st.column_config.TextColumn(t("rp_col_manifest"), width=150),
        "ScoreRisk": st.column_config.TextColumn("ScoreRisk", width=96),
        "KEV": st.column_config.TextColumn("KEV", width=40, help=t("col_kev_help")),
        "EPSS": st.column_config.TextColumn("EPSS", width=52),
        "CVSS": st.column_config.TextColumn("CVSS", width=44),
        "Band": st.column_config.TextColumn(t("rp_col_band"), width=110),
        "Why here": st.column_config.TextColumn(t("rp_col_basis"), width=230, help=t("rp_col_basis_help")),
        "Fixed in": st.column_config.TextColumn(t("rp_col_fix"), width=90),
    })


def code_table(t, ranked):
    rows = [{
        "#": r["rank"],
        "Level": f"{r['severity']} / {r['confidence']}",
        "Finding": f"{r['test_id']} {r['test_name']}: {r['message']}",
        "CWE": r["cwe"] or DASH,
        "File": r["file"],
        "Line": str(r["line"]),
        "Tests": t("yes") if r["test_code"] else "",
    } for r in ranked["code"]]
    st.dataframe(pd.DataFrame(rows), hide_index=True, column_config={
        "#": st.column_config.NumberColumn("#", width=36),
        "Level": st.column_config.TextColumn(t("rp_col_level"), width=130, help=t("rp_col_level_help")),
        "Finding": st.column_config.TextColumn(t("rp_col_finding"), width=380),
        "CWE": st.column_config.TextColumn("CWE", width=76),
        "File": st.column_config.TextColumn(t("rp_col_file"), width=180),
        "Line": st.column_config.TextColumn(t("rp_col_line"), width=50),
        "Tests": st.column_config.TextColumn(t("rp_col_tests"), width=90),
    })


def explain_dependency(t, r):
    lines = [t("rp_ex_dep_head", rank=r["rank"], package=r["package"], version=r["version"],
               where=f"{r['file']}:{r['line']}" if r["file"] else DASH, advisory=r["advisory"],
               aliases=f" ({', '.join(a for a in r['aliases'] if a != r['advisory'])})" if r["aliases"] else "")]
    if not r["cve"]:
        lines.append(t("rp_ex_e_nocve"))
    elif r["kev"]:
        lines.append(t("rp_ex_e_kev", floor=KEV_FLOOR, epss=f"; EPSS {r['epss']:.3f}" if r["epss"] is not None else ""))
    elif r["epss"] is not None:
        lines.append(t("rp_ex_e_epss", v=f"{r['epss']:.3f}", p=f"{r['epss_percentile']:.2f}"))
    else:
        lines.append(t("rp_ex_e_none"))
    if r["cvss"] is not None:
        lines.append(t("rp_ex_s", v=f"{r['cvss']:.1f}", cwe=f"; {', '.join(r['cwe'])}" if r["cwe"] else ""))
    else:
        lines.append(t("rp_ex_s_none"))
    low, high = r["X"]
    lines.append(t("rp_ex_x", x=t("rp_x_exact", x=f"{low:.2f}") if low == high
                   else t("rp_x_range", low=f"{low:.2f}", high=f"{high:.2f}")))
    position = t("rp_ex_exact") if r["position"] == "exact" else \
        t("rp_ex_provisional", missing=", ".join(m for m in r["missing"] if m != "CVE") or "E")
    lines.append(t("rp_ex_score", score=_score(r), position=position))
    if len(r["bands"]) == 1:
        lines.append(t("rp_ex_band", bands=r["bands"][0]))
    else:
        what = [t("rp_ex_band_internet")] if r["X"][0] != r["X"][1] else []
        what += [t("rp_ex_band_epss")] if r["epss"] is None else []
        lines.append(t("rp_ex_band_depends", bands=" / ".join(r["bands"]), what=", ".join(what)))
    lines.append(t("rp_ex_fix", versions=", ".join(r["fix_versions"])) if r["fix_versions"] else t("rp_ex_nofix"))
    if r.get("summary"):
        lines.append(t("rp_ex_summary", text=r["summary"]))
    st.markdown(lines[0] + "\n\n" + "\n".join(f"- {line}" for line in lines[1:]))


def explain_code(t, r):
    lines = [t("rp_ex_code_head", rank=r["rank"], where=f"{r['file']}:{r['line']}", test=r["test_id"],
               name=r["test_name"], cwe=f", {r['cwe']}" if r["cwe"] else ""),
             t("rp_ex_code_message", message=r["message"]),
             t("rp_ex_code_position", severity=r["severity"], confidence=r["confidence"],
               tests=t("rp_ex_code_tests") if r["test_code"] else "")]
    if r.get("more_info"):
        lines.append(t("rp_ex_more", url=r["more_info"]))
    st.markdown(lines[0] + "\n\n" + "\n".join(f"- {line}" for line in lines[1:]))


def results(t, lang, scan, exposure):
    meta = scan["meta"]
    ranked = repo_scan.rank_scan(scan, exposure)
    scanners = ", ".join(f"{name} {version}" for name, version in meta["scanners"].items())
    threat = meta["threat_data"]["fetched_at"][:10] if meta["threat_data"]["downloaded"] else t("rp_threat_none")
    st.caption(t("rp_meta", folder=meta["folder_name"], commit=t("rp_commit", c=meta["commit"]) if meta["commit"] else "",
                 id=meta["id"], when=meta["scanned_at"][:16].replace("T", " "), scanners=scanners, threat=threat))
    check = meta["repository_check"]
    if check["unchanged"]:
        st.success(t("rp_check_ok", n=check["files_compared"]))
    else:
        st.error(t("rp_check_changed", files=", ".join(check["changed"])))
    excluded = meta["excluded"]
    st.caption(t("rp_excluded", items=", ".join(f"`{e['path']}` ({data_label(e['reason'], lang)})" for e in excluded))
               if excluded else t("rp_excluded_none"))
    st.warning(t("rp_scope"))
    low, high = ranked["X"]
    x_text = t("rp_x_exact", x=f"{low:.2f}") if low == high else t("rp_x_range", low=f"{low:.2f}", high=f"{high:.2f}")
    st.caption(t("rp_x_summary", summary=f"{exposure_summary(t, ranked['exposure'])} ({x_text})"))
    c = ranked["counts"]
    st.markdown(t("rp_counts", deps=c["dependencies"], cves=c["cves"], kev=c["kev"], prov=c["provisional"],
                  code=c["code"], high=c["code_high"], medium=c["code_medium"], low=c["code_low"],
                  tests=c["code_in_tests"]))
    with st.expander(t("rp_how_title")):
        st.markdown(t("rp_how"))

    st.markdown(f"##### {t('rp_deps_title', n=c['dependencies'])}")
    if ranked["dependencies"]:
        dependency_table(t, ranked)
    elif meta["pinned"]:
        st.success(t("rp_deps_none", n=len(meta["pinned"])))
    else:
        st.info(t("rp_deps_nopins"))
    st.markdown(f"##### {t('rp_code_title', n=c['code'])}")
    if ranked["code"]:
        code_table(t, ranked)
    else:
        st.success(t("rp_code_none", n=meta["bandit"]["files_analyzed"]))

    options = [("d", r["rank"]) for r in ranked["dependencies"]] + [("c", r["rank"]) for r in ranked["code"]]
    if options:
        deps, code = ranked["dependencies"], ranked["code"]

        def label(option):
            kind, rank = option
            r = (deps if kind == "d" else code)[rank - 1]
            if kind == "d":
                return t("rp_detail_dep_label", rank=rank, package=r["package"], version=r["version"],
                         advisory=r["cve"] or r["advisory"])
            return t("rp_detail_code_label", rank=rank, file=r["file"], line=r["line"], test=r["test_id"])

        kind, rank = _choice(t, t("rp_detail"), options, "rp_detail_memory", f"rp_detail_{lang}_{meta['id']}", label)
        (explain_dependency if kind == "d" else explain_code)(t, (deps if kind == "d" else code)[rank - 1])

    not_audited = meta["not_audited"]
    if not_audited:
        with st.expander(t("rp_not_audited", n=len(not_audited))):
            st.dataframe(pd.DataFrame([{
                # masked again when shown: a scan saved by an earlier version may hold an unmasked line
                "File": n["file"] or DASH, "Line": str(n["line"]) if n["line"] else DASH,
                "Text": repo_scan.mask_secrets(n["text"] or ""),
                "Reason": data_label(n["reason"], lang),
            } for n in not_audited]), hide_index=True, column_config={
                "File": st.column_config.TextColumn(t("rp_col_file")),
                "Line": st.column_config.TextColumn(t("rp_col_line")),
                "Text": st.column_config.TextColumn(t("rp_col_text")),
                "Reason": st.column_config.TextColumn(t("rp_col_reason")),
            })
    if meta["manifests_not_read"]:
        st.caption(t("rp_manifests", files=", ".join(f"`{m}`" for m in meta["manifests_not_read"])))
    if meta["bandit"]["files_not_parsed"]:
        st.caption(t("rp_not_parsed", n=len(meta["bandit"]["files_not_parsed"]),
                     files=", ".join(f"`{f['file']}`" for f in meta["bandit"]["files_not_parsed"])))
    with st.expander(t("rp_external_title")):
        lines = [t("rp_ext_" + e["service"], n=e["count"]) for e in meta["external"]]
        st.markdown("\n".join(f"- {line}" for line in lines + [t("rp_ext_bandit"), t("rp_ext_none")]))
    st.caption(t("rp_not_done"))


def render(t, lang):
    status = local_scan_status()
    st.subheader(t("rp_title"))
    st.markdown(t("rp_intro"))
    if status == "off":
        st.info(t("rp_off"))
    elif status != "on":  # asked for, but refused: say why and how to start it safely
        st.error(t("rp_refused_" + status))
    if status != "on":
        return  # saved analyses (project names, results) are shown only in the authorized local mode
    scan_form(t, lang)
    projects = repo_scan.list_projects()
    if not projects:
        st.caption(t("rp_none"))
        return
    st.divider()
    project = _choice(t, t("rp_select_project"), projects, "rp_project_memory", f"rp_project_{lang}")
    scans = repo_scan.list_scans(project)
    complete = [scan_id for scan_id, _, done in scans if done]
    folders = {scan_id: folder for scan_id, folder, _ in scans}
    if len(complete) < len(scans):
        st.caption(t("rp_incomplete", n=len(scans) - len(complete)))
    if not complete:
        return
    exposure = exposure_form(t, lang, project)
    st.markdown(f"**{t('rp_step3')}**")
    scan_id = _choice(t, t("rp_select_scan"), complete, "rp_scan_memory", f"rp_scan_{lang}_{project}",
                      lambda i: t("rp_scan_label", when=f"{i[:4]}-{i[4:6]}-{i[6:8]} {i[9:11]}:{i[11:13]}", id=i))
    results(t, lang, repo_scan.load_scan(folders[scan_id]), exposure)
