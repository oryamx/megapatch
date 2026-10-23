"""Focused check: the English / Español selector changes words, never data.

  A. ui_text.py: every text exists in both languages with the same placeholders, and every recorded
     status, band basis, export state and data label the dashboard can show has a Spanish version
     ("the person declined" appears in Spanish only for export_status=declined, as in English).
  B. The real dashboard rendered headless (Streamlit's AppTest) in English and in Spanish, for every
     run: the metrics, the code blocks (PoC output, tests, diffs), the data in the tables and the
     selected run are identical; the interface words are Spanish; switching the language keeps the
     selected run and the finding followed in the walkthrough.

It only reads the repository. Usage: python check_language.py   (judge_check.py runs it too)
"""
import itertools
import json
import re
import subprocess
import sys
from pathlib import Path

import ui_text
from bands import band_for
from ui_text import TEXT, band_basis, data_label, export_text, status_label

HERE = Path(__file__).resolve().parent
results = []
ENGLISH_ONLY_EMPTY = {"evidence_recorded_note"}  # a note that only Spanish needs (the summaries are English)


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def placeholders(text):
    return set(re.findall(r"(?<!\{)\{(\w+)\}(?!\})", text))


RENDER_CHILD = r"""
import json
from streamlit.testing.v1 import AppTest

def text_of(page):
    out = []
    for kind in ("markdown", "caption", "info", "warning", "success", "error", "subheader"):
        out += [e.value for e in getattr(page, kind)]
    out += [e.label for e in page.metric] + [e.label for e in page.expander] + [e.label for e in page.tabs]
    out += [e.label for e in page.selectbox] + [e.label for e in page.button]
    return out

def snapshot(page):
    frames = []
    for d in page.dataframe:
        frame = d.value
        frames.append({c: [str(v) for v in frame[c].tolist()] for c in frame.columns})
    return {
        "exceptions": [str(e.value) for e in page.exception],
        "run": str(page.sidebar.selectbox[0].value) if page.sidebar.selectbox else None,
        "metrics": [m.value for m in page.metric],
        "codes": [c.value for c in page.code],
        "frames": frames,
        "tables": [[[str(v) for v in t.value.iloc[:, i].tolist()] for i in range(t.value.shape[1])]
                   for t in page.table],
        "tabs": [tab.label for tab in page.tabs],
        "text": text_of(page),
    }

at = AppTest.from_file("dashboard.py", default_timeout=240).run()
out = {"runs": {}}
labels = [str(o) for o in at.sidebar.selectbox[0].options]
for index in range(len(labels)):
    at = at.sidebar.selectbox[0].select_index(index).run()
    english = snapshot(at)
    at = at.sidebar.radio[0].set_value("es").run()
    spanish = snapshot(at)
    at = at.sidebar.radio[0].set_value("en").run()
    back = snapshot(at)
    out["runs"][str(index)] = {"en": english, "es": spanish, "back": back}

# The finding followed in the walkthrough survives a language switch.
at = at.sidebar.selectbox[0].select_index(0).run()  # the default run, human_approved_run_b.json
recorded = json.load(open("evidence/human_approved_run_b.json", encoding="utf-8"))
followed = [i["id"] for i in recorded["final_order"] if i["id"] in recorded["patches"]]
second = followed[1] if len(followed) > 1 else followed[0]
# set_value with the real id: AppTest's select_index re-formats an already formatted label
at = at.selectbox(key="walk_choice").set_value(second).run()
at = at.sidebar.radio[0].set_value("es").run()
walk_es = [s.value for s in at.selectbox if s.key and s.key.startswith("walk_choice")]
at = at.sidebar.radio[0].set_value("en").run()
out["walk"] = {"chosen": second, "after_es": walk_es, "after_back": at.selectbox(key="walk_choice").value}
print("LANG-JSON:" + json.dumps(out))
"""

# Columns that hold data (ids, titles, numbers): identical in both languages. The others are words.
DATA_COLUMNS = ("Queue #", "Id", "Finding", "Band", "ScoreRisk", "ScoreRisk rank", "CVSS", "CVSS rank", "EPSS")
SPANISH_TABS = ["Recorrido", "Cola de prioridad", "Antes / después", "Evidencia pública", "Por qué este orden",
                "Reprodúcelo", "Tu repositorio (local)", "Analizar (local)"]


def static_checks():
    missing = [k for k, v in TEXT.items()
               if not v.get("es") or (not v.get("en") and k not in ENGLISH_ONLY_EMPTY)]
    check("texts: every key has an English and a Spanish text", not missing, f"({len(TEXT)} keys) {missing[:5]}")
    mismatched = [k for k, v in TEXT.items() if v.get("en") and placeholders(v["en"]) != placeholders(v["es"])]
    check("texts: both languages use exactly the same placeholders", not mismatched, f"{mismatched[:5]}")

    wrong = []
    for approval, status, exported, accepted in itertools.product(
            ("human, x", "auto (--yes)", "none (x)", ""),
            (None, "exported", "pending", "failed", "declined", "not_applicable", "weird"), (True, False), (True, False)):
        patch = {"accepted": accepted, "approval": approval, "exported": exported}
        if status is not None:
            patch["export_status"] = status
        spanish = export_text(patch, "es")
        declined = accepted and status == "declined" and not exported
        if not spanish or ("rechazó exportar" in spanish) != declined:
            wrong.append((approval[:5], status, exported, accepted))
    check("export states: a Spanish text for every combination, and 'rechazó exportar' only for declined",
          not wrong, f"{wrong[:3]}")

    rows = [{"kev": kev, "internet_facing": net, "epss": epss}
            for kev in (True, False) for net in (True, False) for epss in (None, 0.1, 0.9)]
    bases = {band_for(row, verdict)[1] for row in rows for verdict in (None, "CONFIRMED")}
    untranslated = [b for b in bases if band_basis(b, "es") == b]
    check("band basis: every basis bands.py can produce has a Spanish version", not untranslated,
          f"({len(bases)} bases) {untranslated}")

    statuses, executors = set(), set()
    for path in (HERE / "evidence").glob("*run*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        statuses |= {item["status"] for item in data.get("final_order", [])}
        executors.add(data.get("executor"))
    shown = [s for s in statuses if status_label(s, "en") != s]  # the statuses the dashboard turns into labels
    raw_shown = [s for s in statuses if status_label(s, "en") == s and s not in ("CONFIRMED",)]
    untranslated = [s for s in shown if status_label(s, "es") == status_label(s, "en")]
    check("statuses: every recorded status shown as a label has a Spanish label", not untranslated and not raw_shown,
          f"({len(statuses)} statuses) {untranslated[:3]} {raw_shown[:3]}")

    sensitivity = json.loads((HERE / "evidence" / "sensitivity.json").read_text(encoding="utf-8"))
    isolation = json.loads((HERE / "evidence" / "isolation_check.json").read_text(encoding="utf-8"))
    labels = [k for k, v in sensitivity.items() if isinstance(v, float)] + list(isolation["results"]) + list(executors)
    untranslated = [x for x in labels if data_label(x, "es") == x]
    check("recorded labels: sensitivity conclusions, isolation checks and executors have Spanish versions",
          not untranslated, f"({len(labels)} labels) {untranslated[:3]}")


def render_checks():
    proc = subprocess.run([sys.executable, "-c", RENDER_CHILD], cwd=HERE, capture_output=True, text=True,
                          timeout=600)
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("LANG-JSON:")), None)
    if proc.returncode != 0 or line is None:
        check("dashboard rendered headless in both languages", False, f"(exit {proc.returncode}) {proc.stderr[-600:]}")
        return
    data = json.loads(line.removeprefix("LANG-JSON:"))
    runs = data["runs"]
    check("every run renders without an exception in English and in Spanish",
          all(not snap["exceptions"] for r in runs.values() for snap in r.values()), f"({len(runs)} runs)")

    same_run = all(r["en"]["run"] == r["es"]["run"] == r["back"]["run"] for r in runs.values())
    check("switching the language keeps the selected run", same_run)

    # Words that a metric or a table may show as a value: the Spanish value must be exactly the translation.
    word_values = {TEXT[k]["es"]: TEXT[k]["en"] for k in ("yes", "no", "ev_unclear", "accepted", "rejected",
                                                          "rejected_upper", "no_upper")}

    def data_of(snap, spanish):
        to_english = (lambda v: word_values.get(v, v)) if spanish else (lambda v: v)
        metrics = [to_english(v) for v in snap["metrics"]]
        frames = [{c: f[c] for c in DATA_COLUMNS if c in f} for f in snap["frames"]]
        tables = []
        for columns in snap["tables"]:
            if len(columns) == 2:   # robustness table: translated conclusion, then the share of configurations
                tables.append([columns[1]])
            else:                   # re-judge table: finding ids, then words
                tables.append([columns[0]] + [[to_english(v) for v in col] for col in columns[1:]])
        return metrics, snap["codes"], frames, tables

    differing = [i for i, r in runs.items()
                 if data_of(r["en"], False) != data_of(r["es"], True) or data_of(r["en"], False) != data_of(r["back"], False)]
    check("the data is identical in both languages: metrics, PoC and test output, diffs, table data",
          not differing, f"(runs differing: {differing})")
    conclusions = [(table[0], spanish[0]) for r in runs.values()
                   for table, spanish in zip(r["en"]["tables"], r["es"]["tables"]) if len(table) == 2]
    check("the robustness conclusions are shown as their Spanish translation, value by value",
          bool(conclusions) and all([data_label(x, "es") for x in en] == es for en, es in conclusions))
    check("English after a round trip through Spanish is exactly the English page",
          all(r["en"]["text"] == r["back"]["text"] for r in runs.values()))

    first = runs["0"]
    check("the tabs are in Spanish", first["es"]["tabs"] == SPANISH_TABS, f"({first['es']['tabs']})")

    english_sentences = {v["en"].strip() for k, v in TEXT.items()
                         if v.get("en") and v["en"] != v["es"] and len(v["en"]) >= 25 and not placeholders(v["en"])}
    leftovers = sorted({s[:60] for r in runs.values() for text in r["es"]["text"] for s in english_sentences
                        if s in text})
    check("no English interface sentence is left on the Spanish page", not leftovers, f"{leftovers[:3]}")
    check("the Spanish page really is translated (it differs from the English one)",
          all(r["en"]["text"] != r["es"]["text"] for r in runs.values()))

    walk = data["walk"]
    check("switching the language keeps the finding followed in the walkthrough",
          walk["after_es"] == [walk["chosen"]] and walk["after_back"] == walk["chosen"], f"({walk})")


def main():
    static_checks()
    render_checks()
    print("\nCHECK-LANGUAGE:", "ALL PASSED" if results and all(results) else "FAILED")
    sys.exit(0 if results and all(results) else 1)


if __name__ == "__main__":
    main()
