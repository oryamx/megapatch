"""Focused check: the dashboard tells the whole loop to a first-time visitor, from the data.

The real dashboard is rendered headless (Streamlit's AppTest) in a child process. It only reads
the repository's files; nothing is written. Every expected value is computed here from the scanner
files and the recorded runs, never typed by hand:
  - the page opens on the run made with the current judge and approved by a person;
  - the five-step strip states the scanner funnel (entries, findings, CVEs, KEV) and each run's
    approval kind as that run recorded it (a --yes run must say no person approved);
  - the Walkthrough tab follows one finding through five steps, with the SAME PoC before and after;
  - a repaired patch is shown as repaired;
  - the main limits are visible without opening anything.

Usage: python check_walkthrough.py   (judge_check.py runs it too)
"""
import json
import subprocess
import sys
from pathlib import Path

from catalog import CLASSES
from ingest import scanner_counts
from scorerisk import score_all

HERE = Path(__file__).resolve().parent
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


RENDER_CHILD = r"""
import json, sys
from streamlit.testing.v1 import AppTest

follow = json.loads(sys.argv[1])  # {run label fragment: finding id to follow in the walkthrough}

def snapshot(page):
    return {
        "exceptions": [str(e.value) for e in page.exception],
        "strip": [m.value for m in page.markdown if m.value.startswith("**") and " · " in m.value[:20]],
        "steps": [m.value for m in page.markdown if m.value.startswith("##### Step")],
        "walk_choice": page.selectbox(key="walk_choice").value if any(
            s.key == "walk_choice" for s in page.selectbox) else None,
        "codes": [c.value for c in page.code],
        "captions": [c.value for c in page.caption],
        "markdown": [m.value for m in page.markdown],
        "expanders": [e.label for e in page.expander],
    }

at = AppTest.from_file("dashboard.py", default_timeout=240).run()
selector = at.sidebar.selectbox[0]
labels = [str(o) for o in selector.options]
out = {"default": labels[selector.index] if selector.index is not None else None, "runs": {}}
for index, label in enumerate(labels):
    page = selector.select_index(index).run()
    for fragment, finding in follow.items():
        if fragment in label and not page.exception and any(s.key == "walk_choice" for s in page.selectbox):
            page = page.selectbox(key="walk_choice").set_value(finding).run()
    out["runs"][label] = snapshot(page)
    selector = page.sidebar.selectbox[0]
print("WALK-JSON:" + json.dumps(out))
"""

LABEL_B = "Recorded run with the current judge - human approval"
LABEL_GOLDEN = "Recorded demo run - automatic approval (--yes)"
LABEL_REPAIR = "Recorded run with a repaired patch - automatic approval (--yes)"


def load(name):
    return json.loads((HERE / "evidence" / name).read_text(encoding="utf-8"))


def main():
    counts = scanner_counts()
    ranked, _ = score_all()
    n_kev = len({r["cve"] for r in ranked if r["kev"]})
    run_b, golden, repair = load("human_approved_run_b.json"), load("golden_run.json"), load("run_with_repair.json")
    repaired_id = next(fid for fid, p in repair["patches"].items() if p.get("attempts", 1) > 1)

    proc = subprocess.run([sys.executable, "-c", RENDER_CHILD, json.dumps({"repaired patch": repaired_id})],
                          cwd=HERE, capture_output=True, text=True, timeout=600)
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("WALK-JSON:")), None)
    if proc.returncode != 0 or line is None:
        check("dashboard rendered headless", False, f"(exit {proc.returncode}) {proc.stderr.strip()[-600:]}")
        return finish()
    data = json.loads(line.removeprefix("WALK-JSON:"))
    runs = data["runs"]

    check("every run renders without an exception", all(not r["exceptions"] for r in runs.values()),
          f"({len(runs)} runs)")
    check("the page opens on the run made with the current judge and approved by a person",
          data["default"] == LABEL_B, f"(default: {data['default']})")

    b = runs.get(LABEL_B, {"strip": [], "steps": [], "codes": [], "captions": [], "markdown": [], "expanders": []})
    strip = " ".join(b["strip"])
    story = strip + " " + " ".join(b["captions"])  # short headlines in the strip, the numbers in the line below
    funnel = [f"{counts['pip_audit_entries']} pip-audit entries", f"{counts['bandit_results']} Bandit results",
              f"{counts['findings']} distinct findings", f"{counts['unique_cves']} unique CVEs",
              f"{n_kev} in CISA KEV"]
    check("strip: five steps, and the scanner funnel stated with the numbers computed from the scanner files",
          len(b["strip"]) == 5 and f"**{counts['findings']} findings**" in strip and all(f in story for f in funnel),
          f"({counts['pip_audit_entries']} -> {counts['findings']} findings, {counts['unique_cves']} CVEs, {n_kev} KEV)")

    approved_b = sum(1 for p in run_b["patches"].values() if p.get("exported"))
    accepted_b = sum(1 for p in run_b["patches"].values() if p.get("accepted"))
    check("strip (run B): patches accepted by the same PoC and tests, and the human approvals, as recorded",
          f"**{accepted_b} accepted**" in strip and f"**{approved_b} of {len(run_b['patches'])} approved**" in strip
          and f"{run_b['usage']['nemotron_calls']} calls" in story and run_b["model"] in story)

    golden_strip = " ".join(runs.get(LABEL_GOLDEN, {}).get("strip", []))
    check("strip (--yes run): it says the run skipped the question and no person approved",
          "Automatic (`--yes`)" in golden_strip and "no person approved" in golden_strip
          and "approved** by a person" not in golden_strip)

    first_id = next(i["id"] for i in run_b["final_order"] if i["id"] in run_b["patches"])
    poc = CLASSES[next(r for r in ranked if r["id"] == first_id)["cwe"]]["poc"]
    patch = run_b["patches"][first_id]
    steps = b["steps"]
    check("walkthrough: five numbered steps, and the SAME PoC is named before and after",
          len(steps) == 5 and [s.split(" · ")[0] for s in steps] == [f"##### Step {i}" for i in range(1, 6)]
          and f"`{poc}`" in steps[1] and f"`{poc}`" in steps[3], f"({poc})")
    check("walkthrough: the before output is the recorded exploit firing, the after output is the recorded re-test",
          run_b["verdicts"][first_id]["evidence"] in b["codes"]
          and patch["diff"].strip() in [c.strip() for c in b["codes"]]  # st.code drops the final newline
          and any(c.startswith(patch["poc_output"]) for c in b["codes"])
          and "VULNERABLE" in run_b["verdicts"][first_id]["evidence"] and "SAFE" in patch["poc_output"])
    check("walkthrough: step 5 states the approval as recorded (a person, for run B)",
          any(m.startswith("Export approved by a person.") for m in b["markdown"]))

    golden_md = runs.get(LABEL_GOLDEN, {}).get("markdown", [])
    check("walkthrough (--yes run): step 5 says exported automatically and no person approved it",
          any(m.startswith("Exported automatically (--yes); no person approved it.") for m in golden_md))

    rep = runs.get(LABEL_REPAIR, {"captions": [], "strip": [], "walk_choice": None})
    check("walkthrough (repair run): the repaired patch is shown as rejected once, then repaired from the judge's output",
          rep["walk_choice"] == repaired_id and any("Attempt 1 was rejected by the judge" in c for c in rep["captions"])
          and "after one repair" in " ".join(rep["strip"]), f"({repaired_id})")

    captions = " ".join(b["captions"])
    check("limits are visible without opening anything: in-process PoCs, open outbound network, 'accepted' is not 'safe'",
          "in-process" in captions and "outbound network is not blocked" in captions
          and "not \"safe in production\"" in captions)
    expander_text = " ".join(m for m in b["markdown"] if "Declared, not discovered" in m)
    check("the limits panel states the declared inventory, --yes runs and the missing precision figure",
          "What you are looking at, and what it does not show" in b["expanders"]
          and "`--yes`" in expander_text and "no precision figure" in expander_text
          and f"{counts['pip_audit_entries']} entries" in expander_text)
    return finish()


def finish():
    print("\nCHECK-WALKTHROUGH:", "ALL PASSED" if results and all(results) else "FAILED")
    sys.exit(0 if results and all(results) else 1)


if __name__ == "__main__":
    main()
