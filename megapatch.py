"""MegaPatch pipeline: rank -> verify -> patch -> re-test -> evidence.

Usage:
  python megapatch.py                run the whole pipeline (judge in the Nebius sandbox)
  python megapatch.py --top 5        only the top 5 enter verification (shows the budget logic)
  python megapatch.py --yes          skip the human approval question
  python megapatch.py --eval-only    reuse the existing candidate patches (no model call)
  python megapatch.py --local        judge on this machine instead of the sandbox
  python megapatch.py --no-enrich    skip the Tavily public-evidence step

Patch generation always calls Nemotron on Nebius Token Factory.
"The score proposes, execution disposes": ScoreRisk orders the findings, the
sandbox PoC decides which are real, and the same PoC re-tests the fix.
"""
import argparse
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import enrich
import llm
import run_patch_loop as loop
from catalog import CLASSES, judge_fingerprint
from scorerisk import FINGERPRINT_VERSION, fingerprint, score_all

EVIDENCE_DIR = Path("evidence")
WORKERS = 4  # independent sandbox runs, searches and model calls go in parallel
PROTECTED_EVIDENCE = {"golden_run", "run_with_repair", "ranking", "sensitivity", "isolation_check"}


def evidence_path(save_as, stamp):
    """Where this run's evidence goes. A --save-as name can never overwrite recorded evidence.

    Checked BEFORE the pipeline starts, so nobody goes through approvals and then fails."""
    if save_as is None:
        return EVIDENCE_DIR / f"run_{stamp}.json"
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", save_as):
        raise SystemExit("--save-as: use only letters, digits, '-' and '_' (max 60 characters)")
    target = EVIDENCE_DIR / f"{save_as}.json"
    if save_as in PROTECTED_EVIDENCE or target.exists():
        raise SystemExit(f"{target} already exists or is protected evidence; choose another name")
    return target


def verdict_for(finding, judge):
    cwe = finding.get("cwe")
    if cwe not in CLASSES:
        return {"verdict": "NOT_VERIFIABLE", "evidence": "no PoC for this class in the MVP"}
    poc_code, evidence = loop.confirm_vulnerability(judge, cwe)
    verdict = {1: "CONFIRMED", 0: "NOT_REPRODUCIBLE"}.get(poc_code, "ERROR")
    return {"verdict": verdict, "evidence": evidence}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--top", type=int, default=8, help="how many top findings enter verification")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--eval-only", action="store_true")
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--no-enrich", action="store_true", help="skip the Tavily evidence step")
    parser.add_argument("--save-as", metavar="NAME", help="write the evidence to evidence/NAME.json (never overwrites recorded runs)")
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = evidence_path(args.save_as, stamp)  # fail fast, before any approval is asked
    export_dir = loop.EXPORTS / out.stem    # this run's own export folder: an earlier diff is never replaced
    if export_dir.exists():
        raise SystemExit(f"{export_dir} already exists; choose another --save-as name")

    started = time.time()
    calls_before = len(llm.usage_lines())
    judge, where = loop.choose_judge(args.local)
    if not args.local:
        from sandbox_judge import warm_up

        warm_up()  # build the dependency checkpoint once, before parallel runs

    ranked, threat = score_all()
    top = ranked[: args.top]
    print(f"=== 1. ScoreRisk (rule, not a model) | threat data from {threat['fetched_at'][:10]} ===")
    for r in top:
        cvss = f"{r['cvss']:.1f}" if r["cvss"] is not None else "n/a"
        print(f"  #{r['rank']} {r['id']} score {r['pre_score']:>5}  CVSS {cvss:>4}  {r['title']}")

    print(f"\n=== 2. Verification of the top {args.top} in {where} ===")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        verdict_list = list(pool.map(lambda r: verdict_for(r, judge), top))
    verdicts = {r["id"]: v for r, v in zip(top, verdict_list)}
    for r in top:
        print(f"  {r['id']}: {verdicts[r['id']]['verdict']}")

    enrichment = {}
    to_enrich = [
        r for r in top
        if verdicts[r["id"]]["verdict"] == "NOT_VERIFIABLE" and r["cve"] and not args.no_enrich
    ]
    if to_enrich:
        print("\n=== 2b. Public evidence for what execution cannot verify (Tavily + Nemotron) ===")
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            infos = list(pool.map(enrich.enrich_finding, to_enrich))
        for r, info in zip(to_enrich, infos):
            enrichment[r["id"]] = info
            if "skipped" in info or "error" in info:
                print(f"  {r['id']}: skipped ({info.get('skipped') or info.get('error')})")
            else:
                a = info.get("assessment") or {}
                print(
                    f"  {r['id']}: {len(info['sources'])} sources | exploited in the wild: "
                    f"{a.get('exploited_in_the_wild', 'n/a')} | public exploit code: "
                    f"{a.get('public_exploit_code', 'n/a')}"
                )

    print("\n=== 3. Patch + re-test ===")
    confirmed_rows = [r for r in top if verdicts[r["id"]]["verdict"] == "CONFIRMED"]
    prepared = False
    if confirmed_rows and not args.eval_only:
        print(f"  asking Nemotron for {len(confirmed_rows)} patch(es) in parallel ...")
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            list(pool.map(
                lambda r: loop.generate_candidate(r["cwe"], verdicts[r["id"]]["evidence"]), confirmed_rows
            ))
        prepared = True

    patches = {}
    for r in confirmed_rows:
        print(f"\n--- {r['id']}: {r['title']} ---")
        patches[r["id"]] = loop.patch_cycle(
            judge, where, r["cwe"], verdicts[r["id"]]["evidence"],
            auto_yes=args.yes, generate=not args.eval_only, prepared=prepared, export_dir=export_dir,
        )
    if not patches:
        print("  nothing confirmed, nothing to patch")

    def status(finding_id):
        patch = patches.get(finding_id)
        if patch and patch["accepted"]:
            extra = f" (after {patch['attempts']} attempts)" if patch.get("attempts", 1) > 1 else ""
            if not patch.get("exported", True):
                return "CONFIRMED -> patch accepted by the judge, export not approved" + extra
            return "CONFIRMED -> PATCHED, same PoC now fails" + extra
        if patch and not patch["approved"]:
            return "CONFIRMED -> patch proposed, not run (no approval)"
        if patch:
            return "CONFIRMED -> patch REJECTED by PoC/tests"
        return verdicts.get(finding_id, {}).get("verdict", "not verified (outside top N)")

    # Confirmed findings jump to the top regardless of pre-score; the rest keep their order.
    final = sorted(
        ranked,
        key=lambda r: (verdicts.get(r["id"], {}).get("verdict") != "CONFIRMED", -r["pre_score"], r["id"]),
    )
    new_calls = llm.usage_lines()[calls_before:]
    cost = sum(c["est_cost_usd"] for c in new_calls)
    tokens = sum(c["prompt_tokens"] + c["completion_tokens"] for c in new_calls)
    human_review = sum(p.get("human_wait_s", 0.0) for p in patches.values())
    seconds = round(time.time() - started - human_review, 1)  # machine time only

    print("\n=== 4. Result ===")
    for pos, r in enumerate(final[:8], 1):
        print(f"  {pos}. {r['id']} (ScoreRisk #{r['rank']}) {r['title']}  [{status(r['id'])}]")
    print(f"\nNemotron calls: {len(new_calls)} | tokens: {tokens} | est. cost: ${cost:.5f} | machine time: {seconds}s "
          f"(+ {human_review:.0f}s of human review)")

    EVIDENCE_DIR.mkdir(exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "run_at": stamp, "executor": where, "top_n": args.top, "model": llm.MODEL,
                "inventory_fingerprint": fingerprint(), "fingerprint_version": FINGERPRINT_VERSION,
                "judge_fingerprint": judge_fingerprint(),
                "final_order": [
                    {"position": i, "id": r["id"], "scorerisk_rank": r["rank"], "pre_score": r["pre_score"],
                     "cvss": r["cvss"], "status": status(r["id"])}
                    for i, r in enumerate(final, 1)
                ],
                "verdicts": verdicts, "patches": patches, "enrichment": enrichment,
                "usage": {"nemotron_calls": len(new_calls), "tokens": tokens, "est_cost_usd": round(cost, 6)},
                "duration_s": seconds, "human_review_s": round(human_review, 1),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Evidence written to {out}")
    raise SystemExit(0 if all(p["accepted"] for p in patches.values()) else 1)


if __name__ == "__main__":
    main()
