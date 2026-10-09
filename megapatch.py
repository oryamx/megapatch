"""MegaPatch pipeline: rank -> verify -> patch -> re-test -> evidence.

Usage:
  python megapatch.py                run the whole pipeline (judge in the Nebius sandbox)
  python megapatch.py --top 5        only the top 5 enter verification (shows the budget logic)
  python megapatch.py --yes          skip the human approval question
  python megapatch.py --eval-only    reuse the existing candidate patches (no model call)
  python megapatch.py --local        judge on this machine instead of the sandbox

Patch generation always calls Nemotron on Nebius Token Factory.
"The score proposes, execution disposes": ScoreRisk orders the findings, the
sandbox PoC decides which are real, and the same PoC re-tests the fix.
"""
import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import llm
import run_patch_loop as loop
from catalog import CLASSES
from scorerisk import score_all

EVIDENCE_DIR = Path("evidence")


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
    args = parser.parse_args()

    started = time.time()
    calls_before = len(llm.usage_lines())
    judge, where = loop.choose_judge(args.local)

    ranked, threat = score_all()
    print(f"=== 1. ScoreRisk (rule, not a model) | threat data from {threat['fetched_at'][:10]} ===")
    for r in ranked[: args.top]:
        print(f"  #{r['rank']} {r['id']} score {r['pre_score']:>5}  CVSS {r['cvss']:>4}  {r['title']}")

    print(f"\n=== 2. Verification of the top {args.top} in {where} ===")
    verdicts = {}
    for r in ranked[: args.top]:
        verdicts[r["id"]] = verdict_for(r, judge)
        print(f"  {r['id']}: {verdicts[r['id']]['verdict']}")

    print("\n=== 3. Patch + re-test ===")
    patches = {}
    for r in ranked[: args.top]:
        if verdicts[r["id"]]["verdict"] == "CONFIRMED":
            print(f"\n--- {r['id']}: {r['title']} ---")
            patches[r["id"]] = loop.patch_cycle(
                judge, where, r["cwe"], verdicts[r["id"]]["evidence"],
                auto_yes=args.yes, generate=not args.eval_only,
            )
    if not patches:
        print("  nothing confirmed, nothing to patch")

    def status(finding_id):
        patch = patches.get(finding_id)
        if patch and patch["accepted"]:
            return "CONFIRMED -> PATCHED, same PoC now fails"
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
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = EVIDENCE_DIR / f"run_{stamp}.json"
    out.write_text(
        json.dumps(
            {
                "run_at": stamp, "executor": where, "top_n": args.top, "model": llm.MODEL,
                "final_order": [
                    {"position": i, "id": r["id"], "scorerisk_rank": r["rank"], "pre_score": r["pre_score"],
                     "cvss": r["cvss"], "status": status(r["id"])}
                    for i, r in enumerate(final, 1)
                ],
                "verdicts": verdicts, "patches": patches,
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
