"""Summarize logs/usage.jsonl: calls, tokens and estimated cost per purpose.

Usage: python usage_report.py
"""
import json
from collections import defaultdict
from pathlib import Path

LOG_PATH = Path(__file__).parent / "logs" / "usage.jsonl"


def main():
    if not LOG_PATH.exists():
        raise SystemExit("No usage yet. Make a Nemotron call first.")

    rows = [json.loads(line) for line in LOG_PATH.read_text(encoding="utf-8").splitlines() if line]
    groups = defaultdict(list)
    for row in rows:
        groups[row["purpose"]].append(row)

    print(f"{'purpose':<18}{'calls':>6}{'in':>9}{'out':>9}{'reason':>8}{'avg s':>7}{'USD':>10}")
    for purpose, items in sorted(groups.items()):
        print(
            f"{purpose:<18}{len(items):>6}"
            f"{sum(r['prompt_tokens'] for r in items):>9}"
            f"{sum(r['completion_tokens'] for r in items):>9}"
            f"{sum(r['reasoning_tokens'] for r in items):>8}"
            f"{sum(r['latency_s'] for r in items) / len(items):>7.1f}"
            f"{sum(r['est_cost_usd'] for r in items):>10.5f}"
        )
    total_tokens = sum(r["prompt_tokens"] + r["completion_tokens"] for r in rows)
    total_cost = sum(r["est_cost_usd"] for r in rows)
    print(f"\nTOTAL: {len(rows)} calls, {total_tokens} tokens, ~${total_cost:.5f} (estimate)")
    print("Prices are estimates; the source of truth is the Token Factory console.")


if __name__ == "__main__":
    main()
