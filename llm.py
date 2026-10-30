"""Single entry point for every Nemotron call: logs tokens, latency and cost.

Every call appends one JSON line to logs/usage.jsonl. Read it with usage_report.py.
"""
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # the lean install (requirements.txt): prices and the usage log still work, chat() does not
    load_dotenv = None

if load_dotenv:
    load_dotenv()

BASE_URL = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
MODEL = os.getenv("NEBIUS_MODEL", "nvidia/nemotron-3-super-120b-a12b")
# USD per 1M tokens, from a third-party price listing. Confirm in the Token
# Factory console and override in .env if they differ.
PRICE_IN_PER_M = float(os.getenv("PRICE_IN_PER_M", "0.30"))
PRICE_OUT_PER_M = float(os.getenv("PRICE_OUT_PER_M", "0.90"))
LOG_PATH = Path(__file__).parent / "logs" / "usage.jsonl"
_LOG_LOCK = threading.Lock()  # the pipeline calls chat() from several threads


def usage_lines():
    """All logged calls so far (lets a pipeline report the cost of its own run)."""
    if not LOG_PATH.exists():
        return []
    return [json.loads(line) for line in LOG_PATH.read_text(encoding="utf-8").splitlines() if line]


def chat(purpose, messages, **kwargs):
    """Call Nemotron and log the usage. `purpose` groups calls in the report."""
    from openai import APIStatusError, OpenAI  # requirements-pipeline.txt

    api_key = os.getenv("NEBIUS_API_KEY")
    if not api_key:
        raise SystemExit("Missing NEBIUS_API_KEY. Copy .env.example to .env and paste your key.")

    client = OpenAI(base_url=BASE_URL, api_key=api_key)
    started = time.time()
    try:
        response = client.chat.completions.create(model=MODEL, messages=messages, **kwargs)
    except APIStatusError as exc:
        hint = ""
        if exc.status_code in (401, 402, 403):
            hint = " Check the API key and the account balance (trial credit expires after 30 days)."
        raise SystemExit(f"Token Factory error {exc.status_code}: {exc.message}.{hint}") from exc
    latency = time.time() - started

    usage = response.usage
    details = getattr(usage, "completion_tokens_details", None)
    reasoning = (getattr(details, "reasoning_tokens", 0) or 0) if details else 0
    # Reasoning tokens are part of completion_tokens, so they are billed as output.
    cost = (
        usage.prompt_tokens * PRICE_IN_PER_M + usage.completion_tokens * PRICE_OUT_PER_M
    ) / 1_000_000

    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "purpose": purpose,
        "model": response.model,
        "prompt_tokens": usage.prompt_tokens,
        "completion_tokens": usage.completion_tokens,
        "reasoning_tokens": reasoning,
        "latency_s": round(latency, 2),
        "est_cost_usd": round(cost, 6),
    }
    with _LOG_LOCK:
        LOG_PATH.parent.mkdir(exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    print(
        f"[usage] {purpose}: in={usage.prompt_tokens} out={usage.completion_tokens} "
        f"(reasoning={reasoning}) {latency:.1f}s ~${cost:.5f}"
    )
    return response
