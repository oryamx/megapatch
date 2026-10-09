# MegaPatch

**Rank what matters, prove it is exploitable by running the exploit, patch it, and re-run the same exploit to prove the fix.**

Built for the Nebius x NVIDIA Global AI Hackathon 2026 (track: Coding and Agentic Engineering).

> Status: work in progress, hackathon submission due 2026-10-30. This README only describes what exists today.

## The idea

A scanner gives you thousands of findings, all with a CVSS score, so everything looks critical. MegaPatch does three things in one flow:

1. **Prioritize with exploitation data, not severity alone.** ScoreRisk is a deterministic rule (not a model): `100 * (0.50*E + 0.30*X + 0.20*S)` where E is exploitability (EPSS, CISA KEV), X is the exposure of the asset, and S is the CVSS base score. A CVSS 9.8 that nobody exploits ranks below a CVSS 7.5 that is in KEV and internet-facing.
2. **Verify by execution.** The top findings go to an isolated Nebius Sandbox where a proof-of-concept exploit runs. The result is a verdict (`CONFIRMED`, `NOT_REPRODUCIBLE`, or `NOT_VERIFIABLE` for classes without a PoC), not an opinion.
3. **Patch and re-test.** Nemotron writes the fix. The **same** exploit and the functional tests judge it. The model proposes; the exploit and the tests decide. A human approves before any model-written code runs.

## Where Nebius and NVIDIA are used

| Piece | What it does here |
|---|---|
| **NVIDIA Nemotron 3 Super** (`nvidia/nemotron-3-super-120b-a12b`) | Writes the security patch from the exploit evidence. |
| **Nebius Token Factory** (OpenAI-compatible API) | Serves Nemotron at runtime (`llm.py`). Every call is logged with tokens, latency and estimated cost. |
| **Nebius Token Factory Sandboxes** (beta, `contree-sdk`) | Runs the PoC, the tests and the model-written patch in an isolated environment, never on the developer's machine (`sandbox_judge.py`). |

## Quickstart

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

**1. Verify the claim yourself, no credentials needed:**

```bash
python judge_check.py
```

It runs three exploits (SQL injection, OS command injection, path traversal) against the vulnerable practice app (expect `VULNERABLE`) and against a known-good fix (expect `SAFE`), runs the functional tests on both, and checks that ScoreRisk is deterministic.

**2. See the ranking (offline, deterministic):**

```bash
python scorerisk.py
python sensitivity.py   # does the ranking survive different weights?
```

**3. Run the full pipeline** (needs a Nebius Token Factory account, API key and Sandboxes access):

```bash
cp .env.example .env    # then fill NEBIUS_API_KEY and NEBIUS_PROJECT_ID
python megapatch.py
```

The pipeline ranks the findings, verifies the top 8 in the sandbox, asks Nemotron for a patch for each confirmed one, shows you the diff, and, after you approve, judges it in the sandbox. Output goes to `evidence/run_<timestamp>.json`. Useful flags: `--top N`, `--yes`, `--eval-only`, `--local`.

## What the data is (and is not)

- **Real:** CVE identifiers, EPSS (FIRST), CISA KEV membership and CVSS base scores (NVD), frozen in `data/threat_data.json` so results are reproducible. Refresh with `python fetch_threat_data.py`.
- **Fictional:** the inventory in `data/findings.json` (a made-up project called demo-shop) and the exposure of its assets. Weights and constants in `scorerisk.py` are starting points, not validated values; `sensitivity.py` checks which conclusions depend on them.
- **Verifiable in the MVP:** only the three vulnerability classes of our own practice app (`target_app/`). Other findings are ranked but reported as `NOT_VERIFIABLE`, never as safe.
- **Not measured yet:** we do not claim any precision figure for the ranking.

## Safety and scope

- Everything runs against applications built for practice and prepared by the team, in an isolated sandbox.
- No third-party systems, repositories or accounts are touched.
- No real credentials inside the sandbox; the practice app only contains fake secrets.
- A human approves before any model-written code is executed.
- Defensive security lab: the goal is to shorten the time between finding and fixing, not to enable attacks. The PoCs only target the bundled practice app and only echo a marker or read its own fake file.

## License

Apache License 2.0, see [LICENSE](LICENSE).
