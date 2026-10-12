# MegaPatch

**Rank what matters, prove it is exploitable by running the exploit, patch it, and re-run the same exploit to prove the fix.**

Built for the Nebius x NVIDIA Global AI Hackathon 2026 (track: Coding and Agentic Engineering).

> Status: work in progress, hackathon submission due 2026-10-30. This README only describes what exists today.

**Live demo (read-only dashboard):** https://megapatch.streamlit.app/ — it shows a recorded real run. If the page says the app is asleep, press the wake-up button (free hosting sleeps after inactivity; it is back in about a minute). Everything in it can also be reproduced offline with `python judge_check.py`.

## The idea

A scanner gives you a long list of findings, all with a CVSS score, so everything looks critical. In our demo, pip-audit reported 124 entries on nine deliberately outdated pinned Python packages (69 distinct advisories, 62 distinct CVEs; the scanner lists some advisories twice); only one of those CVEs is in CISA's KEV catalog. MegaPatch does three things in one flow:

1. **Prioritize with exploitation data, not severity alone.** ScoreRisk is a deterministic rule (not a model): `100 * (0.50*E + 0.30*X + 0.20*S)` where E is exploitability (EPSS, CISA KEV), X is the exposure of the asset, and S is the CVSS base score. A CVSS 9.8 that is almost never exploited ranks below a lower-CVSS finding that is in KEV and internet-facing.
2. **Verify by execution.** The top findings go to an isolated Nebius Sandbox where a proof-of-concept exploit runs. The result is a verdict (`CONFIRMED`, `NOT_REPRODUCIBLE`, or `NOT_VERIFIABLE` for classes without a PoC), not an opinion.
3. **Patch and re-test.** Nemotron writes the fix. The **same** exploit and the functional tests judge it. If the judge rejects a patch, its output goes back to the model for one repair attempt. The model proposes; the exploit and the tests decide.

Model-written code runs only inside the isolated Nebius sandbox (we place no secrets in it; what it can and cannot reach is documented under "Safety and scope"), so it runs automatically. **A human approves each patch accepted by the judge before it is exported** (`out/patches/*.diff`). With `--local`, which runs the judge on your own machine, the human approves before anything runs.

Input is real scanner output: **pip-audit** (software composition analysis) over `scans/requirements.txt` and **Bandit** (static analysis) over our practice app, parsed by `ingest.py`. The scanner outputs are frozen in `scans/` so results are reproducible.

## Where Nebius and NVIDIA are used

| Piece | What it does here |
|---|---|
| **NVIDIA Nemotron 3 Super** (`nvidia/nemotron-3-super-120b-a12b`) | Writes the security patch from the exploit evidence. |
| **Nebius Token Factory** (OpenAI-compatible API) | Serves Nemotron at runtime (`llm.py`). Every call is logged with tokens, latency and estimated cost. |
| **Nebius Token Factory Sandboxes** (beta, `contree-sdk`) | Runs the PoC, the tests and the model-written patch in an isolated environment, never on the developer's machine (`sandbox_judge.py`). |
| **Tavily** (runtime web search) | For findings that execution cannot verify, searches public advisories and exploit reports; Nemotron summarizes only what the cited sources support (`enrich.py`). It never changes the ScoreRisk number. Optional: skipped when `TAVILY_API_KEY` is not set. |

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
pip install -r requirements-pipeline.txt
cp .env.example .env    # then fill NEBIUS_API_KEY and NEBIUS_PROJECT_ID (TAVILY_API_KEY is optional)
python megapatch.py
```

The pipeline ranks the findings, verifies the top 8 in the sandbox, asks Nemotron for a patch for each confirmed one, judges it in the sandbox (model-written code runs only there), repairs a rejected patch once, and then asks you to approve each patch **accepted by the judge** before it is exported to `out/patches/`. Output goes to `evidence/run_<timestamp>.json`. Useful flags: `--top N`, `--yes`, `--eval-only`, `--local`, `--no-enrich`.

**4. Look at the result** in a browser:

```bash
streamlit run dashboard.py
```

The dashboard shows the prioritized queue, the before/after proof for each patch, the public evidence for findings that execution cannot verify, and why the order is what it is. It needs no credentials.

**5. Analyze one finding from the dashboard (local, opt-in).** With `NEBIUS_API_KEY`, `NEBIUS_PROJECT_ID` and `MEGAPATCH_ENABLE_INTERACTIVE=1` in your `.env`, the dashboard's *Analyze (local)* tab runs the loop on one finding: it shows each stage as it happens, then the **same PoC** before and after the patch, then waits. **Nothing is exported until you click Approve**, and only a patch the judge accepted can be approved. Each analysis gets its own session id (a UTC timestamp plus random characters, so two sessions started in the same second get different ids); if a collision ever happened, it is rejected without overwriting any file. Your decision is recorded in a new `evidence/interactive_run_<session id>.json` and an approved diff goes to a new `out/patches/<session id>/` folder; existing files are never overwritten. On approval the record is written first with `exported: false` and `export_status: "pending"`, then the diff, and only once the diff is confirmed on disk is the record finalized as `exported: true`. If the process stops in between, the record keeps saying `pending` (never `exported: true`; the diff at `export_target` may or may not exist), and if the diff cannot be written the record says `export_status: "failed"` with the error. A diff is never left without its record, and cleanup only removes files the call itself created. The dashboard's patch detail follows `export_status` (exported, pending, failed, declined): `exported: false` alone is never shown as a refusal by the person, and only `declined` says so. `python check_export_state.py` tests that, including the dashboard rendered headless from a temporary copy. The command-line flow is unchanged. Live runs are off on the public demo (they need your credentials and the explicit flag). The same limits apply as everywhere else: the PoCs call the app in-process, not over HTTP; the sandbox's network is not blocked; "accepted by the judge" is not "safe in production". `python check_interactive.py` tests these rules with fake model and judge functions, and `judge_check.py` runs it.

The repository ships four recorded runs, selectable in the sidebar. Each one states how its patches were approved, read from its own data:

| Recorded run | What it shows | How the patches were approved |
|---|---|---|
| `evidence/golden_run.json` | Three patches accepted by the judge at the first attempt | **Automatic (`--yes`)**: no person approved anything |
| `evidence/run_with_repair.json` | One patch rejected by the judge, then repaired by Nemotron using the judge's output | **Automatic (`--yes`)**: no person approved anything |
| `evidence/human_approved_run.json` | Three patches accepted by the judge at the first attempt, run without `--yes` | **Human, on the judge-accepted patch**: the sandbox ran the model's code automatically, then a person was asked about each patch the judge had accepted and approved two of the three (`CWE-78`, `CWE-89`) and declined one (`CWE-22`). The declined path traversal patch compared path strings with `startswith`; the judge of that time only tried `../secret.txt` and accepted it. The PoC now also tries a sibling directory whose name starts with `public`. This run predates that check, was not re-judged, and was not edited |
| `evidence/human_approved_run_b.json` | Three patches (`CWE-78`, `CWE-89`, `CWE-22`), all accepted by the judge at the first attempt and all approved for export, run without `--yes`. The only run made with the current judge (fingerprint `b2dbcb16a570b350`) | **Human, on the judge-accepted patch**: the sandbox ran the model's code automatically, and the record marks each of the three approvals as `human` and each patch as exported. The record does not say who answered. **No patch was rejected or declined in this run**, so it is not evidence of the rejection that the re-judge record shows; it only shows the current judge accepting three patches. Its `export_path` values (`out\patches\CWE-*.diff`) are relative to the working copy the run was executed from, a copy of the code made so that approving could not overwrite earlier exports. Those `.diff` files are not in this repository (`out/` is not published); the diff of each patch is stored in the record. This run is not covered by the re-judge record, and was not edited |

Only `evidence/human_approved_run.json` and `evidence/human_approved_run_b.json` show export decisions marked as made by a person. `evidence/golden_run.json` and `evidence/run_with_repair.json` must not be read as human approval: both used `--yes`. In `human_approved_run.json` and `human_approved_run_b.json` the decision is recorded per patch (`exported: true/false`); the records only say `human` and do not record who answered. `python judge_check.py` verifies that `human_approved_run_b.json` corresponds to the current inputs, was made by the current judge, contains exactly the patches `bandit:CWE-78`, `bandit:CWE-89` and `manual:CWE-22`, and that each of them was accepted at the first attempt, marked `human` and exported. Runs made with the current code store a fingerprint (version 2) of the full findings, threat data, parameters and computed ranking they were made with, and the dashboard hides runs that do not match the current inputs. **`run_with_repair.json` is a legacy run**: it was recorded just before that fingerprint existed and carries a partial version-1 fingerprint, which covered the finding ids plus some metadata and parameters (the threat-data download date, the KEV catalog version, and the scoring weights and constants) but not the full findings, the full threat data or the computed ranking. It was not edited afterwards; instead the dashboard matches it by identical finding ids, labels it as legacy, and `python judge_check.py` verifies that its recorded ranks, scores and CVSS equal the current ranking.

## Action bands

Each finding gets a band named after CISA's SSVC outcomes (Act, Attend, Track\*, Track). This is a **simplified, project-specific rule table, not CISA's SSVC decision tree**, defined in `bands.py`:

| Band | Rule |
|---|---|
| Act | Exploit confirmed in the sandbox, or in CISA KEV and internet-facing |
| Attend | In KEV but internal, or EPSS at or above a project parameter (0.50) |
| Track\* | Internet-facing with no exploitation evidence |
| Track | No strong signal |

Every band shows its basis. Asset exposure is declared in `data/assets.json`, so a band for a finding that was not verified by execution (for example the KEV-listed libwebp issue reported through Pillow) is built from KEV/EPSS plus declared exposure, not from an exploit run.

## What the data is (and is not)

- **Real:** CVE identifiers, EPSS (FIRST), CISA KEV membership and CVSS base scores (NVD), frozen in `data/threat_data.json` so results are reproducible. Refresh with `python fetch_threat_data.py`.
- **Real scanner output, deliberately chosen input:** pip-audit ran over nine pinned packages that we picked because they are old (so the scanner has a lot to say), and Bandit ran over our own practice app. Bandit flagged two of our three vulnerability classes; the path traversal was added from manual review and is labeled as such.
- **Declared, fictional context:** which asset each package or file belongs to and how exposed that asset is (`data/assets.json`). Weights and constants in `scorerisk.py` are starting points, not validated values; `sensitivity.py` checks which conclusions depend on them (it varies the weights, not these declared inputs).
- **Verifiable in the MVP:** only the three vulnerability classes of our own practice app (`target_app/`). Other findings are ranked but reported as `NOT_VERIFIABLE`, never as safe.
- **Not measured yet:** we do not claim any precision figure for the ranking.
- **The public-evidence step is not reproducible run to run.** Web results and the model's summary can change between runs (we observed it). That is why it never enters the score; each run stores the sources and the summary it saw.
- **The judge only judges what the tests cover.** A patch can pass the PoC and the tests and still differ in behavior outside them. For example, a "fix" that blacklists the exact payload used by the PoC would pass it; the PoC tests one payload per class, not every payload.
- **The path traversal check was strengthened after the recorded runs, because a person declined a patch the judge had accepted.** That patch used a `startswith` comparison on path strings. The first PoC only tried `../secret.txt`; the PoC now also tries `../public_backup/backup.txt`, a sibling directory whose name starts with `public`, and `judge_check.py` includes a `startswith` patch that must be rejected. `golden_run.json`, `run_with_repair.json` and `human_approved_run.json` predate this check and `human_approved_run_b.json` was made with it; each new run stores a `judge_fingerprint`, a hash of exactly these nine files: `harness.py`, `test_target_app.py`, `target_app/app.py`, `judge.py`, `sandbox_judge.py`, `catalog.py`, `poc_sqli.py`, `poc_cmdi.py` and `poc_path.py` (what it does not cover is listed in the bullet below), and the dashboard tells you when a run was judged with a different version.
- **A separate re-judge record exists** (`evidence/rejudge_<judge fingerprint>.json`, made by `python rejudge.py`). It rebuilds each patch stored in `golden_run.json`, `run_with_repair.json` and `human_approved_run.json` (`human_approved_run_b.json` was made with the current judge and is not part of this record) from its diff, checks that the diff round-trips against the vulnerable app of that time, applies the same change to the current app and judges it again in the sandbox with the current PoCs and tests. For every patch it stores the run file and its hash, the diff hash, the CWE, the original verdict, the verdict of the current judge, the judge fingerprint, the sandbox's package versions and the judge's output. It is not part of any recorded run, exports nothing and calls no model. Result: of the 9 recorded patches, 8 are still accepted and 1 (the path traversal patch that a person declined to export) is rejected by the current judge. `python judge_check.py` verifies the record: that each result points at its run by hash and the run is unmodified, that each `diff_sha256` equals the diff stored in that run, that the original verdicts copied into the record equal the run's own data, that every `verdict_changed` flag follows from them, that each new verdict follows from its stored `poc_exit` and `tests_exit` by the acceptance rule in `judge.py`, that the record covers exactly every patch of those three source runs once (no omissions, no duplicates), and that the summary totals add up. **If the judge changed after the record was made, the check fails and prints a `STALE RE-JUDGE RECORD` notice** instead of ending in `ALL PASSED`; the fix is to re-run `python rejudge.py --force`.
- **What the judge fingerprint covers, and what it does not.** It hashes the PoCs, the functional tests, the harness, the vulnerable app, `catalog.py`, `sandbox_judge.py` and `judge.py` (the acceptance rule and the local executor). It does not cover the packages installed inside the sandbox at run time (`flask` and `pytest` are installed unpinned; the re-judge record stores the versions it saw), the `contree-sdk` version, or Nebius's platform behavior.
- **Exploitability uses EPSS and CISA KEV only.** "A public exploit exists" is not a separate signal in the score. The sandbox PoC covers that question for the findings we can execute.
- **Scanner outputs are frozen fixtures.** `ingest.py` parses real pip-audit and Bandit JSON, but the pipeline does not run the scanners itself nor clone a repository. Refresh the fixtures with `pip-audit -r scans/requirements.txt --no-deps --disable-pip -f json -o scans/pip_audit.json` and `bandit -r target_app -f json -o scans/bandit.json`, then `python fetch_threat_data.py`.
- **The PoCs call the app in-process** through Flask's test client. They show that the code executes the payload and that a patch blocks it; they do not test network reachability, and `NOT_REACHABLE` is not implemented.
- **The safety guarantees apply to the default path.** `--yes` skips every human approval question and `--local` runs the judge on the developer's machine instead of an isolated sandbox. Both exist for development and offline checks; every recorded run is labeled with how it was approved (`approval` in `evidence/*.json`). The recorded demo run was made with `--yes`.
- **Sandbox runs from one checkpoint, but patches do not compete yet.** Dependencies are installed once and every judge run starts from that checkpoint; we generate one candidate per finding (plus one repair attempt), not several competing candidates.

## Data sources and attribution

- **CISA Known Exploited Vulnerabilities (KEV) Catalog**, https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **EPSS** (Exploit Prediction Scoring System) data provided by FIRST, https://www.first.org/epss/
- **CVSS base scores** from the NVD. *This product uses data from the NVD API but is not endorsed or certified by the NVD.*

## How this was built

Developed during the hackathon submission period (the code in this repository was written after 2026-08-26). It was built with AI coding assistance (Claude Code); the commit history carries a `Co-Authored-By` trailer. The product runs on Nemotron through Nebius Token Factory and executes untrusted code only inside Nebius Sandboxes.

## Safety and scope

- Everything runs against applications built for practice and prepared by the team, in an isolated sandbox.
- Exploits and PoCs only ever target the bundled practice app. No third-party system, repository or account is attacked or scanned.
- External services the project does call: Nebius Token Factory and Sandboxes (inference and execution); Tavily (web search, optional); and, only when refreshing data, CISA KEV, FIRST EPSS, the NVD API, and PyPI/OSV during the scanner runs. `isolation_check.py` additionally opens one TCP connection to `pypi.org:443` (a host `pip` already uses) and sends no application data, only to observe whether outbound traffic is possible.
- No real credentials inside the sandbox; the practice app only contains fake secrets.
- Model-written code runs only inside the isolated Nebius sandbox. In `--local` mode it would run on your machine, so there a human approves **before** it runs.
- A human approves each patch **accepted by the judge** before it is exported.
- What was observed inside the sandbox (`python isolation_check.py` writes `evidence/isolation_check.json`; these are observations, not guarantees):
  - its environment variables are the base image's own, with no Nebius or Tavily variables; we pass no secrets into it;
  - its working directory contains only the files we upload;
  - we looked for the developer's drives at `/c`, `/mnt` and `/host` and found nothing there; the sandbox's root filesystem is a `virtiofs` mount supplied by Nebius's infrastructure. That is a statement about the paths we checked, not proof about the platform's internal isolation;
  - **outbound network is not blocked** (one TCP connect to `pypi.org:443` succeeded; the sandbox needs it for `pip`) and code runs as root inside the sandbox.

  So "isolation" here means "nothing sensitive is placed in it and it is not our machine", not "it cannot reach the internet".
- Defensive security lab: the goal is to shorten the time between finding and fixing, not to enable attacks. The PoCs only target the bundled practice app and only echo a marker or read its own fake file.

## License

Apache License 2.0, see [LICENSE](LICENSE).
