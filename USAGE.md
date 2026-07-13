# Threat Automation — Step-by-Step Usage Guide

This guide covers **local Python** and **Docker Compose** workflows for the full threat intelligence pipeline: RSS ingestion → dynamic filter → grounded rule generation → deterministic validation → human triage → production.

Run CLI commands from the **repository root** (`Threat_automation/`).

---

## Quick reference

| Goal | Local | Docker |
|------|-------|--------|
| Ingest RSS | `python main_ingestion.py` | `docker compose run --rm step1-ingestion` |
| Filter threats | `python main_filter.py` | `docker compose run --rm step2-filter` |
| Generate rules | `python main_generator.py` | `docker compose run --rm step3-generator` |
| Validate rules | `python main_validator.py` | `docker compose run --rm step4-validator` |
| Threat stream UI | `streamlit run app.py` | `docker compose up -d threat-dashboard` |
| Triage dashboard | `streamlit run app_triage.py --server.port 8502` | *(local only)* |
| Feedback loop | `python main_feedback.py` | *(local only)* |

**Operational scripts:** `main_ingestion.py` → `main_filter.py` → `main_generator.py` → `main_validator.py` → `app_triage.py` → `main_feedback.py`

---

## Current behavior

| Area | Behavior |
|------|----------|
| **Feed coverage** | **198 RSS feeds** across 14 categories — major news outlets, government CERTs, threat intel platforms, vendor research, cloud security, detection engineering, and community sources. |
| **Ingestion** | Only RSS items **published in the last 7 days** (UTC). Undated or older items are dropped. Each article stores `published_at`. |
| **Dedup state** | `data/ingestion_dedup_state.json` stores SHA-256 fingerprints (`title\|url`) so re-runs skip duplicates. |
| **Patch advisory filter** | Generic vendor bulletins (e.g. "Monthly Security Update", "Patch Tuesday", "Security Bulletin") are dropped at Step 2 before Gemma, regardless of CVE presence. |
| **CVE patch filter** | Articles citing CVEs in a patched/historical context are dropped. |
| **Dynamic filter** | Gemma 4 strict JSON router (`temperature=0`). Pass: `is_relevant=true` **and** `confidence_score >= 6`. |
| **Filtered queue** | Merges with prior runs, sorts by **confidence then date**, **caps at 50**. |
| **Rule generation** | `phi4-mini-reasoning` generates **exactly 3 strategy-diverse variants** per threat: Process/CLI, File/Registry, Network/API. Strips `<thinking>` blocks before JSON parse. |
| **Validation — Stage 1** | Python contract check: all 7 rule keys present, non-empty, valid severity enum. |
| **Validation — Stage 2** | Python KB lookup: every `actionName` cross-referenced against 30,000+ KB catalog entries. |
| **Validation — Stage 3** | `phi4-mini-reasoning` Sherman Kent CTI audit: 5-section structured report with probability and confidence assessment. |
| **Triage dashboard** | Security engineer 3-column decision panel. One rule wins per threat → production. The other two → feedback queue with justification. Each rejected variant is stamped with its `detection_strategy` for downstream analysis. |
| **Feedback loop** | `phi4-mini-reasoning` reads `failed_feedback_queue.json`, groups rejections by strategy, and distils 2–3 generalized negative constraints per group into `negative_constraints.json`. Processed items are archived to `failed_feedback_history.json` and the queue is cleared. |
| **Threat stream UI** | Read-only Streamlit; auto-refresh 60s; no Ollama or pipeline side effects. |
| **Docker** | Single image `threat-automation:latest`; steps share `./data` volume; Ollama on **host** only. |
| **Repository** | `data/*.json` outputs are **gitignored**; only `data/.gitkeep` is committed. |

---

## Pipeline overview

```
Step 1  main_ingestion.py   RSS feeds (198)  →  data/threat_queue.json
                            (+ data/ingestion_dedup_state.json)
Step 2  main_filter.py      Keyword + Patch Advisory + CVE + Gemma 4
                            →  data/filtered_threat_queue.json  (max 50)
Step 3  main_generator.py   phi4-mini-reasoning + KB  →  data/generated_rules_staging.json
                            (exactly 3 variants per threat: Process / File+Registry / Network)
Step 4  main_validator.py   Stage 1 (contract) + Stage 2 (KB) + Stage 3 (CTI audit)
                            →  data/validated_rules.json
Step 5  app_triage.py       3-column engineer decision panel
                            →  data/prod_detection_rules.json  (approved rules)
                            →  data/failed_feedback_queue.json (rejected with detection_strategy tag)
Step 6  main_feedback.py    phi4-mini-reasoning analyses rejection patterns per strategy
                            →  data/negative_constraints.json  (2–3 constraints per strategy)
                            →  data/failed_feedback_history.json (archive)
                            clears data/failed_feedback_queue.json
UI      app.py              Read-only threat stream (Streamlit :8501)
```

**Ollama models:**

| Step | Model | Config (`ingestion/config.py`) |
|------|-------|--------------------------------|
| 2 — Dynamic Semantic Filter | `gemma4:e4b` | `OLLAMA_MODEL` |
| 3 — Rule generation | `phi4-mini-reasoning` | `OLLAMA_PHI4_MODEL` |
| 4 — CTI cognitive audit (Stage 3) | `phi4-mini-reasoning` | `OLLAMA_PHI4_MODEL` / `STAGE3_TIMEOUT_SECONDS` |
| 6 — Feedback loop | `phi4-mini-reasoning` | `OLLAMA_PHI4_MODEL` / `FEEDBACK_TIMEOUT_SECONDS` |

LiteLLM orchestrator (`main.py`): `REASONING_MODEL=ollama/phi4-mini-reasoning` — see `.env.example`.

---

# Part A — Local Python setup

## A.1 Prerequisites

```bash
cd /path/to/Threat_automation
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows (PowerShell): `.venv\Scripts\Activate.ps1` then `pip install -r requirements.txt`.

## A.2 Ollama (required for Steps 2–4 and Step 6)

**Terminal A — keep running:**

```bash
ollama serve
```

If you see `bind: address already in use`, Ollama is already running — skip this step.

**Terminal B — one-time model pull:**

```bash
ollama pull gemma4:e4b
ollama pull phi4-mini-reasoning
curl http://localhost:11434/api/tags   # verify both models appear
```

## A.3 Knowledge base (optional, recommended for Steps 3–4)

GitHub, Okta, and Azure catalogs ship in-repo. Sync AWS/GCP IAM lists:

```bash
python scripts/sync_knowledge_base.py
```

---

## A.4 Step 1 — Ingest threat intelligence (RSS)

Fetches **198 RSS feeds** across 14 source categories, applies a **7-day publication window**, and deduplicates by title + URL.

- **Keeps** items with `published_at` within `INGESTION_MAX_AGE_DAYS` (default **7**, UTC).
- **Drops** older or undated feed entries.
- **Prunes** `data/threat_queue.json` on export to remove out-of-window rows.

**Dedup file:** `data/ingestion_dedup_state.json` is a fingerprint cache, not article content. Reset with:

```bash
rm data/ingestion_dedup_state.json
```

```bash
python main_ingestion.py
```

| Output | Purpose |
|--------|---------|
| `data/threat_queue.json` | Articles in the ingestion window |
| `data/ingestion_dedup_state.json` | Cross-run dedup hashes |

Change window: `INGESTION_MAX_AGE_DAYS` in `ingestion/config.py`.

---

## A.5 Step 2 — Dynamic Semantic Filter

Gates (in order):

1. **Platform keywords** — AWS, Azure, GitHub, Okta, GCP, etc.
2. **Patch advisory filter** — drops generic vendor bulletins ("Monthly Security Update", "Patch Tuesday", "Security Bulletin", "Security Advisory", "Cumulative Update") regardless of CVE presence.
3. **CVE patch filter** — drops articles that cite CVEs in a fixed/patched/historical context.
4. **Gemma 4** — deterministic JSON classification (`temperature=0`).

**Pass criteria:** `is_relevant == true` AND `confidence_score >= 6` (`MIN_CONFIDENCE_SCORE` in `filters/gemma_verifier.py`).

**`gemma_verdict` schema:**

```json
{
  "is_relevant": true,
  "confidence_score": 8,
  "primary_domain": "Cloud",
  "primary_platform": "AWS",
  "reasoning_summary": "One sentence tied to text in the article."
}
```

Malformed JSON → safe fallback (`MALFORMED_JSON_FALLBACK`); pipeline does not crash.

**Queue logic:** merge existing file → dedupe by URL → sort by confidence then date → **keep top 50**.

```bash
python main_filter.py
python main_filter.py --limit 20
python main_filter.py --skip-gemma          # keyword + patch + CVE gates only (no Ollama)
python main_filter.py --workers 6
```

Console log:

```text
[Dynamic Filter] Title: AWS CloudGoat EC2 SSRF | Domain: Cloud | Score: 8/10
```

---

## A.6 Step 3 — Grounded rule generation (phi4-mini-reasoning)

Generates **exactly 3 structurally diverse detection rule variants** per filtered threat, grounded in knowledge-base `actionNames`.

### Strategy diversity constraint

The model is instructed to produce one rule per telemetry layer — **no slight syntax variations**:

| Variant | Strategy layer | Detection focus |
|---------|---------------|-----------------|
| 1 | 🖥️ Process / CLI | Spawned processes, command-line flags, script invocations, interpreter abuse |
| 2 | 📁 File & Registry | File writes/reads on sensitive paths, registry changes, config drift, persistence artifacts |
| 3 | 🌐 Network / API | Outbound connections, DNS lookups, API/cloud-plane calls, protocol-level indicators |

```bash
python main_generator.py
python main_generator.py --limit 3
python main_generator.py --platforms aws,azure
python main_generator.py --force --no-resume
```

**Input:** `data/filtered_threat_queue.json`  
**Output:** `data/generated_rules_staging.json` (incremental; safe to interrupt)

Requires Ollama with `phi4-mini-reasoning`. Model responses may include `<thinking>` blocks; `generators/rule_engine.py` strips them before parsing the rules JSON. If the model returns more than 3 rules, only the first 3 are kept. Fewer than 3 is logged as a generation failure.

**Resume behaviour:** already-staged threats are skipped automatically. Use `--force --no-resume` to regenerate everything from scratch.

---

## A.7 Step 4 — Deterministic rule validation

Three sequential stages per rule variant — **single write-back** to `data/validated_rules.json` only after all stages complete.

| Stage | Type | What it checks |
|-------|------|----------------|
| **Stage 1** | Pure Python | All 7 contract keys present and non-empty; `defaultSeverity` is `Low/Medium/High/Critical` |
| **Stage 2** | Pure Python | Every `actionName` in the rule exists in the local KB catalogs (30,000+ entries across AWS, GCP, Azure, GitHub, Okta, Active Directory) |
| **Stage 3** | phi4-mini-reasoning | Sherman Kent CTI analytic discipline: 5-section report with probability and confidence assessment |

**Fail-fast:** a variant that fails Stage 1 is not sent to Stage 2 or Stage 3.

```bash
python main_validator.py
python main_validator.py --limit 1          # test with 1 staging entry
python main_validator.py --input data/generated_rules_staging.json --output data/validated_rules.json
```

**Input:** `data/generated_rules_staging.json`  
**Output:** `data/validated_rules.json`

Each passing variant receives a `validation` block:

```json
{
  "validation": {
    "stage": "passed",
    "errors": [],
    "stage3_audit": {
      "is_valid": true,
      "kent_probability_tag": "Likely",
      "audit_rationale": "Executive summary (≤600 chars)…",
      "full_report": "Full 5-section CTI report…",
      "model": "phi4-mini-reasoning",
      "model_error": null
    }
  }
}
```

Failing variants carry `"stage": "failed_stage_1"` or `"failed_stage_2"` with a list of specific `errors`.

**Stage 3 timing:** phi4-mini-reasoning runs its full `<thinking>` chain before writing the CTI report. Expect ~30–90 seconds per variant. With 3 variants × N threats, plan accordingly.

**Environment overrides for Stage 3:**

```bash
OLLAMA_BASE_URL=http://localhost:11434/v1 python main_validator.py
STAGE3_TIMEOUT_SECONDS=600 python main_validator.py   # extend if model is slow
```

---

## A.8 Triage Dashboard — Security Engineer Decision Panel

Human-in-the-loop interface for approving or rejecting validated rule variants. **One rule wins per threat.**

```bash
streamlit run app_triage.py --server.port 8502
```

Open **http://localhost:8502**.

### Layout

Each threat renders as a full-width header block followed by a **3-column comparison grid** — one column per strategy layer (Process/CLI, File/Registry, Network/API) — so the engineer can compare detection approaches side-by-side.

### Decision actions

| Action | Result |
|--------|--------|
| **✅ Approve / Move to Prod** | Variant appended to `data/prod_detection_rules.json`. The other 2 variants automatically sent to `data/failed_feedback_queue.json` with reason: *"Implicitly rejected: Another variant strategy was selected for production by the engineer."* Threat removed from queue. |
| **❌ Reject / Mark Invalid** | Opens a mandatory text area. Engineer types a justification. Submit writes the variant to `data/failed_feedback_queue.json` with the typed reason. Threat remains in queue until one variant is approved. |

### Data files

| File | Written by | Purpose |
|------|-----------|---------|
| `data/validated_rules.json` | Step 4 | Source — entries are removed as threats are triaged |
| `data/prod_detection_rules.json` | Triage | Approved rules ready for SIEM deployment |
| `data/failed_feedback_queue.json` | Triage | Rejected variants with justification for re-generation loop |

All file writes are **atomic** (tmp file → `os.replace`). The dashboard initialises missing output files automatically.

---

## A.9 Step 6 — Automated Feedback Loop (`main_feedback.py`)

Closes the engineering feedback loop: ingests rejected variants from the triage dashboard, groups them by detection strategy, and calls `phi4-mini-reasoning` to distil 2–3 generalized **Negative Constraints** per strategy that prevent the rule-generation model from repeating the same mistakes.

### When to run

Run after engineers have triaged at least one batch of rules through `app_triage.py` and there are items in `data/failed_feedback_queue.json`.

```bash
python main_feedback.py

# Options
python main_feedback.py --dry-run          # preview prompts; no Ollama call, no file changes
python main_feedback.py --no-archive       # skip history file (queue is still cleared)
python main_feedback.py --min-failures 2   # require ≥2 rejections before calling the model
```

### I/O

| File | Direction | Purpose |
|------|-----------|---------|
| `data/failed_feedback_queue.json` | Read → cleared | Source rejections (written by `app_triage.py`) |
| `data/negative_constraints.json` | Write (additive) | Accumulated constraints per strategy |
| `data/failed_feedback_history.json` | Append | Permanent archive of all processed rejections |

### Output schema (`negative_constraints.json`)

```json
{
  "updated_at": "2026-06-16T10:00:00+00:00",
  "total_failures_processed": 12,
  "last_batch_size": 6,
  "model": "phi4-mini-reasoning",
  "strategy_counts": {
    "Process / CLI Args": 2,
    "File & Registry": 3,
    "Network / API Calls": 1
  },
  "constraints": {
    "Process / CLI Args": [
      "DO NOT generate rules that rely solely on process name matching without parent-process context.",
      "AVOID rules that flag common administrator tools (e.g., psexec, wmic) without scope-limiting user or time conditions.",
      "NEVER write detection logic that depends on absolute paths without also checking the working directory."
    ],
    "File & Registry": [
      "DO NOT trigger on generic filesystem write actions without correlating with the initiating process identity.",
      "AVOID rules targeting high-volume registry hives without a specific sub-key pattern filter."
    ],
    "Network / API Calls": [
      "AVOID rules that alert on all outbound connections to port 443 without domain or certificate reputation context.",
      "DO NOT use IP-based detection alone — always combine with hostname or user-agent patterns."
    ]
  }
}
```

Constraints accumulate across runs. New constraints for a strategy **prepend** the existing list (most recent first), capped at 6 per strategy.

### Strategy grouping

Each feedback record is tagged with `detection_strategy` by `app_triage.py` when it writes to the queue. If the field is missing (legacy records), the engine infers the strategy from keyword analysis of the rule name, description, and `actionNames`.

### Environment overrides

```bash
OLLAMA_BASE_URL=http://localhost:11434/v1 python main_feedback.py
FEEDBACK_TIMEOUT_SECONDS=600 python main_feedback.py   # extend if model is slow
```

### Timing

Expect ~30–90 seconds per strategy group call. A typical batch of 3 strategy groups finishes in 2–5 minutes.

---

## A.10 Threat Stream Dashboard (read-only)

Read-only UI. Does **not** call Ollama or run pipeline stages.

```bash
streamlit run app.py
```

Open **http://localhost:8501**.

- Reads `data/filtered_threat_queue.json` only
- Auto-refresh every **60 seconds**; sidebar **Refresh now**
- **Deploy** button in the UI is Streamlit Cloud branding — ignore for local use

Optional `.streamlit/config.toml`:

```toml
[client]
toolbarMode = "minimal"
```

---

## A.11 Shell script — full pipeline (Steps 1–3)

```bash
chmod +x scripts/run_pipeline_from_scratch.sh
./scripts/run_pipeline_from_scratch.sh
./scripts/run_pipeline_from_scratch.sh --fresh --quick --skip-gemma
```

| Flag | Effect |
|------|--------|
| `--fresh` | Delete prior `data/*.json` artifacts |
| `--quick` | Filter `--limit 20`, generate `--limit 3` |
| `--skip-gemma` | Step 2 without Ollama |

---

## A.12 Local copy-paste sequence (full pipeline)

```bash
# Terminal A
ollama serve

# Terminal B
cd /path/to/Threat_automation
source .venv/bin/activate
python scripts/sync_knowledge_base.py   # optional, first time only

python main_ingestion.py                # Step 1
python main_filter.py                   # Step 2
python main_generator.py                # Step 3
python main_validator.py                # Step 4

streamlit run app_triage.py --server.port 8502  # Step 5 — triage validated rules
# (open http://localhost:8502 — approve/reject each threat)

python main_feedback.py                 # Step 6 — run after triage session
streamlit run app.py                    # Optional — threat stream UI :8501
```

**Smoke test (minimal Ollama):**

```bash
python main_ingestion.py
python main_filter.py --limit 20 --skip-gemma
python main_generator.py --limit 2 --force --no-resume
python main_validator.py --limit 1
# Triage manually via app_triage.py, then:
python main_feedback.py --dry-run       # preview without calling Ollama
```

---

# Part B — Docker Compose deployment

Single codebase, **multi-service** architecture: one image (`threat-automation:latest`) built from the root `Dockerfile` (`python:3.11-slim`). Each step is an isolated Compose service; all share the `./data` volume. **Ollama is not in Docker** — run it on the host.

> The triage dashboard (`app_triage.py`) writes to `./data` and is intended to run locally (not in Docker) so the engineer interacts with the host filesystem directly.

## B.1 Prerequisites

- Docker + Docker Compose v2
- Ollama on the host with models pulled (see A.2)
- `./data` directory present (`data/.gitkeep` in repo)

## B.2 Build

```bash
docker compose build
```

Rebuild after code changes:

```bash
docker compose build --no-cache
```

## B.3 Persistent threat stream dashboard

```bash
docker compose up -d threat-dashboard
```

| Property | Value |
|----------|-------|
| URL | http://localhost:8501 |
| Volume | `./data:/app/data:ro` |
| Restart | `always` |

```bash
docker compose logs -f threat-dashboard
docker compose stop threat-dashboard
```

## B.4 Run pipeline steps in isolation

Pipeline step services use profile `pipeline` and mount `./data` **read-write**. Steps 2–4 reach host Ollama via `OLLAMA_BASE_URL=http://host.docker.internal:11434/v1`.

```bash
docker compose run --rm step1-ingestion
docker compose run --rm step2-filter
docker compose run --rm step3-generator
docker compose run --rm step4-validator
```

**Pass flags** (note the `--` separator):

```bash
docker compose run --rm step2-filter -- --limit 20
docker compose run --rm step2-filter -- --skip-gemma
docker compose run --rm step3-generator -- --limit 3 --force --no-resume
docker compose run --rm step4-validator -- --limit 1
```

## B.5 Full Docker sequence

```bash
docker compose build
docker compose run --rm step1-ingestion
docker compose run --rm step2-filter
docker compose run --rm step3-generator
docker compose run --rm step4-validator
docker compose up -d threat-dashboard
# Locally — human triage then feedback loop:
streamlit run app_triage.py --server.port 8502
python main_feedback.py
```

## B.6 Compose service map

| Service | Command | `./data` | Host Ollama |
|---------|---------|----------|-------------|
| `threat-dashboard` | `streamlit run app.py` | read-only | No |
| `step1-ingestion` | `python main_ingestion.py` | read-write | No |
| `step2-filter` | `python main_filter.py` | read-write | Yes (Gemma 4) |
| `step3-generator` | `python main_generator.py` | read-write | Yes (phi4-mini-reasoning) |
| `step4-validator` | `python main_validator.py` | read-write | Yes (phi4-mini-reasoning) |
| *(local)* `app_triage.py` | `streamlit run app_triage.py` | read-write | No |
| *(local)* `main_feedback.py` | `python main_feedback.py` | read-write | Yes (phi4-mini-reasoning) |

Steps communicate **only through files** in `./data` — no inter-container API calls.

---

# Part C — Reference

## C.1 Data files

Generated locally (gitignored):

| File | Step | Purpose |
|------|------|---------|
| `data/threat_queue.json` | 1 | Recent articles (`published_at`, 7-day window) |
| `data/ingestion_dedup_state.json` | 1 | Cross-run dedup fingerprint cache |
| `data/filtered_threat_queue.json` | 2 | Gemma-confirmed threats (max 50) |
| `data/generated_rules_staging.json` | 3 | 3 strategy-diverse rule variants per threat |
| `data/validated_rules.json` | 4 | Stage 1/2/3 annotated rules; consumed by triage |
| `data/prod_detection_rules.json` | 5 (Triage) | Approved rules ready for SIEM deployment |
| `data/failed_feedback_queue.json` | 5 (Triage) → 6 | Rejected variants with `detection_strategy` tag; cleared after Step 6 |
| `data/negative_constraints.json` | 6 (Feedback) | Accumulated negative constraints per strategy; fed back into Step 3 |
| `data/failed_feedback_history.json` | 6 (Feedback) | Permanent append-only archive of all processed rejections |

**Clean pipeline outputs (preserve production + history):**

```bash
rm -f data/threat_queue.json \
      data/ingestion_dedup_state.json \
      data/filtered_threat_queue.json \
      data/generated_rules_staging.json \
      data/validated_rules.json \
      data/failed_feedback_queue.json
```

**Full reset (wipe everything including prod rules and constraints):**

```bash
rm -f data/threat_queue.json \
      data/ingestion_dedup_state.json \
      data/filtered_threat_queue.json \
      data/generated_rules_staging.json \
      data/validated_rules.json \
      data/prod_detection_rules.json \
      data/failed_feedback_queue.json \
      data/negative_constraints.json \
      data/failed_feedback_history.json
```

Or: `./scripts/run_pipeline_from_scratch.sh --fresh`

## C.2 Configuration

**`ingestion/config.py`:**

| Setting | Default | Effect |
|---------|---------|--------|
| `RSS_FEED_LINKS` | **198 feeds** (14 categories) | Ingestion sources |
| `INGESTION_MAX_AGE_DAYS` | `7` | Publication window |
| `PLATFORM_KEYWORDS` | AWS, Azure, … | Step 2 keyword gate |
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | Ollama API (override in Compose for containers) |
| `OLLAMA_MODEL` | `gemma4:e4b` | Step 2 |
| `OLLAMA_PHI4_MODEL` | `phi4-mini-reasoning` | Steps 3 & 4 |
| `RULE_VARIANTS_MIN` | `3` | Min variants the model must return |
| `RULE_VARIANTS_MAX` | `3` | Max variants kept (over-generation is truncated) |
| `LITELLM_REASONING_MODEL` | `ollama/phi4-mini-reasoning` | `main.py` orchestrator |
| `OLLAMA_MAX_WORKERS` | `4` | Parallel Gemma calls |
| `OLLAMA_PHI4_MAX_WORKERS` | `2` | Parallel phi4 calls |

**Step 4 environment overrides** (set as env vars):

| Env var | Default | Effect |
|---------|---------|--------|
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | Shared with Steps 2–3 |
| `OLLAMA_PHI4_MODEL` | `phi4-mini-reasoning` | Stage 3 model |
| `STAGE3_TIMEOUT_SECONDS` | `300` | Per-variant Ollama timeout |

**Step 6 environment overrides** (set as env vars):

| Env var | Default | Effect |
|---------|---------|--------|
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | Shared with Steps 2–4 |
| `OLLAMA_PHI4_MODEL` | `phi4-mini-reasoning` | Constraint generation model |
| `FEEDBACK_TIMEOUT_SECONDS` | `300` | Per-strategy-group Ollama timeout |

Filter cap (`50`) → `main_filter.py`. Min confidence (`6`) → `filters/gemma_verifier.py`.

**`.env.example`** — copy to `.env` for LiteLLM / orchestrator overrides.

## C.3 Troubleshooting

| Problem | What to try |
|---------|-------------|
| `0 articles fetched` | Check network/VPN; RSS feeds may not have published in the 7-day window. |
| Large `stale_dropped` | Expected — old items filtered by design. |
| Ollama connection errors (local) | `ollama serve`; `ollama list`. If `bind: address already in use`, Ollama is already running. |
| Ollama errors (Docker Steps 2–4) | Ensure Ollama is running on host; `curl http://localhost:11434/api/tags`; confirm `host.docker.internal` resolves (Linux: `host-gateway` in compose). |
| Step 3 KB empty | `python scripts/sync_knowledge_base.py` (run on host before `docker compose build`). |
| Vendor patch bulletins in filtered queue | Re-run Step 2 to clear them — the patch-advisory filter now blocks these titles. |
| Filter confirms 0 | `--limit 20`; `--skip-gemma` to isolate keyword / CVE / patch gates. |
| Scores all `1` / `MALFORMED_JSON_FALLBACK` | Verify `gemma4:e4b` is pulled; check Ollama container logs. |
| Step 3 returns < 3 variants | `generation_status: "failed"` — re-run with `--force --no-resume`; phi4 non-deterministic. |
| Step 4 Stage 3 timeout | Set `STAGE3_TIMEOUT_SECONDS=600`; each variant takes 30–90s depending on hardware. |
| Step 4 `stage3_audit.is_valid: false` | Ollama offline or empty response — check `model_error` field in `validated_rules.json`. |
| Step 4 all variants `failed_stage_2` | `python scripts/sync_knowledge_base.py` to refresh KB catalogs. |
| Triage dashboard empty | Run Steps 3 & 4 first; ensure `data/validated_rules.json` has entries with `stage: "passed"` variants. |
| Feedback loop: "No feedback entries" | Triage at least one threat in `app_triage.py` first; the feedback queue is only populated when rules are rejected. |
| Feedback loop: constraints have `PARSE_ERROR` | phi4 returned malformed JSON — re-run Step 6; if persistent, use `--dry-run` to inspect the raw prompt and model output. |
| Feedback loop: constraints look generic | Increase batch size by running several triage sessions before running Step 6; or lower `--min-failures` to 1. |
| `data/failed_feedback_queue.json` not empty after Step 6 | Indicates a crash mid-run — re-run `main_feedback.py` to reprocess the remaining items. |
| Dashboard empty | Run Step 2; ensure `data/filtered_threat_queue.json` exists on the mounted volume. |
| Docker dashboard stale | Re-run Step 2; `threat-dashboard` is read-only and refreshes automatically. |
| Rule gen slow | `--limit 3` locally or `docker compose run --rm step3-generator -- --limit 3`. |
| Streamlit **Deploy** button | Built-in Streamlit Cloud branding — ignore for local use. |

**KB sync in Docker:** `sync_knowledge_base.py` writes under `knowledge_base/` (baked into the image). Run on the host before `docker compose build`, or `docker exec` into a container if you need fresh catalogs after build.

## C.4 Alternative entry point (`main.py`)

Experimental LiteLLM orchestrator under `src/threat_pipeline/`:

```bash
export LLM_MOCK=true
python main.py --stage full --mock path/to/mock_feeds.json
```

Not the day-to-day operational path. Use the `main_*` scripts (Steps 1–4 and 6) and `app_triage.py` (Step 5), or Docker Compose services.

---

See also [README.md](./README.md) (Docker quick start) and [ARCHITECTURE.md](./ARCHITECTURE.md) (system design).
