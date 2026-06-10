# Threat Automation — Step-by-Step Usage Guide

This guide covers **local Python** and **Docker Compose** workflows for the threat intelligence pipeline: RSS ingestion → dynamic filter → grounded rule generation → Streamlit dashboard.

Run CLI commands from the **repository root** (`Threat_automation/`).

> **Step 4 (validation) is removed** pending a clean-slate refactor. Pipeline output ends at `data/generated_rules_staging.json` after Step 3.

---

## Quick reference

| Goal | Local | Docker |
|------|-------|--------|
| Ingest RSS | `python main_ingestion.py` | `docker compose run --rm step1-ingestion` |
| Filter threats | `python main_filter.py` | `docker compose run --rm step2-filter` |
| Generate rules | `python main_generator.py` | `docker compose run --rm step3-generator` |
| Dashboard UI | `streamlit run app.py` | `docker compose up -d threat-dashboard` |

**Operational scripts:** `main_ingestion.py` → `main_filter.py` → `main_generator.py` (+ optional `app.py`).

---

## Current behavior

| Area | Behavior |
|------|----------|
| **Ingestion** | Only RSS items **published in the last 7 days** (UTC). Undated or older items are dropped. Each article stores `published_at`. |
| **Dedup state** | `data/ingestion_dedup_state.json` stores SHA-256 fingerprints (`title\|url`) so re-runs skip duplicates. |
| **Dynamic filter** | Gemma 4 strict JSON router (`temperature=0`). Pass: `is_relevant=true` **and** `confidence_score >= 6`. |
| **Filtered queue** | Merges with prior runs, sorts by **confidence then date**, **caps at 50**. |
| **Rule generation** | `phi4-mini-reasoning` via Ollama; strips `<thinking>` blocks before JSON parse. |
| **Dashboard** | Read-only Streamlit; auto-refresh 60s; no Ollama or pipeline side effects. |
| **Docker** | Single image `threat-automation:latest`; steps share `./data` volume; Ollama on **host** only. |
| **Repository** | `data/*.json` outputs are **gitignored**; only `data/.gitkeep` is committed. |

---

## Pipeline overview

```
Step 1  main_ingestion.py     RSS feeds  →  data/threat_queue.json
                              (+ data/ingestion_dedup_state.json)
Step 2  main_filter.py        Keyword + CVE + Gemma 4  →  data/filtered_threat_queue.json  (max 50)
Step 3  main_generator.py     phi4-mini-reasoning + KB  →  data/generated_rules_staging.json
Dashboard  app.py             Read-only filtered-queue UI (Streamlit :8501)
```

**Ollama models (host or local Python):**

| Step | Model | Config (`ingestion/config.py`) |
|------|-------|--------------------------------|
| 2 — Dynamic Semantic Filter | `gemma4:e4b` | `OLLAMA_MODEL` |
| 3 — Rule generation | `phi4-mini-reasoning` | `OLLAMA_PHI4_MODEL` |

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

## A.2 Ollama (required for Steps 2–3)

**Terminal A — keep running:**

```bash
ollama serve
```

**Terminal B — one-time model pull:**

```bash
ollama pull gemma4:e4b
ollama pull phi4-mini-reasoning
curl http://localhost:11434/api/tags   # verify
```

## A.3 Knowledge base (optional, recommended for Step 3)

GitHub, Okta, and Azure catalogs ship in-repo. Sync AWS/GCP IAM lists:

```bash
python scripts/sync_knowledge_base.py
```

---

## A.4 Step 1 — Ingest threat intelligence (RSS)

Fetches security RSS feeds, applies a **7-day publication window**, deduplicates by title + URL.

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

1. **Platform keywords** — AWS, Azure, GitHub, Okta, etc.
2. **CVE patch filter** — drops patched/historical CVE noise.
3. **Gemma 4** — deterministic JSON classification.

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
python main_filter.py --skip-gemma          # keyword + CVE only (no Ollama)
python main_filter.py --workers 6
```

Console log:

```text
[Dynamic Filter] Title: AWS CloudGoat EC2 SSRF | Domain: Cloud | Score: 8/10
```

---

## A.6 Step 3 — Grounded rule generation (phi4-mini-reasoning)

Generates 5–6 detection rule variants per filtered threat, grounded in knowledge-base `actionNames`.

```bash
python main_generator.py
python main_generator.py --limit 3
python main_generator.py --platforms aws,azure
python main_generator.py --force --no-resume
```

**Input:** `data/filtered_threat_queue.json`  
**Output:** `data/generated_rules_staging.json` (incremental; safe to interrupt)

Requires Ollama with `phi4-mini-reasoning`. Model responses may include `<thinking>` blocks; `generators/rule_engine.py` strips them before parsing the rules JSON.

---

## A.7 Dashboard — Threat Intelligence Stream Console

Read-only UI. Does **not** call Ollama or run pipeline stages.

```bash
streamlit run app.py
```

Open **http://localhost:8501**.

- Reads `data/filtered_threat_queue.json` only
- Auto-refresh every **60 seconds**; sidebar **Refresh now**
- **Deploy** button in the UI is Streamlit Cloud branding — not part of this project; ignore for local use

Optional `.streamlit/config.toml`:

```toml
[client]
toolbarMode = "minimal"
```

---

## A.8 Shell script — full pipeline (Steps 1–3)

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

## A.9 Local copy-paste sequence

```bash
# Terminal A
ollama serve

# Terminal B
cd /path/to/Threat_automation
source .venv/bin/activate
python scripts/sync_knowledge_base.py   # optional, first time
python main_ingestion.py
python main_filter.py
python main_generator.py
streamlit run app.py                  # optional
```

**Smoke test (minimal Ollama):**

```bash
python main_ingestion.py
python main_filter.py --limit 20 --skip-gemma
python main_generator.py --limit 2 --force --no-resume
```

---

# Part B — Docker Compose deployment

Single codebase, **multi-service** architecture: one image (`threat-automation:latest`) built from the root `Dockerfile` (`python:3.11-slim`). Each step is an isolated Compose service; all share the `./data` volume. **Ollama is not in Docker** — run it on the host.

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

## B.3 Persistent dashboard

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

## B.4 Run steps in isolation

Pipeline step services use profile `pipeline` and mount `./data` **read-write**. Steps 2–3 reach host Ollama via `OLLAMA_BASE_URL=http://host.docker.internal:11434/v1`.

```bash
docker compose run --rm step1-ingestion
docker compose run --rm step2-filter
docker compose run --rm step3-generator
```

**Pass flags** to the underlying script (note the `--` separator):

```bash
docker compose run --rm step2-filter -- --limit 20
docker compose run --rm step2-filter -- --skip-gemma
docker compose run --rm step3-generator -- --limit 3 --force --no-resume
```

## B.5 Full Docker sequence

```bash
docker compose build
docker compose run --rm step1-ingestion
docker compose run --rm step2-filter
docker compose run --rm step3-generator
docker compose up -d threat-dashboard
```

## B.6 Compose service map

| Service | Command | `./data` | Host Ollama |
|---------|---------|----------|-------------|
| `threat-dashboard` | `streamlit run app.py` | read-only | No |
| `step1-ingestion` | `python main_ingestion.py` | read-write | No |
| `step2-filter` | `python main_filter.py` | read-write | Yes (Gemma) |
| `step3-generator` | `python main_generator.py` | read-write | Yes (phi4-mini-reasoning) |

Steps communicate **only through files** in `./data` — no inter-container API calls.

> There is no `step4-validator` service; validation was removed pending refactor.

---

# Part C — Reference

## C.1 Data files

Generated locally (gitignored):

| File | Step | Purpose |
|------|------|---------|
| `data/threat_queue.json` | 1 | Recent articles (`published_at`, 7-day window) |
| `data/ingestion_dedup_state.json` | 1 | Dedup fingerprint cache |
| `data/filtered_threat_queue.json` | 2 | Gemma-confirmed threats (max 50) |
| `data/generated_rules_staging.json` | 3 | Rule variants per threat |

**Clean outputs:**

```bash
rm -f data/threat_queue.json \
      data/ingestion_dedup_state.json \
      data/filtered_threat_queue.json \
      data/generated_rules_staging.json
```

Or: `./scripts/run_pipeline_from_scratch.sh --fresh`

## C.2 Configuration

**`ingestion/config.py`:**

| Setting | Default | Effect |
|---------|---------|--------|
| `RSS_FEED_LINKS` | 64 feeds | Ingestion sources |
| `INGESTION_MAX_AGE_DAYS` | `7` | Publication window |
| `PLATFORM_KEYWORDS` | AWS, Azure, … | Step 2 keyword gate |
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | Ollama API (override in Compose for containers) |
| `OLLAMA_MODEL` | `gemma4:e4b` | Step 2 |
| `OLLAMA_PHI4_MODEL` | `phi4-mini-reasoning` | Step 3 |
| `LITELLM_REASONING_MODEL` | `ollama/phi4-mini-reasoning` | `main.py` orchestrator |
| `OLLAMA_MAX_WORKERS` | `4` | Parallel Gemma calls |
| `OLLAMA_PHI4_MAX_WORKERS` | `2` | Parallel reasoning calls |

Filter cap (`50`) → `main_filter.py`. Min confidence (`6`) → `filters/gemma_verifier.py`.

**`.env.example`** — copy to `.env` for LiteLLM / orchestrator overrides.

## C.3 Troubleshooting

| Problem | What to try |
|---------|-------------|
| `0 articles fetched` | Check network/VPN; few feeds may publish in the 7-day window. |
| Large `stale_dropped` | Expected — old RSS items filtered by design. |
| Ollama connection errors (local) | `ollama serve`; `ollama list`. |
| Ollama errors (Docker Steps 2–3) | Ollama on host; `curl http://localhost:11434/api/tags` from host; confirm `host.docker.internal` resolves (Linux: `host-gateway` in compose). |
| Step 3 KB empty | `python scripts/sync_knowledge_base.py` (run locally or `docker compose run --rm step1-ingestion` won't sync KB — run sync on host or add a one-off). |
| Filter confirms 0 | `--limit 20`; `--skip-gemma` to isolate keyword/CVE. |
| Scores all `1` / `MALFORMED_JSON_FALLBACK` | Verify `gemma4:e4b` pulled; check container logs. |
| Dashboard empty | Run Step 2; ensure `data/filtered_threat_queue.json` exists on mounted volume. |
| Docker dashboard stale | Re-run Step 2; dashboard is read-only on `./data`. |
| Rule gen slow | `--limit 3` locally or `docker compose run --rm step3-generator -- --limit 3`. |
| Streamlit **Deploy** button | Built into Streamlit — ignore locally. |

**KB sync in Docker:** `sync_knowledge_base.py` writes under `knowledge_base/` (baked into image). Run on host before `docker compose build`, or exec into a container after build if you need fresh catalogs.

## C.4 Alternative entry point (`main.py`)

Experimental LiteLLM orchestrator under `src/threat_pipeline/`:

```bash
export LLM_MOCK=true
python main.py --stage full --mock path/to/mock_feeds.json
```

Not the day-to-day operational path. Use Steps 1–3 (`main_*` scripts) or Docker Compose services.

---

See also [README.md](./README.md) (Docker quick start) and [ARCHITECTURE.md](./ARCHITECTURE.md) (system design).
