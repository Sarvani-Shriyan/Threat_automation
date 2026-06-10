# Threat Research Automation Pipeline

Modular, model-agnostic threat intelligence pipeline with production-grade stateful ingestion.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for system design and [USAGE.md](./USAGE.md) for the full local CLI walkthrough.

## Quick start (local Python)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main_ingestion.py
python main_filter.py
python main_generator.py
```

## Modular deployment (Docker)

This repository uses a **single codebase, multi-service** layout: one Docker image contains the entire project (ingestion, filters, generators, knowledge base, shared config, and Streamlit UI). Each pipeline step runs as an **independent Compose service** that reads and writes shared state under `./data`.

**Ollama is not installed inside Docker.** Pull and run models on your **host machine** (`gemma4:e4b`, `phi4-mini-reasoning`); Step 2 and Step 3 containers reach the host engine via `host.docker.internal`.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose v2
- [Ollama](https://ollama.com/) running on the host:

```bash
ollama serve
ollama pull gemma4:e4b
ollama pull phi4-mini-reasoning
```

Ensure `./data` exists (the repo includes `data/.gitkeep`).

### Build the unified image

```bash
docker compose build
```

This builds `threat-automation:latest` from the root `Dockerfile` (`python:3.11-slim`, full codebase + `requirements.txt`).

### Run the dashboard (persistent UI)

```bash
docker compose up -d threat-dashboard
```

Open **http://localhost:8501**. The dashboard mounts `./data` **read-only** and auto-refreshes from `data/filtered_threat_queue.json`.

```bash
docker compose logs -f threat-dashboard   # tail logs
docker compose stop threat-dashboard    # stop UI
```

### Run pipeline steps in isolation

Each step is a one-shot job sharing the `./data` volume (read-write). Steps 2–3 use `OLLAMA_BASE_URL=http://host.docker.internal:11434/v1`.

```bash
# Step 1 — RSS ingestion → data/threat_queue.json
docker compose run --rm step1-ingestion

# Step 2 — keyword + CVE + Gemma filter → data/filtered_threat_queue.json
docker compose run --rm step2-filter

# Step 3 — grounded rule generation → data/generated_rules_staging.json
docker compose run --rm step3-generator
```

Pass script flags after the service name:

```bash
docker compose run --rm step2-filter -- --limit 20
docker compose run --rm step3-generator -- --limit 3 --force --no-resume
```

> **Note:** Step 4 (validation) was removed pending refactor. There is no `step4-validator` service.

### Full pipeline sequence (Compose)

```bash
docker compose build
docker compose run --rm step1-ingestion
docker compose run --rm step2-filter
docker compose run --rm step3-generator
docker compose up -d threat-dashboard
```

### Architecture summary

| Service | Command | Data volume | Ollama (host) |
|---------|---------|-------------|---------------|
| `threat-dashboard` | `streamlit run app.py` | `./data` **ro** | No |
| `step1-ingestion` | `python main_ingestion.py` | `./data` **rw** | No |
| `step2-filter` | `python main_filter.py` | `./data` **rw** | Yes (Gemma) |
| `step3-generator` | `python main_generator.py` | `./data` **rw** | Yes (phi4-mini-reasoning) |

Services communicate **asynchronously through files** in `./data` — no inter-container RPC. Rebuild the image after code changes:

```bash
docker compose build --no-cache
```

## Stages (local CLI)

| Stage | Script | Output |
|-------|--------|--------|
| 1 — Ingestion | `main_ingestion.py` | `data/threat_queue.json` |
| 2 — Dynamic filter | `main_filter.py` | `data/filtered_threat_queue.json` |
| 3 — Rule generation | `main_generator.py` | `data/generated_rules_staging.json` |
| Dashboard | `streamlit run app.py` | Read-only UI |

## Configuration

Edit `ingestion/config.py` for feeds, keywords, model names, and ingestion window. Override Ollama URL in Compose via `OLLAMA_BASE_URL` (already set for SLM steps).

Optional `.env` for the LiteLLM orchestrator path (`main.py`): `REASONING_MODEL`, `SLM_MODEL`, `LLM_MOCK`, etc. See `.env.example`.
