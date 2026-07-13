# Threat Research Automation Pipeline

Modular, model-agnostic threat intelligence pipeline with production-grade stateful ingestion, deterministic validation, and a human-in-the-loop triage interface.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for system design and [USAGE.md](./USAGE.md) for the full local CLI walkthrough.

## Quick start (local Python)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python main_ingestion.py       # Step 1 — ingest 198 RSS feeds
python main_filter.py          # Step 2 — keyword + patch-advisory + Gemma 4 filter
python main_generator.py       # Step 3 — generate 3 strategy-diverse rules per threat
python main_validator.py       # Step 4 — contract + KB + CTI cognitive audit

streamlit run app_triage.py --server.port 8502   # Step 5 — security engineer triage
python main_feedback.py                          # Step 6 — feedback loop → negative constraints

streamlit run app.py           # Threat stream dashboard   :8501
```

## Pipeline at a glance

```
Step 1  main_ingestion.py   →  data/threat_queue.json               (198-feed RSS, 7-day window)
Step 2  main_filter.py      →  data/filtered_threat_queue.json       (keyword + patch-advisory + Gemma 4, max 50)
Step 3  main_generator.py   →  data/generated_rules_staging.json     (3 strategy-diverse variants / threat)
Step 4  main_validator.py   →  data/validated_rules.json             (Stage 1 contract + Stage 2 KB + Stage 3 CTI audit)
Step 5  app_triage.py       →  data/prod_detection_rules.json        (human approve/reject per threat)
Step 6  main_feedback.py    →  data/negative_constraints.json        (phi4 distils rejection patterns → prevent repeats)
                               data/failed_feedback_history.json     (archive of all processed rejections)
```

## Stages (local CLI)

| Stage | Script | Output |
|-------|--------|--------|
| 1 — Ingestion | `main_ingestion.py` | `data/threat_queue.json` |
| 2 — Dynamic filter | `main_filter.py` | `data/filtered_threat_queue.json` |
| 3 — Rule generation | `main_generator.py` | `data/generated_rules_staging.json` |
| 4 — Validation | `main_validator.py` | `data/validated_rules.json` |
| 5 — Triage | `app_triage.py` | `data/prod_detection_rules.json` + `data/failed_feedback_queue.json` |
| 6 — Feedback loop | `main_feedback.py` | `data/negative_constraints.json` + `data/failed_feedback_history.json` |
| Threat stream UI | `app.py` | Read-only threat stream (`:8501`) |

## Modular deployment (Docker)

Single codebase, **multi-service** layout: one Docker image contains the entire project (ingestion, filters, generators, knowledge base, shared config, and Streamlit UI). Each pipeline step runs as an **independent Compose service** reading and writing shared state under `./data`.

**Ollama is not installed inside Docker.** Pull and run models on your **host machine** (`gemma4:e4b`, `phi4-mini-reasoning`); Steps 2–4 containers reach the host engine via `host.docker.internal`.

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

### Run the threat stream dashboard (persistent UI)

```bash
docker compose up -d threat-dashboard
```

Open **http://localhost:8501**. The dashboard mounts `./data` **read-only** and auto-refreshes from `data/filtered_threat_queue.json`.

```bash
docker compose logs -f threat-dashboard
docker compose stop threat-dashboard
```

> The **security engineer triage dashboard** (`app_triage.py`) is a local-only Streamlit app and does not have a Compose service. Run it directly: `streamlit run app_triage.py --server.port 8502`

### Run pipeline steps in isolation

Each step is a one-shot job sharing the `./data` volume (read-write). Steps 2–4 use `OLLAMA_BASE_URL=http://host.docker.internal:11434/v1`.

```bash
# Step 1 — RSS ingestion → data/threat_queue.json
docker compose run --rm step1-ingestion

# Step 2 — keyword + patch-advisory + Gemma filter → data/filtered_threat_queue.json
docker compose run --rm step2-filter

# Step 3 — 3-strategy rule generation → data/generated_rules_staging.json
docker compose run --rm step3-generator

# Step 4 — contract + KB + CTI validation → data/validated_rules.json
docker compose run --rm step4-validator
```

Pass script flags after the service name:

```bash
docker compose run --rm step2-filter -- --limit 20
docker compose run --rm step2-filter -- --skip-gemma
docker compose run --rm step3-generator -- --limit 3 --force --no-resume
docker compose run --rm step4-validator -- --limit 1
```

### Full pipeline sequence (Compose)

```bash
docker compose build
docker compose run --rm step1-ingestion
docker compose run --rm step2-filter
docker compose run --rm step3-generator
docker compose run --rm step4-validator
docker compose up -d threat-dashboard
# Locally — triage then run feedback loop:
streamlit run app_triage.py --server.port 8502
python main_feedback.py
```

### Architecture summary

| Service | Command | Data volume | Ollama (host) |
|---------|---------|-------------|---------------|
| `threat-dashboard` | `streamlit run app.py` | `./data` **ro** | No |
| `step1-ingestion` | `python main_ingestion.py` | `./data` **rw** | No |
| `step2-filter` | `python main_filter.py` | `./data` **rw** | Yes (Gemma 4) |
| `step3-generator` | `python main_generator.py` | `./data` **rw** | Yes (phi4-mini-reasoning) |
| `step4-validator` | `python main_validator.py` | `./data` **rw** | Yes (phi4-mini-reasoning) |
| *(local only)* `app_triage.py` | `streamlit run app_triage.py` | `./data` **rw** | No |
| *(local only)* `main_feedback.py` | `python main_feedback.py` | `./data` **rw** | Yes (phi4-mini-reasoning) |

Services communicate **asynchronously through files** in `./data` — no inter-container RPC. Rebuild after code changes:

```bash
docker compose build --no-cache
```

## Configuration

Edit `ingestion/config.py` for feeds, keywords, model names, and ingestion window. Override Ollama URL in Compose via `OLLAMA_BASE_URL` (already set for SLM steps).

Optional `.env` for the LiteLLM orchestrator path (`main.py`): `REASONING_MODEL`, `SLM_MODEL`, `LLM_MOCK`, etc. See `.env.example`.

## Intelligence feed landscape

**198 RSS feeds** tracked across 14 source categories (`ingestion/config.py` → `RSS_FEED_LINKS`):

| Category | Feeds | Representative sources |
|---|---|---|
| Tier-1 cybersecurity news | 13 | The Hacker News, BleepingComputer, Krebs on Security, Dark Reading, The Record, Wired Security |
| Government / CERTs | 12 | CISA (news + blog + advisories), NCSC (4 feeds), CERT-EU, MS-ISAC / CIS |
| Threat intelligence | 17 | Unit 42, Securelist, Cyble, GreyNoise, ThreatCluster, ThreatMon, Pulsedive, VulDB, Exploit-DB |
| Cloud security | 8 | AWS Security Blog, Google Cloud, Wiz (blog + threat landscape), CloudSecList, Datadog Security Labs |
| Vendor research blogs | 22 | Microsoft Security, CrowdStrike, SentinelOne, Huntress, Red Canary, Rapid7, Elastic, ReversingLabs |
| Identity / IAM | 4 | Saviynt, Silverfort, IDSA, Cyera |
| Detection engineering | 5 | Detection Engineering Weekly, Detect FYI, tl;dr sec, defend.network |
| Vulnerability research | 14 | Project Zero, Trail of Bits, Doyensec, DAY[0], HackTheBox, GitHub Security Lab |
| Malware / forensics / IR | 4 | DataBreaches.Net, Cybercrime Diaries, Forensic Focus, Binalyze |
| AI & ML security | 3 | AI Security Blog, Protect AI, OWASP GenAI |
| DevSecOps | 6 | DevOps.com, DevSec Blog, Aikido Security, Harness, GitHub DevSecOps |
| Community & write-ups | 14 | r/netsec, r/cybersecurity, InfoSec Write-ups, Cybersecurity Write-ups, TechCrunch |
| Broader tech & platform signals | 12 | Forbes Innovation, Google Workspace Updates, CIO Security, CloudSEK |
| Legacy research blogs | 64 | Original curated set of independent security researcher blogs |

> All feeds pass through a 7-day publication window, platform keyword gate, patch-advisory title blocker, CVE patch filter, and Gemma 4 semantic confidence gate (score ≥ 6) before any article reaches rule generation.
