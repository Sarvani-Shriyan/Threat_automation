# Threat Research Automation Pipeline

Modular, model-agnostic threat intelligence pipeline with production-grade stateful ingestion.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for system design.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export LLM_MOCK=true
python main.py --stage full --mock data/mock_feeds.json
pytest tests/ -q
```

## Stages

| Stage | Module | CLI |
|-------|--------|-----|
| Ingestion | `ingestion/` | `--stage ingest --mock data/mock_feeds.json` |
| Keyword + SLM filter | `filters/` | `--stage filter` |
| Full pipeline | `orchestrator.py` | `--stage full --mock-llm` |

## Configuration

Set via `.env` or environment: `THREAT_QUEUE_DB`, `FEED_URLS`, `KEYWORDS`, `SLM_MODEL`, `REASONING_MODEL`, `LLM_MOCK`.
