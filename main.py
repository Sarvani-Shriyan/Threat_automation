#!/usr/bin/env python3
"""Threat Research Automation Pipeline — CLI entrypoint."""

import argparse
import json
import sys
from pathlib import Path

import structlog

# Ensure project root on path for config package
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from config.settings import Settings, get_settings  # noqa: E402
from threat_pipeline.orchestrator import PipelineOrchestrator  # noqa: E402

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Threat Research Automation Pipeline")
    parser.add_argument(
        "--stage",
        choices=["ingest", "filter", "generate", "hitl", "full"],
        default="full",
        help="Pipeline stage to run",
    )
    parser.add_argument("--mock", type=str, help="Path to mock_feeds.json")
    parser.add_argument("--feeds", type=str, help="Comma-separated RSS feed URLs")
    parser.add_argument("--output", type=str, default="-", help="Output JSON path or '-' for stdout")
    parser.add_argument("--mock-llm", action="store_true", help="Use deterministic LLM responses")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    settings = get_settings()
    if args.mock_llm:
        settings = Settings(**{**settings.model_dump(), "llm_mock": True})

    feed_urls = None
    if args.feeds:
        feed_urls = [u.strip() for u in args.feeds.split(",") if u.strip()]

    orchestrator = PipelineOrchestrator(settings)

    if args.stage == "ingest":
        count = orchestrator.run_ingestion(feed_urls=feed_urls, mock_path=args.mock)
        result = {"enqueued": count, "pending": orchestrator.queue.pending_count()}
    elif args.stage == "filter":
        confirmed = orchestrator.run_filter_stage()
        result = {"confirmed_threat_ids": confirmed}
    elif args.stage == "full":
        payloads = orchestrator.run_full_pipeline(feed_urls=feed_urls, mock_path=args.mock)
        result = [p.model_dump(mode="json") for p in payloads]
    else:
        payloads = orchestrator.run_full_pipeline(feed_urls=feed_urls, mock_path=args.mock)
        result = [p.model_dump(mode="json") for p in payloads]

    output = json.dumps(result, indent=2, default=str)
    if args.output == "-":
        print(output)
    else:
        Path(args.output).write_text(output, encoding="utf-8")
        logger.info("wrote_output", path=args.output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
