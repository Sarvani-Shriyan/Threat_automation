import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from config.settings import Settings
from threat_pipeline.orchestrator import PipelineOrchestrator


@pytest.fixture
def orchestrator(tmp_path: Path) -> PipelineOrchestrator:
    db = tmp_path / "test_queue.db"
    settings = Settings(
        threat_queue_db=db,
        llm_mock=True,
        keywords=["AWS", "CloudTrail", "Okta"],
    )
    return PipelineOrchestrator(settings)


def test_full_pipeline_mock(orchestrator: PipelineOrchestrator) -> None:
    mock_path = ROOT / "data" / "mock_feeds.json"
    payloads = orchestrator.run_full_pipeline(mock_path=str(mock_path))
    assert len(payloads) >= 1
    for p in payloads:
        assert p.threat_context.title
        assert len(p.validated_rules) >= 1
        assert p.metadata.get("pipeline_version")


def test_ingestion_dedup_count(orchestrator: PipelineOrchestrator) -> None:
    mock_path = ROOT / "data" / "mock_feeds.json"
    enqueued = orchestrator.run_ingestion(mock_path=str(mock_path))
    # 4 docs, 1 exact duplicate -> 3 unique
    assert enqueued == 3


def test_feedback_retry(orchestrator: PipelineOrchestrator) -> None:
    mock_path = ROOT / "data" / "mock_feeds.json"
    payloads = orchestrator.run_full_pipeline(mock_path=str(mock_path))
    assert payloads
    payload = payloads[0]
    bundle = orchestrator.feedback_loop.build_bundle_from_hitl(
        payload,
        human_notes="actionNames must use revoke_session not fake_action",
    )
    updated = orchestrator.apply_feedback(bundle)
    assert updated
    assert updated[0].threat_id == payload.threat_id
