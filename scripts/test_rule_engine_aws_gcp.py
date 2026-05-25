#!/usr/bin/env python3
"""Quick test: rule_engine + AWS/GCP knowledge base only (no Phi-4 call)."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generators.knowledge_base import KnowledgeBase
from generators.rule_engine import RuleEngine, build_grounded_system_prompt

AWS_THREAT = {
    "title": "AWS CloudGoat EC2 SSRF Exploitation",
    "source": "Hacking Articles",
    "url": "https://www.hackingarticles.in/aws-cloudgoat-ec2-ssrf-exploitation/",
    "content": (
        "Cloud environments are targeted due to misconfigurations. SSRF on AWS EC2 "
        "via IAM AssumeRole and CloudTrail logging gaps when attackers abuse metadata service."
    ),
}

GCP_THREAT = {
    "title": "GCP Compute Metadata SSRF via IAM permission abuse",
    "source": "Test",
    "url": "https://example.com/gcp-ssrf",
    "content": (
        "Attacker exploits compute.instances.setMetadata on Google Cloud Platform "
        "using stolen service account with iam.serviceAccounts.actAs."
    ),
}


def main() -> None:
    kb = KnowledgeBase(platforms=["aws", "gcp"])
    engine = RuleEngine(knowledge_base=kb)

    print(kb.summary())
    for label, threat in [("AWS", AWS_THREAT), ("GCP", GCP_THREAT)]:
        g = engine.ground_threat(threat)
        print(f"\n--- {label} grounding ---")
        print(f"Platforms: {g.matched_platforms}")
        print(f"Injected: {g.action_count} actionNames")
        print(f"Sources: {g.source_files}")
        print(f"Sample: {g.allowed_actions[:8]}")
        prompt = build_grounded_system_prompt(g.allowed_actions)
        assert "STRICT ALLOWED VOCABULARY" in prompt
        assert g.allowed_actions[0] in prompt

    print("\nGrounding test OK. Run Phi-4 generation with:")
    print("  python main_generator.py --force --no-resume --platforms aws,gcp --limit 2")


if __name__ == "__main__":
    main()
