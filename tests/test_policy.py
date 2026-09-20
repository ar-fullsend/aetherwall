from pathlib import Path

from aetherwall.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]


def test_default_policy_compiles():
    p = load_policy(ROOT / "policies" / "default.yaml")
    assert p.name == "default"
    assert "agent:docs-helper" in p.identities
    assert "summarize" in p.contracts
    assert p.schema_for(p.contract("summarize")) is not None
    assert p.ai.scoring.block_threshold > p.ai.scoring.challenge_threshold
