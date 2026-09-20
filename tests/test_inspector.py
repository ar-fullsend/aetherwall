from pathlib import Path

from aetherwall.inspector.engine import inspect_payload
from aetherwall.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]
POLICY = load_policy(ROOT / "policies" / "default.yaml")


def _load(name: str):
    import json

    data = json.loads((ROOT / "examples" / "attacks" / name).read_text())
    identity = data.pop("_identity", "agent:docs-helper")
    contract = data.pop("_contract", "summarize")
    hops = int(data.pop("_hops", 0))
    dest = data.pop("_destination", None)
    return data, identity, contract, hops, dest


def _decide(name: str):
    payload, identity, contract, hops, dest = _load(name)
    return inspect_payload(
        payload, POLICY, identity=identity, contract_name=contract, destination=dest, hops=hops
    )


def test_worm_is_denied():
    d = _decide("injection_worm.json")
    assert d.action == "deny"
    assert d.score >= 0.72
    families = {f.detector for f in d.findings}
    assert "worm_replication" in families
    assert "prompt_injection" in families


def test_tool_escape_denied():
    d = _decide("mcp_tool_escalation.json")
    assert d.action == "deny"
    assert any(f.detector == "tool_escalation" for f in d.findings)


def test_shadow_ai_denied():
    d = _decide("shadow_ai_egress.json")
    assert d.action == "deny"
    assert any(f.detector == "shadow_endpoint" for f in d.findings)


def test_secret_smuggle_denied():
    d = _decide("secret_smuggle.json")
    assert d.action == "deny"
    assert any(f.detector == "secret_smuggle" for f in d.findings)


def test_unknown_identity_dark():
    d = _decide("unknown_identity.json")
    assert d.action == "deny"
    assert any(f.detector == "sdp" for f in d.findings)


def test_benign_projects_or_allows():
    d = _decide("benign_summary.json")
    assert d.action in {"allow", "project"}
    assert d.score < 0.45
    if d.action == "project":
        assert d.projected is not None
        assert "text" in d.projected


def test_hop_budget():
    payload = {"text": "summarize please"}
    d = inspect_payload(payload, POLICY, identity="agent:docs-helper", contract_name="summarize", hops=4)
    assert any("hops" in f.evidence for f in d.findings)


def test_polymorphic_packer_denied():
    d = _decide("polymorphic_packer.json")
    assert d.action == "deny"
    assert any(f.detector == "polymorphic_payload" for f in d.findings)
