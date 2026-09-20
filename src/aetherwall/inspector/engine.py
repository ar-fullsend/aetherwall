from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

from aetherwall.policy import Contract, FirewallPolicy, Schema


INJECTION = [
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"disregard (your |the )?(system )?prompt",
    r"you are now ",
    r"new persona",
    r"jailbreak",
    r"do not follow (your|the) (safety|system) rules",
    r"override (the )?(guardrails|policy|contract)",
    r"<!--\s*(system|instruction)",
    r"\[INST\]",
    r"system:\s*you",
]

WORM = [
    r"append this (text|message|prompt) to every",
    r"forward this (entire )?(message|instruction) to",
    r"copy these instructions into",
    r"replicate (this|yourself) to (all|every|other) agents?",
    r"when you talk to another agent, include",
    r"hide this in (the )?(scratchpad|memory|system)",
    r"propagate to (your )?tools?",
]

LEAK = [
    r"reveal (your )?(system prompt|hidden instructions)",
    r"print (the )?(system|developer) (prompt|message)",
    r"what are your exact instructions",
    r"dump (your )?(policy|constitution)",
]

TOOL_ESCAPE = [
    r"call tool ['\"]?shell['\"]?",
    r"execute( a)? (bash|powershell|cmd)",
    r"mcp://",
    r"tools?\.(invoke|call)\(",
]

SECRET = [
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----",
    r"ghp_[A-Za-z0-9]{20,}",
    r"sk-[A-Za-z0-9]{20,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.",
]


@dataclass
class Finding:
    detector: str
    weight: float
    evidence: str


@dataclass
class Decision:
    action: str
    score: float
    reasons: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    projected: dict[str, Any] | None = None
    contract: str | None = None
    identity: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "score": round(self.score, 3),
            "reasons": self.reasons,
            "findings": [
                {"detector": f.detector, "weight": f.weight, "evidence": f.evidence}
                for f in self.findings
            ],
            "projected": self.projected,
            "contract": self.contract,
            "identity": self.identity,
        }


def _blob(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, ensure_ascii=False)
    except TypeError:
        return str(payload)


def _messages_text(payload: Any) -> str:
    if isinstance(payload, dict):
        msgs = payload.get("messages")
        if isinstance(msgs, list):
            parts = []
            for m in msgs:
                if isinstance(m, dict):
                    parts.append(str(m.get("content", "")))
            if parts:
                return "\n".join(parts)
        if "content" in payload:
            return str(payload.get("content"))
        if "text" in payload:
            return str(payload.get("text"))
    return _blob(payload)


def _scan(patterns: list[str], text: str, detector: str, weight: float) -> list[Finding]:
    hits: list[Finding] = []
    lower = text.lower()
    for raw in patterns:
        if re.search(raw, lower, flags=re.I | re.S):
            hits.append(Finding(detector, weight, raw))
    return hits


def _shannon(text: str) -> float:
    if not text:
        return 0.0
    freq = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in freq if p > 0)


def _polymorphic(text: str) -> list[Finding]:
    findings: list[Finding] = []
    compact = re.sub(r"\s+", "", text)
    if len(compact) > 280 and _shannon(compact) > 5.3:
        findings.append(Finding("polymorphic_payload", 0.35, f"shannon={_shannon(compact):.2f}"))
    if re.search(r"(powershell.*-enc|from_base64|eval\(atob|new function\()", text, re.I):
        findings.append(Finding("polymorphic_payload", 0.75, "packer idiom"))
    if compact.count("=") > 40 and re.fullmatch(r"[A-Za-z0-9+/=\n]+", compact[:400] or "x"):
        findings.append(Finding("polymorphic_payload", 0.25, "long base64 run"))
    return findings


def _tool_calls(payload: Any) -> list[str]:
    names: list[str] = []
    if not isinstance(payload, dict):
        return names
    for key in ("tools", "tool_calls", "mcp_calls"):
        block = payload.get(key)
        if isinstance(block, list):
            for item in block:
                if isinstance(item, dict):
                    names.append(str(item.get("name") or item.get("tool") or ""))
                elif isinstance(item, str):
                    names.append(item)
    if isinstance(payload.get("tool"), str):
        names.append(payload["tool"])
    return [n for n in names if n]


def project_to_schema(payload: Any, schema: Schema | None) -> tuple[dict[str, Any] | None, list[str]]:
    if schema is None:
        return None, []
    src = payload if isinstance(payload, dict) else {"text": _messages_text(payload)}
    if "text" in schema.properties and "text" not in src:
        src = {**src, "text": _messages_text(payload)}
    projected: dict[str, Any] = {}
    errors: list[str] = []
    for field_name, spec in schema.properties.items():
        if field_name in src:
            value = src[field_name]
            if spec.get("type") == "string" and not isinstance(value, str):
                value = str(value)
            max_len = spec.get("maxLength")
            if isinstance(value, str) and max_len and len(value) > max_len:
                value = value[:max_len]
            enum = spec.get("enum")
            if enum and value not in enum:
                errors.append(f"{field_name} not in enum")
                continue
            projected[field_name] = value
    for req in schema.required:
        if req not in projected:
            errors.append(f"missing {req}")
    extras = [k for k in src.keys() if k not in schema.properties and k not in {"model", "messages"}]
    if extras and not schema.additionalProperties:
        errors.append(f"stripped extras: {extras}")
    return projected, errors


def inspect_payload(
    payload: Any,
    policy: FirewallPolicy,
    *,
    identity: str | None = None,
    contract_name: str | None = None,
    destination: str | None = None,
    hops: int = 0,
) -> Decision:
    text = _messages_text(payload)
    findings: list[Finding] = []
    hard_deny = False
    contract = policy.contract(contract_name)
    detectors = policy.ai.detectors

    if detectors.get("prompt_injection", True):
        findings += _scan(INJECTION, text, "prompt_injection", 0.42)
    if detectors.get("worm_replication", True):
        findings += _scan(WORM, text, "worm_replication", 0.5)
    if detectors.get("system_prompt_leak", True):
        findings += _scan(LEAK, text, "system_prompt_leak", 0.38)
    if detectors.get("tool_escalation", True):
        findings += _scan(TOOL_ESCAPE, text, "tool_escalation", 0.4)
        allowed = set(contract.tools) if contract else set()
        for name in _tool_calls(payload):
            if name not in allowed:
                findings.append(Finding("tool_escalation", 0.85, f"tool '{name}' outside contract"))
                hard_deny = True
    if detectors.get("secret_smuggle", True):
        findings += _scan(SECRET, text, "secret_smuggle", 0.6)
    if detectors.get("polymorphic_payload", True):
        findings += _polymorphic(text)

    if destination and detectors.get("shadow_endpoint", True):
        if not policy.destination_sanctioned(destination):
            findings.append(Finding("shadow_endpoint", 0.85, destination))
            hard_deny = True

    if contract and hops > contract.max_hops:
        findings.append(Finding("worm_replication", 0.55, f"hops {hops} > max {contract.max_hops}"))

    schema = policy.schema_for(contract)
    projected, proj_errors = project_to_schema(payload, schema)

    score = min(1.0, sum(f.weight for f in findings))
    families = {f.detector for f in findings}
    if len(families) >= 2:
        score = min(1.0, score + 0.1)

    reasons = [f"{f.detector}: {f.evidence}" for f in findings] + proj_errors
    thresholds = policy.ai.scoring

    if not policy.identity_allowed(identity) and policy.dark_until_authenticated:
        return Decision(
            action="deny",
            score=1.0,
            reasons=["dark resource: identity missing or unknown"],
            findings=[Finding("sdp", 1.0, identity or "none")],
            contract=contract_name,
            identity=identity,
        )

    if hard_deny or score >= thresholds.block_threshold:
        action = "deny"
    elif schema and (policy.ai.language_converter.get("drop_freeform_when_schema_declared") or score >= thresholds.challenge_threshold):
        action = "project" if projected is not None and not any(e.startswith("missing ") for e in proj_errors) else "deny"
        if action == "deny" and projected is None:
            reasons.append("language converter could not project onto contract schema")
    else:
        action = "allow"

    if action == "project" and projected is None:
        action = "deny"

    return Decision(
        action=action,
        score=score,
        reasons=reasons or ["clean"],
        findings=findings,
        projected=projected if action == "project" else None,
        contract=contract_name,
        identity=identity,
    )
