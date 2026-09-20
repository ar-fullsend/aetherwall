from __future__ import annotations

import time
from collections import deque
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from aetherwall.inspector.engine import inspect_payload
from aetherwall.policy import FirewallPolicy


class InspectRequest(BaseModel):
    payload: Any
    identity: str | None = None
    contract: str | None = None
    destination: str | None = None
    hops: int = 0


class AuditEvent(BaseModel):
    ts: float
    action: str
    score: float
    identity: str | None
    contract: str | None
    reasons: list[str]
    destination: str | None = None


def build_app(policy: FirewallPolicy) -> FastAPI:
    app = FastAPI(title="Aetherwall Control Plane", version="0.1.0")
    audit: deque[AuditEvent] = deque(maxlen=1000)
    compiled_at = time.time()

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "ok": True,
            "policy": policy.name,
            "identities": len(policy.identities),
            "contracts": list(policy.contracts),
            "compiled_at": compiled_at,
        }

    @app.get("/v1/policy")
    def get_policy() -> dict[str, Any]:
        return {
            "name": policy.name,
            "default_action": policy.default_action,
            "identities": policy.identities,
            "resources": [r.model_dump() for r in policy.resources],
            "contracts": {k: v.model_dump() for k, v in policy.contracts.items()},
            "sanctioned_endpoints": policy.sanctioned_endpoints,
            "scoring": policy.ai.scoring.model_dump(),
        }

    @app.post("/v1/decide")
    def decide(req: InspectRequest) -> dict[str, Any]:
        decision = inspect_payload(
            req.payload,
            policy,
            identity=req.identity,
            contract_name=req.contract,
            destination=req.destination,
            hops=req.hops,
        )
        audit.appendleft(
            AuditEvent(
                ts=time.time(),
                action=decision.action,
                score=decision.score,
                identity=req.identity,
                contract=req.contract,
                reasons=decision.reasons,
                destination=req.destination,
            )
        )
        return decision.as_dict()

    @app.get("/v1/audit")
    def get_audit(limit: int = 50) -> dict[str, Any]:
        return {"events": [e.model_dump() for e in list(audit)[:limit]]}

    @app.get("/v1/whoami")
    def whoami(x_aetherwall_identity: str | None = Header(default=None)) -> dict[str, Any]:
        if not policy.identity_allowed(x_aetherwall_identity):
            raise HTTPException(status_code=403, detail="dark")
        return {"identity": x_aetherwall_identity, "policy": policy.name}

    return app
