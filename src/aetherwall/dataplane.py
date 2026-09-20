from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse

from aetherwall.inspector.engine import inspect_payload
from aetherwall.policy import FirewallPolicy


UPSTREAM_DEFAULT = "http://127.0.0.1:8787"


def _extract_payload(body: bytes, content_type: str | None) -> Any:
    if not body:
        return {}
    if content_type and "json" in content_type:
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"_raw": body.decode("utf-8", "replace")}
    return {"text": body.decode("utf-8", "replace")}


def build_proxy(policy: FirewallPolicy, upstream: str = UPSTREAM_DEFAULT) -> FastAPI:
    app = FastAPI(title="Aetherwall Data Plane", version="0.1.0")
    header_name = policy.identity_header

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def enforce(
        path: str,
        request: Request,
        x_aetherwall_contract: str | None = Header(default=None),
        x_aetherwall_hops: int = Header(default=0),
        x_aetherwall_upstream: str | None = Header(default=None),
    ) -> Response:
        identity = request.headers.get(header_name)
        body = await request.body()
        payload = _extract_payload(body, request.headers.get("content-type"))
        dest = x_aetherwall_upstream or upstream
        destination_url = dest.rstrip("/") + "/" + path.lstrip("/")

        decision = inspect_payload(
            payload,
            policy,
            identity=identity,
            contract_name=x_aetherwall_contract,
            destination=dest,
            hops=x_aetherwall_hops,
        )

        envelope = {
            "firewall": "aetherwall",
            "action": decision.action,
            "score": decision.score,
            "reasons": decision.reasons,
            "contract": decision.contract,
            "identity": decision.identity,
        }

        if decision.action == "deny":
            return JSONResponse(status_code=403, content=envelope)

        out_body = body
        headers = {
            k: v for k, v in request.headers.items() if k.lower() not in {"host", "content-length"}
        }
        if decision.action == "project" and decision.projected is not None:
            out_body = json.dumps(decision.projected).encode()
            headers["content-type"] = "application/json"
            envelope["projected"] = True

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                proxied = await client.request(
                    request.method, destination_url, content=out_body or None, headers=headers
                )
        except httpx.RequestError as exc:
            envelope["upstream_error"] = str(exc)
            envelope["note"] = "enforced locally; upstream unreachable (expected in unit demo)"
            envelope["projected_body"] = decision.projected
            return JSONResponse(status_code=200, content=envelope)

        resp_body = proxied.content
        try:
            parsed = proxied.json()
            text = json.dumps(parsed)
            from aetherwall.inspector.engine import SECRET
            import re

            redacted = text
            for pat in SECRET:
                redacted = re.sub(pat, "[REDACTED]", redacted)
            if redacted != text:
                return JSONResponse(
                    status_code=proxied.status_code,
                    content={"upstream": json.loads(redacted), "firewall": envelope},
                )
        except Exception:
            pass

        return Response(
            content=resp_body,
            status_code=proxied.status_code,
            media_type=proxied.headers.get("content-type"),
            headers={"x-aetherwall-action": decision.action},
        )

    @app.get("/__aetherwall/health")
    def health() -> dict[str, Any]:
        return {"plane": "dataplane", "policy": policy.name}

    return app
