"""Optional embedding classifier seam.

Set AETHERWALL_EMBEDDING_ENDPOINT to a compatible HTTP classifier:

    POST {endpoint}
    {"text": "..."}
    -> {"score": 0.0-1.0, "label": "malicious"|"benign"}

When unset, the heuristic engine in engine.py is the sole scorer.
"""

from __future__ import annotations

import os
from typing import Any

import httpx


def embedding_score(text: str) -> dict[str, Any] | None:
    endpoint = os.environ.get("AETHERWALL_EMBEDDING_ENDPOINT")
    if not endpoint:
        return None
    response = httpx.post(endpoint, json={"text": text}, timeout=3.0)
    response.raise_for_status()
    return response.json()
