from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class Resource(BaseModel):
    name: str
    hosts: list[str]
    contracts: list[str] = Field(default_factory=list)


class Contract(BaseModel):
    description: str = ""
    inbound_schema: str | None = None
    outbound_granularity: str = "abstract"
    max_hops: int = 1
    tools: list[str] = Field(default_factory=list)


class Schema(BaseModel):
    type: str = "object"
    required: list[str] = Field(default_factory=list)
    additionalProperties: bool = False
    properties: dict[str, Any] = Field(default_factory=dict)


class Scoring(BaseModel):
    block_threshold: float = 0.72
    challenge_threshold: float = 0.45


class AIDefense(BaseModel):
    language_converter: dict[str, Any] = Field(default_factory=dict)
    data_abstraction: dict[str, Any] = Field(default_factory=dict)
    quarantine: dict[str, Any] = Field(default_factory=dict)
    scoring: Scoring = Field(default_factory=Scoring)
    detectors: dict[str, bool] = Field(default_factory=dict)


class FirewallPolicy(BaseModel):
    raw: dict[str, Any]
    name: str
    identities: list[str]
    identity_header: str
    default_action: str
    sanctioned_endpoints: list[str]
    resources: list[Resource]
    contracts: dict[str, Contract]
    schemas: dict[str, Schema]
    ai: AIDefense
    dark_until_authenticated: bool = True

    def contract(self, name: str | None) -> Contract | None:
        if not name:
            return None
        return self.contracts.get(name)

    def schema_for(self, contract: Contract | None) -> Schema | None:
        if not contract or not contract.inbound_schema:
            return None
        return self.schemas.get(contract.inbound_schema)

    def identity_allowed(self, identity: str | None) -> bool:
        if not identity:
            return False
        return identity in self.identities

    def destination_sanctioned(self, url: str) -> bool:
        return any(url.startswith(ep) or ep in url for ep in self.sanctioned_endpoints)


def load_policy(path: str | Path) -> FirewallPolicy:
    data = yaml.safe_load(Path(path).read_text())
    meta = data.get("metadata", {})
    identity = data.get("identity", {})
    network = data.get("network", {})
    sdp = data.get("sdp", {})
    contracts = {
        name: Contract(**spec) for name, spec in data.get("contracts", {}).items()
    }
    schemas = {name: Schema(**spec) for name, spec in data.get("schemas", {}).items()}
    resources = [Resource(**r) for r in sdp.get("resources", [])]
    return FirewallPolicy(
        raw=data,
        name=meta.get("name", "unnamed"),
        identities=list(identity.get("allow", [])),
        identity_header=identity.get("header", "x-aetherwall-identity"),
        default_action=network.get("default_action", "deny"),
        sanctioned_endpoints=list(network.get("sanctioned_model_endpoints", [])),
        resources=resources,
        contracts=contracts,
        schemas=schemas,
        ai=AIDefense(**data.get("ai_defense", {})),
        dark_until_authenticated=bool(network.get("dark_until_authenticated", True)),
    )
