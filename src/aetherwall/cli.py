from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from aetherwall.controlplane import build_app
from aetherwall.dataplane import build_proxy
from aetherwall.inspector.engine import inspect_payload
from aetherwall.policy import load_policy

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()


@app.command()
def up(
    policy: Path = typer.Option(Path("policies/default.yaml")),
    plane: str = typer.Option("control", help="control | data | both"),
    host: str = "127.0.0.1",
    port: int = 8080,
    data_port: int = 8443,
    upstream: str = "http://127.0.0.1:8787",
) -> None:
    """Start a plane."""
    compiled = load_policy(policy)
    console.print(f"[bold]Aetherwall[/bold] policy={compiled.name} plane={plane}")
    if plane == "control":
        uvicorn.run(build_app(compiled), host=host, port=port, log_level="info")
    elif plane == "data":
        uvicorn.run(build_proxy(compiled, upstream=upstream), host=host, port=data_port, log_level="info")
    elif plane == "both":
        combined = build_proxy(compiled, upstream=upstream)
        combined.mount("/__control", build_app(compiled))
        uvicorn.run(combined, host=host, port=data_port, log_level="info")
    else:
        raise typer.BadParameter("plane must be control, data, or both")


@app.command()
def inspect(
    target: Path,
    policy: Path = typer.Option(Path("policies/default.yaml")),
    identity: str = typer.Option("agent:docs-helper"),
    contract: Optional[str] = typer.Option("summarize"),
    hops: int = 0,
) -> None:
    """Run the AI Defense Plane against a file (json or text)."""
    compiled = load_policy(policy)
    raw = target.read_text()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"text": raw}
    decision = inspect_payload(
        payload, compiled, identity=identity, contract_name=contract, hops=hops
    )
    console.print_json(data=decision.as_dict())


@app.command()
def demo(policy: Path = typer.Option(Path("policies/default.yaml"))) -> None:
    """Evaluate bundled attack fixtures and print a scoreboard."""
    compiled = load_policy(policy)
    root = Path("examples/attacks")
    if not root.exists():
        console.print("no examples/attacks directory")
        raise typer.Exit(1)
    table = Table(title="Aetherwall AI-virus fixtures")
    table.add_column("fixture")
    table.add_column("action")
    table.add_column("score")
    table.add_column("top reason")
    for path in sorted(root.glob("*")):
        raw = path.read_text()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"text": raw}
        identity = payload.pop("_identity", "agent:docs-helper") if isinstance(payload, dict) else "agent:docs-helper"
        contract = payload.pop("_contract", "summarize") if isinstance(payload, dict) else "summarize"
        hops = int(payload.pop("_hops", 0)) if isinstance(payload, dict) else 0
        dest = payload.pop("_destination", None) if isinstance(payload, dict) else None
        decision = inspect_payload(
            payload, compiled, identity=identity, contract_name=contract, destination=dest, hops=hops
        )
        table.add_row(path.name, decision.action, f"{decision.score:.2f}", decision.reasons[0][:80])
    console.print(table)


@app.command()
def compile_policy(policy: Path = typer.Option(Path("policies/default.yaml"))) -> None:
    """Validate and pretty-print the compiled enforcement graph."""
    compiled = load_policy(policy)
    console.print_json(
        data={
            "name": compiled.name,
            "identities": compiled.identities,
            "contracts": {k: v.model_dump() for k, v in compiled.contracts.items()},
            "resources": [r.model_dump() for r in compiled.resources],
        }
    )


if __name__ == "__main__":
    app()
