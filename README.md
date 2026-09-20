# Aetherwall

**A next-generation software-defined firewall for the AI threat era.**

Aetherwall treats prompts, tool calls, model context, and multi-agent messages as first-class network traffic. Traditional NGFWs inspect packets and apps. Aetherwall inspects *intent* — and contains self-replicating instruction payloads ("AI viruses") before they hop from document → agent → tool → peer agent.

> Scaffold status: working local control plane + data plane + AI Defense Plane, policy-as-code, attack fixtures, and a compile-ready Go dataplane stub. Not a production appliance.

## Why this exists

AI systems created a new class of network objects:

| Traffic | What a classic firewall sees | What actually happens |
|---|---|---|
| HTTPS to an LLM API | Port 443 to a SaaS IP | A prompt carrying secrets, jailbreaks, or a worm |
| Agent → MCP server | TLS to an internal tool | A tool-call graph that can exfiltrate or mutate state |
| Agent → agent | East-west JSON | An instruction payload that copies itself into the next context window |
| RAG ingest | File upload / HTTP GET | Indirect prompt injection planted in a page no human reads |

An **AI virus** in this project is a *self-propagating instruction payload*: text (or a tool result) that causes an agent to (1) ignore its task contract, (2) copy the payload into another channel, and (3) expand its capability set. Signature AV cannot keep up with LLM-generated polymorphism. Aetherwall's answer is structural, not just statistical.

## Architecture

```
                         Control Plane
              policy-as-code · identity · audit · intent compiler
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                                         ▼
     Network Data Plane                          AI Defense Plane
     • authenticate-before-connect               • Language Converter Firewall
     • L3–L7 + identity                          • Data Abstraction Firewall
     • SDP / dark resources                      • Quarantine vs privileged path
     • deny-by-default routes                    • MCP / tool-call mediator
                                                 • hop-budget + behavior graph
                                                 • polymorphic payload heuristics
```

Two ideas do most of the work:

1. **Language Converter Firewall** — inbound free-form text never reaches a privileged agent. It is projected onto a closed, schema-validated protocol. Manipulation has no channel left to ride.
2. **Data Abstraction Firewall** — outbound context is projected onto the *minimum granularity the task contract allows*. Binary redact-or-disclose is not enough.

The privileged controller never sees raw untrusted text; the quarantine inspector never holds production credentials or unconstrained tools.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start

```bash
# Python 3.11+
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run the stacked control + data + inspector planes
aetherwall up --plane both --policy policies/default.yaml

# Or:
docker compose up --build
```

Decide a payload without the proxy:

```bash
aetherwall inspect examples/attacks/injection_worm.json
aetherwall demo
```

## Repository map

```
aetherwall/
├── cmd/dataplane          Go dataplane stub (enforce compiled policy at line rate)
├── src/aetherwall         Python reference planes (runnable today)
│   ├── controlplane       Policy compile, decision API, audit
│   ├── dataplane          Identity-aware L7 proxy
│   ├── inspector          AI Defense Plane
│   └── policy             Intent → compiled enforcement graph
├── policies               Policy-as-code (YAML)
├── examples/attacks       Known-bad AI-virus fixtures
├── proto                  Decision / flow schemas
└── docs
```

## Threats in scope

- Direct and indirect prompt injection, including multi-hop worms
- Jailbreak / instruction-override / system-prompt extraction
- MCP and tool-call confused-deputy / capability escalation
- Context-window data exfiltration and secret smuggling
- AI-generated polymorphic binaries and scripts in transit
- Agent lateral movement past implicit east-west trust
- Shadow-AI egress (unsanctioned model endpoints)
- Retrieval-poisoned documents used as command channels

## Design principles

1. **Structure over persuasion.** Do not win an argument with an adversarial string. Remove the string's degree of freedom.
2. **Authenticate before packets.** Resources stay dark until identity + device + task contract are proven.
3. **Least context, not least privilege alone.** Privilege without context minimization still leaks.
4. **Quarantine models inspect; privileged models act.** Dual-LLM / two-brain split.
5. **Policy is compiled, not interpreted on the hot path.**
6. **Every deny is attributable.** Identity, contract, rule, evidence.

## Status

This is an engineering scaffold: real enforcement loop, real policies, real fixtures, intentional seams for production dataplane (eBPF/nftables, TLS inspection, IdP). Heuristic inspectors ship with the repo; plug a local embedding model or remote classifier at `AETHERWALL_EMBEDDING_ENDPOINT`.

## License

Apache-2.0. See [LICENSE](LICENSE).
