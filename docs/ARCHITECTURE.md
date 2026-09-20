# Aetherwall architecture

Aetherwall is a software-defined firewall whose enforcement target is not only
the 5-tuple. It is the *task contract* that an identity is allowed to perform
with a model, a tool, or another agent.

## Planes

### Control plane

Compiles YAML policy into a decision graph: identities, SDP resources,
contracts, inbound schemas, detector thresholds, hop budgets, sanctioned
model endpoints.

### Network data plane

Authenticate-before-connect. Until identity is proven, advertised resources
are dark. The Python proxy is the reference dataplane. `cmd/dataplane` is the
shape of the line-rate Go enforcement point.

### AI Defense Plane

**Language Converter Firewall** — inbound free-form text is projected onto a
closed schema. Jailbreaks that do not fit a field type cannot be represented.

**Data Abstraction Firewall** — outbound content is projected to the contract's
granularity (`label`, `abstract`, `findings`, `file-slice`, `ticket-id`).

**Quarantine vs privileged** — untrusted bytes are inspected only by a path
with no production credentials and no unconstrained tools.

## AI viruses

An AI virus is a payload that (a) is interpreted as instructions, (b) tries to
copy itself into another context window, tool argument, or peer message, and
(c) expands capabilities beyond the current contract.

Detectors look for the replication signature, not a static hash.

## Decision flow

SDP identity → sanctioned destination → contract → language converter →
detectors → hop budget → data abstraction → audit.

Actions: `allow`, `project`, `deny`.
