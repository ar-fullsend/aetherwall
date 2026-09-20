# Security policy

Aetherwall is a defensive security research scaffold. It is **not** a
production firewall. Do not put it in front of real user traffic and assume
containment.

## What we will not accept

- Exploit payloads whose purpose is to teach offense rather than test a detector
- Requests for weaponized "AI virus" samples beyond the sanitized fixtures in
  `examples/attacks/`
- Signing or packaging this repo as a commercial appliance without a threat
  model review

## Reporting

Open a private advisory on GitHub or email the repository owner. Please include
the policy version, the fixture or traffic sample, and the expected vs actual
decision.

## Threat model snapshot

Trusted: control plane host, policy authors, identity issuer.

Untrusted: every prompt, retrieved document, tool result, model completion,
and peer-agent message.

Non-goals of v0.1: TLS interception at line rate, eBPF packet filter, IdP
integration, trained embedding classifier in CI.
