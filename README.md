# did:aaid - Agentic AI Identifier

A DID method for AI agents that resolves an agent's keys from an identity document it
already publishes - an **OAuth Client ID Metadata Document (CIMD)** - without a registry or
a ledger.

- **Specification:** [`did-method-aaid.md`](./did-method-aaid.md)
- **Method name:** `aaid` · **Example:** `did:aaid:cimd:example.com:agents:billing`
- **Trust root:** the agent's HTTPS origin
- **Status:** v1.0

## Why

An agent that identifies itself to an OAuth authorization server already publishes the
public keys it authenticates with in its CIMD (`jwks` / `jwks_uri`). CIMD is protocol-neutral:
MCP clients use it, and so do A2A clients calling OAuth-protected agents. `did:aaid` makes
that document addressable as a DID, so the same key can verify the agent in DID- and
VC-based systems, with no extra document to publish.

## How it resolves

```
did:aaid:cimd:example.com:agents:billing
        │
        ▼  B = https://example.com/agents/billing
GET B  ──►  CIMD   (client_id MUST equal B)
        │
        ▼  jwks  or  jwks_uri (same origin as B)
JWK Set ──►  signing keys  ──►  DID Document (authentication, assertionMethod)
```

`410 Gone` at `B` deactivates the DID. Every fetch is HTTPS-only, rejects cross-origin
redirects, and is treated as attacker-influenced for SSRF defenses.

## Trust model

This method creates no new root of trust. It exposes an existing one — control of a Web
PKI-authenticated HTTPS origin — through the DID resolution interface. It establishes *who
controls the origin*, not whether the agent should be trusted; that decision belongs to a
separate layer (trust registries, VC-based attestation).

## Surfaces and roles

The identifier carries a `surface` segment so that further identity-document formats can be
added without changing existing identifiers.

| Surface | Document | Agent role | Status |
|---|---|---|---|
| `cimd` | OAuth Client ID Metadata Document | calling (OAuth client), MCP or A2A | defined |
| `agentcard` | A2A Agent Card | called (serving requests) | **reserved** |

`agentcard` is not yet defined because the A2A specification does not currently designate a
field for the key an agent authenticates with, and an Agent Card's signing key is not, by
that specification, the agent's identity key. A future version **will define** the
`agentcard` surface once A2A standardizes this. See §1.1 of the specification.

## Future work

- Define the `agentcard` surface once A2A standardizes agent key publication.
- Require signed CIMD metadata if the CIMD draft adopts a signed-metadata option.

## Repository layout

```
did-method-aaid.md                          # the specification
registration/w3c-did-extensions/aaid.json   # entry to submit to w3c/did-extensions (methods/aaid.json)
```

## License

Copyright (c) 2026 The did:aaid Authors. Licensed under the Apache License 2.0 — see
[`LICENSE`](./LICENSE).
