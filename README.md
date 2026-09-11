# did:aaid - Agentic AI Identifier

A DID method for AI agents that resolves an agent's keys from an identity document it
already publishes - an **A2A Agent Card** or an **OAuth Client ID Metadata Document
(CIMD, as used by MCP)** - without a registry or a ledger.

- **Specification:** [`did-method-aaid.md`](./did-method-aaid.md)
- **Method name:** `aaid` · **Example:** `did:aaid:mcp:example.com:agents:billing`
- **Trust root:** the agent's HTTPS origin
- **Status:** v1.0

## Why

An agent is one subject but is reached through several protocols, and each protocol has
its own place to put a public key (A2A: the card's extensions and `signatures`;
OAuth/MCP: the CIMD's `jwks_uri`). `did:aaid` makes the surface explicit in the
identifier, so a verifier knows exactly which document a key came from - and binds the
two identifiers for the same agent through `alsoKnownAs`.

## Repository layout

```
did-method-aaid.md                          # the specification
did-method-aaid.ko.md                       # Korean translation
registration/w3c-did-extensions/aaid.json   # entry to submit to w3c/did-extensions (methods/aaid.json)
```

## License

Apache-2.0.
