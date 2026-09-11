# did:aaid - Agentic AI Identifier

A DID method for AI agents that resolves an agent's keys from an identity document it
already publishes - an **A2A Agent Card** or an **OAuth Client ID Metadata Document
(CIMD, as used by MCP)** - without a registry or a ledger.

- **Specification:** [`did-method-aaid.md`](./did-method-aaid.md) ([한국어](./did-method-aaid.ko.md))
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

## Registering with W3C (DID Extensions - Methods)

1. Tag a release (e.g. `v1.0.0`). A tag- or commit-pinned specification URL is preferred
   in the registry entry for content integrity.
2. Fork https://github.com/w3c/did-extensions and add `methods/aaid.json`
   (copy from `registration/w3c-did-extensions/aaid.json`).
3. Open a pull request. In the description, state that the method name is not a generic
   term, that you hold the IP/trademark rights to the specification, and link the spec.
   Registration is accepted once the editors confirm the DID Core §8 requirements are met.

## Universal Resolver driver (after W3C registration)

Universal Resolver requires the method to be registered with W3C first. Then:

1. Implement `GET /1.0/identifiers/{did}` returning a DID Document / Resolution Result
   (`application/did+ld+json`), following §2.2 of the specification.
2. Publish a Docker image and open a PR to
   https://github.com/decentralized-identity/universal-resolver editing
   `docker-compose.yml`, `application.yml` (pattern `^did:aaid:`), `.env`, and `README.md`
   per `docs/driver-development.md`.

## License

Apache-2.0.
