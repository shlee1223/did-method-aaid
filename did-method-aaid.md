# The `did:aaid` Method Specification (v1.0)

`did:aaid` is a DID method for AI agents. It derives a DID Document from the public key an agent already publishes in one of two identity documents it already serves - an **A2A Agent Card** or an **OAuth Client ID Metadata Document** (CIMD; the document MCP uses for client registration). There is no registry and no ledger. The root of trust is the agent's HTTPS origin.

| | |
|---|---|
| **Method name** | `aaid` |
| **Status** | v1.0 |
| **Specification** | https://github.com/shlee1223/did-method-aaid/blob/main/did-method-aaid.md |
| **Issues** | https://github.com/shlee1223/did-method-aaid/issues |
| **License** | Apache-2.0 |

This document conforms to [DID Core 1.0](https://www.w3.org/TR/did/) §8. MUST/SHOULD/MAY are to be read as described in RFC 2119 and RFC 8174.

## 1. Syntax

```abnf
aaid-did = "did:aaid:" surface ":" host *( ":" segment )
surface  = "a2a" / "mcp"
host     = 1*( ALPHA / DIGIT / "-" / "." )      ; a port is encoded as "%3A" port
segment  = 1*( ALPHA / DIGIT / "-" / "_" / "." / pct-encoded )
```

`surface` states **which document is the basis of this identity**. It is mandatory.

The base URL `B` is obtained by dropping `surface`, replacing each `:` after `host` with `/`, decoding `%3A`, and prefixing `https://`.

| DID | Base URL `B` |
|---|---|
| `did:aaid:a2a:example.com:agents:billing` | `https://example.com/agents/billing` |
| `did:aaid:mcp:example.com:agents:billing` | `https://example.com/agents/billing` |

**Location of the identity document**

| surface | Document URL | Notes |
|---|---|---|
| `mcp` | **`B` itself** | Per CIMD: the Client Identifier URL *is* the URL of the metadata document, and the document's `client_id` MUST equal that URL |
| `a2a` (path form) | `B/agent-card.json` | **An AAID convention.** It does not redefine A2A's origin-level well-known location (`https://host/.well-known/agent-card.json`) |
| `a2a` (root form, `host` only) | `https://host/.well-known/agent-card.json` | Here `B` is the origin, so this coincides with A2A's standard discovery location |

An `a2a` DID and an `mcp` DID derived from the same base URL `B` **identify the same agent subject.** Each DID Document expresses the other surface's DID as `alsoKnownAs` (§2.2).

> For the `mcp` surface, `B` itself is the document, so the root form (`did:aaid:mcp:host`) requires the site root to return a CIMD. In practice the path form SHOULD be used.

## 2. Operations

### 2.0 Authorization

Authorization for every operation is determined by control of the base URL's HTTPS origin. Whoever can publish a document at that URL is the DID controller. The DID Document itself is never used to make an authorization decision.

### 2.1 Create

The controller chooses an identity key (a JWK; `kid` REQUIRED) and publishes the document for the chosen surface according to the profile below. There is no third-party registration step.

**`a2a` - Agent Card** ([A2A specification](https://a2a-protocol.org/latest/specification/), `AgentCard`).
A2A defines digital signing of the Agent Card (`signatures[]`, JCS canonicalization + JWS) as OPTIONAL (MAY). `did:aaid:a2a` raises this to a requirement and additionally fixes where the identity key is declared:

1. `capabilities.extensions` MUST contain the extension `{"uri":"https://github.com/shlee1223/did-method-aaid#ext-v1","params":{…}}`, whose `params` carry either `jwks_uri` or an inline `jwks`. **AAID additionally requires that `jwks_uri` be on the same HTTPS origin as `B` (MUST).**
2. `signatures[]` MUST contain at least one signature. The `kid` in its `protected` header MUST be present in the JWK Set from (1), and the signature MUST verify with that key under A2A's canonicalization and JWS procedure. In other words, the card is signed by the identity key.

**`mcp` - CIMD** ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)).

1. The document MUST be served at `B`, and `client_id` MUST equal `B` (per CIMD).
2. The identity key MUST be declared via `jwks` or `jwks_uri` (both permitted by CIMD). **CIMD does not constrain the origin of `jwks_uri`; AAID additionally requires it to be on the same HTTPS origin as `B` (MUST).**

An agent that publishes both documents SHOULD point them at the same `jwks_uri`.

### 2.2 Resolve

1. Parse the DID. On an ABNF violation, return `invalidDid`.
2. **Fetch the identity document.** `GET` the document URL for `surface` (§1) with `Accept: application/json`, over HTTPS only, rejecting any redirect that changes origin.
   - `200` → validate against the profile and extract keys. On a violation, `invalidSurface` → `notFound`.
   - `410` → return `deactivated: true` and stop.
   - `404` or anything else → `notFound`.
3. **Extract keys.** For `a2a`, the JWK Set from the extension (the card signature MUST then be verified); for `mcp`, `jwks`/`jwks_uri`. A `jwks_uri` MUST be same-origin with `B` (an AAID constraint). Any secret parameters found MUST be discarded.
4. **Probe the opposite surface.** `GET` the other surface's document URL for the same `B`. If the response is `200`, has a JSON content type, and parses, that surface is taken to exist. No key is read and no profile validation is performed. A failed probe (404, error, timeout) MUST NOT fail the resolution.
5. **Assemble the DID Document.**
   - `id` = the requested DID.
   - `verificationMethod` = for each key from (3), `{ id: <DID>#<kid>, type: "JsonWebKey2020", controller: <DID>, publicKeyJwk }`.
   - `authentication`, `assertionMethod` = all keys.
   - `service` = the identity document, `{ id: <DID>#a2a | #mcp, type: "A2AAgentCard" | "OAuthClientMetadata", serviceEndpoint: <URL> }`. If (4) found the opposite surface, add its document too.
   - `alsoKnownAs` = if (4) found the opposite surface, it MUST contain that surface's DID (`did:aaid:<other surface>:<same host:segments>`). For `mcp`, it SHOULD also contain the CIMD `client_id` (= `B`).
6. Return `didResolutionMetadata.surfaces` = `{ <surface>: "found", <other>: "found" | "absent" }`.

**Authenticity of the response.** The resolver verifies the origin over TLS (step 2) and, for `a2a`, additionally verifies the identity-key signature (step 3). For `mcp` there is no signature beyond TLS. The opposite-surface probe (step 4) exists only to express the binding and is not evidence about keys.

### 2.3 Update

Republishing the document at the same URL is an update. Key rotation: add the new key to the JWK Set → (for `a2a`) re-sign the Agent Card with the new key → remove the old key after an overlap period. Removing the old key immediately would break verification of cached signatures, so an overlap period SHOULD be used.

### 2.4 Deactivate

Remove the document and make that URL return `410 Gone`. A DID whose identity document returns `410` is deactivated. The state of the opposite surface has no bearing on whether this DID is active.

## 3. Security Considerations

Per RFC 3552. Scope of protection: TLS protects the transport of every document (confidentiality, integrity, server authentication). The Agent Card is additionally protected for integrity and origin by the identity-key JWS. The CIMD and the JWK Set have no protection beyond TLS. Secret material (private keys) is out of scope for this method and MUST NOT appear in any of these documents.

| Attack | Operation | Mitigation |
|---|---|---|
| Eavesdropping | Resolve | The documents are public information. TLS protects the path |
| Replay | Resolve | The documents carry no nonce, so replay is harmless in itself. Replay of a stale document (rollback) is bounded by the cache rules and `410` |
| Insertion / deletion / modification | Create, Update, Deactivate | Origin control is authorization. If the origin is compromised, an attacker can publish keys (residual risk). Modification of an Agent Card is detected by signature verification |
| Denial of service | Resolve | At most two document fetches per resolution (identity document + opposite-surface probe) plus at most one JWK Set fetch. Resolvers SHOULD impose size and time limits. If the origin is down, resolution fails |
| Amplification | Resolve | A resolver performs a fixed number of fetches per caller. There is no amplification factor |
| Man in the middle | Resolve | TLS server authentication. `http` is forbidden, cross-origin redirects are rejected, and `jwks_uri` is forced same-origin (an AAID constraint) |

**Residual risks.** (1) Compromise of DNS, a certificate, or the web host - this method provides no ledger-style evidence of tampering; origin security *is* DID security. (2) `alsoKnownAs` expresses AAID's relation that two DIDs derived from the same base URL `B` identify the same agent subject. It does not imply that the keys used on the two surfaces are identical or mutually authenticated; to trust the opposite surface's keys, resolve that DID separately. (3) Revocation latency - key removal and deactivation are observed only on re-resolution (caches bounded by the document's `max-age`, and by 24 hours). Where immediate revocation is required, a credential-level status list (e.g. Bitstring Status List) SHOULD be used alongside. (4) Resolver implementation errors (skipping signature verification, omitting the origin check) defeat the protections above.

**Integrity and update authentication.** Update and deactivation are authenticated by write access to the origin. The integrity of a resolution result is provided by TLS (all documents) and by the identity-key signature (Agent Card).

**Endpoint authentication.** Authentication of the document URL is TLS server authentication. Resolvers MUST validate the certificate.

**Uniqueness.** Uniqueness is established by surface, DNS host, and path. Two parties cannot control the same host and path, so DIDs are uniquely assigned.

## 4. Privacy Considerations

Per RFC 6973 §5.

- **Surveillance, correlation, identification:** the DID reveals a host and a path, and resolution leaves an access log at the origin (resolver IP, timestamp). The opposite-surface probe leaves one additional access log entry. Agent identity is meant to be public, so this is by design. A subject that must avoid correlation should not use this method.
- **Stored data compromise:** the documents contain public keys only. Private keys are protected separately by the origin.
- **Unsolicited traffic:** resolvers send requests to the origin. Resolvers SHOULD cache to reduce repeated requests.
- **Misattribution:** if the origin is compromised, another party's actions can be attributed to the agent (§3).
- **Secondary use and disclosure:** Agent Cards and CIMDs are public documents. They SHOULD NOT carry personal data about human subjects.
- **Exclusion:** the DID subject publishes its own document and so cannot be excluded by a third party. It does, however, depend on its DNS and hosting providers.

## 5. Example

Resolving `did:aaid:mcp:example.com:agents:billing`. The identity document is `B` itself (a CIMD), and an Agent Card also exists at the same `B`.

`GET https://example.com/agents/billing` (CIMD)
```json
{ "client_id": "https://example.com/agents/billing",
  "client_name": "Billing Agent",
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://example.com/agents/billing/jwks.json" }
```

`GET https://example.com/agents/billing/jwks.json`
```json
{ "keys": [ { "kty": "EC", "crv": "P-256", "kid": "k1", "x": "…", "y": "…", "alg": "ES256", "use": "sig" } ] }
```

`GET https://example.com/agents/billing/agent-card.json` → `200`, JSON (probe only; no key is read)

Resolution result
```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
  "id": "did:aaid:mcp:example.com:agents:billing",
  "alsoKnownAs": ["did:aaid:a2a:example.com:agents:billing",
                  "https://example.com/agents/billing"],
  "verificationMethod": [ { "id": "did:aaid:mcp:example.com:agents:billing#k1",
    "type": "JsonWebKey2020", "controller": "did:aaid:mcp:example.com:agents:billing",
    "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "k1", "x": "…", "y": "…" } } ],
  "authentication":  ["did:aaid:mcp:example.com:agents:billing#k1"],
  "assertionMethod": ["did:aaid:mcp:example.com:agents:billing#k1"],
  "service": [
    { "id": "did:aaid:mcp:example.com:agents:billing#mcp", "type": "OAuthClientMetadata",
      "serviceEndpoint": "https://example.com/agents/billing" },
    { "id": "did:aaid:mcp:example.com:agents:billing#a2a", "type": "A2AAgentCard",
      "serviceEndpoint": "https://example.com/agents/billing/agent-card.json" } ]
}
```
`didResolutionMetadata.surfaces` = `{ "mcp": "found", "a2a": "found" }`.

Resolving `did:aaid:a2a:example.com:agents:billing` is symmetric: keys are read from `B/agent-card.json` (with signature verification), `B` (the CIMD) is probed, and `did:aaid:mcp:…` is placed in `alsoKnownAs`.

## References

DID Core 1.0 · A2A Protocol Specification (`a2a.proto`; Agent Card signature: JCS + JWS) · draft-ietf-oauth-client-id-metadata-document-02 · RFC 7515 · RFC 7517 · RFC 3552 · RFC 6973 · RFC 2119 / 8174

---
Change log - v1.0: first stable release. `alsoKnownAs` is stated in §1 as the relation "identifies the same agent subject", and §3 distinguishes that from key identity. v0.4: corrected the `mcp` document URL to `B` itself (per CIMD); stated that A2A's well-known location is not redefined and separated the path form as an AAID convention; corrected the description of A2A signatures as OPTIONAL (MAY), raised to MUST by AAID; stated that the same-origin `jwks_uri` rule is AAID's additional constraint rather than CIMD's. v0.3: removed the base form, made `surface` mandatory, bound the surfaces via an opposite-surface probe. v0.2: narrowed the method to two documents. v0.1: initial draft.
