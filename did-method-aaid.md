# The `did:aaid` Method Specification (v1.0)

`did:aaid` is a DID method for AI agents. It derives a DID Document from the public key an agent already publishes in its **OAuth Client ID Metadata Document** (CIMD). There is no registry and no ledger. The root of trust is the agent's HTTPS origin.

CIMD is an OAuth-layer document and is not tied to one agent protocol. An agent publishes one when it acts as an **OAuth client** — when it calls an MCP server (MCP uses CIMD for client identification), or when it calls another A2A agent whose Agent Card declares an OAuth 2.0 or OpenID Connect security scheme. `did:aaid` therefore identifies MCP and A2A agents alike **in their calling role**. An agent that only receives calls (e.g. an A2A server that never acts as a client) publishes no CIMD; that role is the purpose of the reserved `agentcard` surface (§1.1).

| | |
|---|---|
| **Method name** | `aaid` |
| **Status** | v1.0 |
| **Specification** | https://github.com/shlee1223/did-method-aaid/blob/main/did-method-aaid.md |
| **Issues** | https://github.com/shlee1223/did-method-aaid/issues |
| **License** | Apache-2.0 |

This document conforms to [DID Core 1.0](https://www.w3.org/TR/did/) §8. MUST/SHOULD/MAY are to be read as described in RFC 2119 and RFC 8174.

**Copyright and intellectual property.** Copyright (c) 2026 The did:aaid Authors. This specification is made available under the [Apache License 2.0](./LICENSE); rights not expressly granted by that license are reserved. The method name `aaid` is not currently claimed as a trademark. To the best of the authors' knowledge at the time of writing, no third-party patent or other intellectual-property claim encumbers this method; this statement is informational and is not a warranty.

## 1. Syntax

```abnf
aaid-did = "did:aaid:" surface ":" host *( ":" segment )
surface  = "cimd"                               ; see §1.1 for reserved values
host     = 1*( ALPHA / DIGIT / "-" / "." )      ; a port is encoded as "%3A" port
segment  = 1*( ALPHA / DIGIT / "-" / "_" / "." / pct-encoded )
```

`surface` states **which identity document format is the basis of this identity**. This version defines one surface, `cimd` (an OAuth Client ID Metadata Document). `surface` is mandatory. A resolver that encounters a `surface` value this version does not define MUST return `invalidDid`.

The base URL `B` is obtained by dropping `surface`, replacing each `:` after `host` with `/`, decoding `%3A`, and prefixing `https://`. For the `cimd` surface, `B` is the Client Identifier URL, which is also the URL of the metadata document.

| DID | Base URL `B` = document URL |
|---|---|
| `did:aaid:cimd:example.com:agents:billing` | `https://example.com/agents/billing` |

> Because `B` itself is the document, the root form (`did:aaid:cimd:host`) requires the site root to return a CIMD. In practice the path form SHOULD be used.

### 1.1 Reserved surface: `agentcard`

The surface value `agentcard` is **reserved** for identities based on an A2A Agent Card. It is not defined in this version, and resolvers MUST treat it as undefined (`invalidDid`) until a future version defines it.

**The two surfaces cover two roles.** `cimd` identifies an agent in its *calling* role: the document exists because the agent is an OAuth client. `agentcard` is meant to identify an agent in its *called* role: the Agent Card exists because the agent serves requests. Most agents do both and would then hold both identifiers for the same base URL; an agent that only serves A2A requests has no CIMD and can be identified only once `agentcard` is defined.

**Why it is not defined now.** An Agent Card does not, today, offer a sound basis from which to derive an agent's identity key, for three reasons:

1. **The signing key has a different purpose.** A2A Agent Card signatures (`signatures[]`) exist to protect the integrity of the card. The key that signs a card is not, by any statement of the A2A specification, the key the agent uses to authenticate itself; it may legitimately belong to a hosting platform or a publishing pipeline. Reading it as the agent's identity key would assign it a meaning its own specification does not give it.
2. **Relying on it would turn optional features into requirements.** Card signing and `jku` are OPTIONAL in A2A. Requiring both would leave most Agent Cards that exist today unresolvable, contradicting the premise of this method — using the document an agent *already* publishes.
3. **There is no designated place for the key.** The A2A specification does not, at the time of writing, define a field in which an agent publishes the public key it authenticates with. Without such a field, any key-discovery rule would be a convention invented by this method rather than a reading of the A2A specification.

**Commitment.** The `surface` segment exists so that new document formats can be added without changing any existing `did:aaid` identifier. When the A2A specification (or an A2A extension adopted by the A2A project) standardizes how an agent publishes its authentication key, a subsequent version of this specification **will define the `agentcard` surface** on that standardized basis, and will define how a `cimd` DID and an `agentcard` DID derived from the same base URL relate to each other.

## 2. Operations

### 2.0 Authorization

Authorization for every operation is determined by control of the base URL's HTTPS origin. Whoever can publish a document at that URL is the DID controller. The DID Document itself is never used to make an authorization decision.

This method establishes control of an origin; it makes no statement about whether that origin, or the key it designates as its authentication key, should be *trusted* for any purpose beyond that control. Applications requiring an authorization or trust decision (e.g., which agents may act on a given task, which keys to rely on beyond mere origin control) SHOULD layer a separate trust mechanism — e.g., a trust registry protocol or Verifiable Credential-based attestation — on top of DID resolution. This method supplies the *subject identity* such a decision is made about, not the decision itself.

### 2.1 Create

The controller chooses an identity key (a JWK; `kid` REQUIRED) and publishes a CIMD ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)) according to the profile below. There is no third-party registration step.

1. The document MUST be served at `B`, and `client_id` MUST equal `B` (per CIMD).
2. The identity key MUST be declared via `jwks` or `jwks_uri` (both permitted by CIMD). These are the keys the client uses to authenticate itself (e.g. `private_key_jwt`), which is exactly the meaning this method gives them. **CIMD does not constrain the origin of `jwks_uri`; AAID additionally requires it to be on the same HTTPS origin as `B` (MUST).**
3. A CIMD carries no signature of its own. Its keys are protected by TLS and same-origin placement only (§3). This reflects a gap in the underlying CIMD draft, which does not itself define a signed-metadata option (unlike neighboring OAuth metadata specifications, e.g. Authorization Server Metadata and Protected Resource Metadata, which allow a JWT-signed alternative) — not a deliberate AAID design choice. Should CIMD adopt a signed-metadata option in a future revision, this specification is expected to require it.

### 2.2 Resolve

1. Parse the DID. On an ABNF violation, or on a `surface` value this version does not define (§1.1), return `invalidDid`.
2. **Fetch the identity document.** `GET B` with `Accept: application/json`, over HTTPS only, rejecting any redirect that changes origin. Resolvers MUST treat this fetch (and the `jwks_uri` fetch in step 3) as fetching an attacker-influenced URL for the purposes of request-forgery defenses: resolve the host and reject requests that target private, loopback, or link-local address space, and re-validate the resolved address is not private immediately before connecting (to close DNS-rebinding TOCTOU gaps).
   - `200` → validate against the profile (§2.1) and extract keys. On a violation, `invalidSurface` → `notFound`.
   - `410` → return `deactivated: true` and stop.
   - `404` or anything else → `notFound`.
3. **Extract keys.** Take `jwks`, or fetch the JWK Set at `jwks_uri`. A `jwks_uri` MUST be same-origin with `B` (an AAID constraint) and MUST be fetched under the same request-forgery defenses as step 2. Any secret parameters found MUST be discarded. **Retain only keys usable for verifying signatures:** discard a JWK whose `use` is present and is not `"sig"`, and one whose `key_ops` is present and does not include `"verify"`; a JWK carrying neither member is retained. If no key remains, the document does not satisfy the profile: `invalidSurface` → `notFound`.
4. **Assemble the DID Document.**
   - `id` = the requested DID.
   - `verificationMethod` = for each key from (3), `{ id: <DID>#<kid>, type: "JsonWebKey2020", controller: <DID>, publicKeyJwk }`.
   - `authentication`, `assertionMethod` = every retained key. The agent authenticates as this DID subject with them, and signs assertions made on its own behalf with them. AAID defines no `keyAgreement`, `capabilityInvocation` or `capabilityDelegation`; a key excluded in (3) appears in none of these.
   - `service` = `{ id: <DID>#cimd, type: "OAuthClientMetadata", serviceEndpoint: B }`.
   - `alsoKnownAs` SHOULD contain the CIMD `client_id` (= `B`).

**Authenticity of the response.** The resolver verifies the origin over TLS (step 2). There is no signature beyond TLS.

### 2.3 Update

Republishing the document at the same URL is an update. Key rotation: publish the new key in `jwks` / at `jwks_uri` → start using it → remove the old key after an overlap period. Removing the old key immediately would break verification of cached signatures, so an overlap period SHOULD be used.

### 2.4 Deactivate

Remove the document and make `B` return `410 Gone`. A DID whose identity document returns `410` is deactivated.

## 3. Security Considerations

Per RFC 3552. Scope of protection: TLS protects the transport of every document (confidentiality, integrity, server authentication). The CIMD and the JWK Set have no protection beyond TLS. Secret material (private keys) is out of scope for this method and MUST NOT appear in any of these documents.

| Attack | Operation | Mitigation |
|---|---|---|
| Eavesdropping | Resolve | The documents are public information. TLS protects the path |
| Replay | Resolve | The documents carry no nonce, so replay is harmless in itself. Replay of a stale document (rollback) is bounded by the cache rules and `410` |
| Insertion / deletion / modification | Create, Update, Deactivate | Origin control is authorization. If the origin is compromised, an attacker can publish keys (residual risk) |
| Denial of service | Resolve | At most one document fetch plus at most one JWK Set fetch per resolution. Resolvers SHOULD impose size and time limits. If the origin is down, resolution fails |
| Amplification | Resolve | A resolver performs a fixed number of fetches per caller. There is no amplification factor |
| Man in the middle | Resolve | TLS server authentication. `http` is forbidden, cross-origin redirects are rejected, and `jwks_uri` is forced same-origin (an AAID constraint) |
| Request forgery (SSRF) | Resolve | Every URL fetched during resolution (identity document, `jwks_uri`) is attacker-influenced. Resolvers MUST reject targets in private, loopback, or link-local address space and MUST re-validate the resolved address immediately before connecting, not only at DNS-resolution time (DNS rebinding) |

**Root of trust and its limits.** Authorization and key discovery in this method both reduce, ultimately, to control of a Web PKI-authenticated HTTPS origin: an identity key is "the agent's key" only in the sense that whoever controls `B` designated it as such, verified via the public Certificate Authority trust model rather than a method-specific ledger or trust root. This method creates no new root of trust; it exposes an existing one through the DID resolution interface, and makes no claim about the trustworthiness of that key or its holder beyond origin control — that judgment belongs to a separate trust layer (§2.0).

**Residual risks.** (1) Compromise of DNS, a certificate, or the web host - this method provides no ledger-style evidence of tampering; origin security *is* DID security, which is to say this method inherits the residual risks of the public Web PKI (mis-issuance, CA compromise, DNS hijacking) rather than defining its own trust root. (2) Revocation latency - key removal and deactivation are observed only on re-resolution (caches bounded by the document's `max-age`, and by 24 hours). Where immediate revocation is required, a credential-level status list (e.g. Bitstring Status List) SHOULD be used alongside. (3) Resolver implementation errors (omitting the origin check, omitting request-forgery defenses on attacker-influenced fetches) defeat the protections above.

**Integrity and update authentication.** Update and deactivation are authenticated by write access to the origin. The integrity of a resolution result is provided by TLS.

**Endpoint authentication.** Authentication of the document URL is TLS server authentication. Resolvers MUST validate the certificate.

**Uniqueness.** Uniqueness is established by surface, DNS host, and path. Two parties cannot control the same host and path, so DIDs are uniquely assigned.

## 4. Privacy Considerations

Per RFC 6973 §5.

- **Surveillance, correlation, identification:** the DID reveals a host and a path, and resolution leaves an access log at the origin (resolver IP, timestamp). Agent identity is meant to be public, so this is by design. A subject that must avoid correlation should not use this method.
- **Stored data compromise:** the documents contain public keys only. Private keys are protected separately by the origin.
- **Unsolicited traffic:** resolvers send requests to the origin. Resolvers SHOULD cache to reduce repeated requests.
- **Misattribution:** if the origin is compromised, another party's actions can be attributed to the agent (§3).
- **Secondary use and disclosure:** CIMDs are public documents. They SHOULD NOT carry personal data about human subjects.
- **Exclusion:** the DID subject publishes its own document and so cannot be excluded by a third party. It does, however, depend on its DNS and hosting providers.

## 5. Example

Resolving `did:aaid:cimd:example.com:agents:billing`.

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

Resolution result

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
  "id": "did:aaid:cimd:example.com:agents:billing",
  "alsoKnownAs": ["https://example.com/agents/billing"],
  "verificationMethod": [ { "id": "did:aaid:cimd:example.com:agents:billing#k1",
    "type": "JsonWebKey2020", "controller": "did:aaid:cimd:example.com:agents:billing",
    "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "k1", "x": "…", "y": "…" } } ],
  "authentication":  ["did:aaid:cimd:example.com:agents:billing#k1"],
  "assertionMethod": ["did:aaid:cimd:example.com:agents:billing#k1"],
  "service": [
    { "id": "did:aaid:cimd:example.com:agents:billing#cimd", "type": "OAuthClientMetadata",
      "serviceEndpoint": "https://example.com/agents/billing" } ]
}
```

## 6. Future Work

- **`agentcard` surface** — reserved (§1.1); to be defined once A2A standardizes how an agent publishes its authentication key.
- **Signed CIMD** — to be required if the CIMD draft adopts a signed-metadata option (§2.1).

## References

DID Core 1.0 · draft-ietf-oauth-client-id-metadata-document · A2A Protocol Specification (for the reserved `agentcard` surface) · RFC 7515 · RFC 7517 · RFC 8725 · RFC 3552 · RFC 6973 · RFC 2119 / 8174
