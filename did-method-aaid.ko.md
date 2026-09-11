# did:aaid 메서드 명세 (v1.0, 한국어본)

`did:aaid`는 AI 에이전트의 DID다. 에이전트가 이미 게시하는 두 신원 문서 - A2A Agent Card, OAuth Client ID Metadata Document(CIMD; MCP가 클라이언트 등록에 쓰는 문서) - 중 하나에서 공개키를 읽어 DID Document를 만든다. 레지스트리와 원장은 쓰지 않는다. 신뢰 루트는 에이전트의 HTTPS 오리진이다.

- 스펙: https://github.com/shlee1223/did-method-aaid/blob/main/did-method-aaid.md
- 이슈: https://github.com/shlee1223/did-method-aaid/issues
- 이 문서는 [DID Core 1.0](https://www.w3.org/TR/did/) §8을 따른다. MUST/SHOULD/MAY는 RFC 2119·8174의 의미다.

## 1. 문법

```abnf
aaid-did = "did:aaid:" surface ":" host *( ":" segment )
surface  = "a2a" / "mcp"
host     = 1*( ALPHA / DIGIT / "-" / "." )      ; 포트는 "%3A" 포트
segment  = 1*( ALPHA / DIGIT / "-" / "_" / "." / pct-encoded )
```

`surface`는 이 DID가 **어느 문서를 신원의 근거로 삼는지**를 정한다. 필수다.

기준 URL `B` = `surface`를 떼고, 호스트 뒤의 `:`을 `/`로 바꾸고, `%3A`를 디코딩한 뒤 `https://`를 붙인 것.

| DID | 기준 URL `B` |
|---|---|
| `did:aaid:a2a:example.com:agents:billing` | `https://example.com/agents/billing` |
| `did:aaid:mcp:example.com:agents:billing` | `https://example.com/agents/billing` |

**신원 문서의 위치**

| surface | 문서 URL | 비고 |
|---|---|---|
| `mcp` | **`B` 자체** | CIMD 규격: Client Identifier URL이 곧 메타데이터 문서의 URL이며, 문서의 `client_id`는 그 URL과 같아야 한다 |
| `a2a` (경로 형식) | `B/agent-card.json` | **AAID 관례.** A2A의 오리진 단위 well-known(`https://host/.well-known/agent-card.json`)을 재정의하지 않는다 |
| `a2a` (루트 형식, `host`만) | `https://host/.well-known/agent-card.json` | 이 경우 `B`가 오리진이므로 A2A 표준 discovery 위치와 일치한다 |

동일한 기준 URL `B`로부터 생성된 `a2a` DID와 `mcp` DID는 **동일한 에이전트 subject를 식별한다.** 각 DID Document는 다른 surface의 DID를 `alsoKnownAs`로 표현한다(§2.2).

> `mcp` surface는 `B` 자체가 문서라서, 루트 형식(`did:aaid:mcp:host`)은 사이트 루트가 CIMD를 반환해야 한다. 실무에서는 경로 형식을 권장한다(SHOULD).

## 2. 연산

### 2.0 권한

모든 연산의 권한은 기준 URL의 HTTPS 오리진을 통제하는 것으로 결정된다. 문서를 그 URL에 게시할 수 있는 자가 DID 컨트롤러다. DID Document 자체는 권한 판단에 쓰지 않는다.

### 2.1 생성 (Create)

컨트롤러는 신원 키(JWK, `kid` 필수)를 정하고, 선택한 surface의 문서를 아래 프로파일에 맞춰 게시한다. 제3자 등록은 없다.

**`a2a` - Agent Card** ([A2A 스펙](https://a2a-protocol.org/latest/specification/) `AgentCard`).
A2A는 Agent Card의 디지털 서명(`signatures[]`, JCS 정규화 + JWS)을 **선택(MAY)**으로 정의한다. `did:aaid:a2a`는 이를 필수로 올리고, 신원 키 선언 위치를 추가로 정한다:
1. `capabilities.extensions`에 확장 `{"uri":"https://github.com/shlee1223/did-method-aaid#ext-v1","params":{…}}`를 두고, `params`에 `jwks_uri` 또는 `jwks`(인라인) 중 하나를 넣는다(MUST). **AAID는 `jwks_uri`가 `B`와 같은 HTTPS 오리진일 것을 추가로 요구한다(MUST).**
2. `signatures[]`에 최소 하나의 서명을 둔다(MUST). `protected` 헤더의 `kid`는 1의 JWK Set에 있어야 하고, 서명은 A2A가 정한 정규화·JWS 절차대로 그 키로 검증되어야 한다(MUST). 즉 카드는 신원 키로 서명된다.

**`mcp` - CIMD** ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)).
1. 문서는 `B`에서 제공되고, `client_id`는 `B`와 같다(MUST; CIMD 규격).
2. `jwks` 또는 `jwks_uri`로 신원 키를 선언한다(MUST; CIMD가 허용하는 방식). **CIMD는 `jwks_uri`의 오리진을 제한하지 않지만, AAID는 `jwks_uri`가 `B`와 같은 HTTPS 오리진일 것을 추가로 요구한다(MUST).**

두 문서를 모두 게시하는 에이전트는 같은 `jwks_uri`를 가리키는 것이 권장된다(SHOULD).

### 2.2 조회 (Resolve)

1. DID를 파싱한다. ABNF 위반이면 `invalidDid`.
2. **신원 문서 fetch.** `surface`가 가리키는 문서 URL(§1)에 `GET`(`Accept: application/json`, HTTPS만, 오리진이 바뀌는 리다이렉트는 거부)한다.
   - `200` → 프로파일 검증 후 키 추출. 위반이면 `invalidSurface` → `notFound`.
   - `410` → `deactivated: true`로 반환하고 종료.
   - `404`·그 외 → `notFound`.
3. **키 추출.** `a2a`는 확장의 JWK Set(이후 카드 서명 검증 필수), `mcp`는 `jwks`/`jwks_uri`. `jwks_uri`는 `B`와 동일 오리진이어야 한다(MUST, AAID 제약). 비밀 파라미터가 섞여 있으면 버린다(MUST).
4. **반대 surface 탐색(probe).** 같은 `B`의 다른 surface 문서 URL을 `GET`한다. 응답이 `200`이고 `Content-Type`이 JSON이며 파싱 가능하면 그 surface가 존재하는 것으로 본다. 키는 읽지 않고 프로파일 검증도 하지 않는다. 탐색 실패(404·오류·타임아웃)는 조회를 실패시키지 않는다(MUST NOT).
5. **DID Document 구성.**
   - `id` = 요청한 DID.
   - `verificationMethod` = 3의 키마다 `{ id: <DID>#<kid>, type: "JsonWebKey2020", controller: <DID>, publicKeyJwk }`.
   - `authentication`, `assertionMethod` = 모든 키.
   - `service` = 신원 문서 `{ id: <DID>#a2a | #mcp, type: "A2AAgentCard" | "OAuthClientMetadata", serviceEndpoint: <URL> }`. 4에서 반대 surface가 존재하면 그 문서도 추가한다.
   - `alsoKnownAs` = 4에서 반대 surface가 존재하면 그 surface의 DID(`did:aaid:<다른 surface>:<같은 host:segments>`)를 넣는다(MUST). `mcp`이면 CIMD `client_id`(= `B`)도 넣는다(SHOULD).
6. `didResolutionMetadata.surfaces`에 `{ <surface>: "found", <other>: "found" | "absent" }`를 담아 반환한다.

**응답 진본성.** 리졸버는 TLS로 오리진을 검증하고(2단계), `a2a`는 추가로 신원 키 서명을 검증한다(3단계). `mcp`는 TLS 외 서명이 없다. 반대 surface 탐색(4단계)은 결속 표시만을 위한 것이며 키 근거가 아니다.

### 2.3 갱신 (Update)

문서를 같은 URL에 다시 게시하면 갱신이다. 키 로테이션: JWK Set에 새 키 추가 → (`a2a`) Agent Card를 새 키로 재서명 → 겹침 기간 뒤 옛 키 제거. 옛 키를 즉시 제거하면 캐시된 서명이 검증되지 않으므로 겹침 기간을 두는 것이 권장된다(SHOULD).

### 2.4 비활성화 (Deactivate)

문서를 제거하고 해당 URL이 `410 Gone`을 반환하게 한다. 신원 문서가 `410`이면 그 DID는 비활성이다. 반대 surface의 상태는 이 DID의 활성 여부에 영향을 주지 않는다.

## 3. 보안 고려사항

RFC 3552를 따른다. 보호 범위: TLS가 모든 문서의 전송(기밀성·무결성·서버 인증)을 보호한다. Agent Card는 추가로 신원 키 JWS로 무결성과 출처가 보호된다. CIMD와 JWK Set은 TLS 외 보호가 없다. 비밀 자료(개인키)는 이 메서드가 다루지 않으며 어떤 문서에도 실리지 않아야 한다(MUST NOT).

| 공격 | 해당 연산 | 대응 |
|---|---|---|
| 도청 | 조회 | 문서는 공개 정보다. TLS가 경로를 보호한다 |
| 재전송 | 조회 | 문서에 nonce가 없어 재전송 자체는 무해하다. 옛 문서 재전송(롤백)은 캐시 만료 규칙과 `410`으로 제한된다 |
| 삽입·삭제·변조 | 생성·갱신·비활성 | 오리진 통제 = 권한. 오리진 침해 시 공격자가 키를 게시할 수 있다(잔여 위험). Agent Card 변조는 서명 검증에서 드러난다 |
| 서비스 거부 | 조회 | 조회당 문서 fetch 최대 2건(신원 문서 + 반대 surface 탐색) + JWK Set 최대 1건. 리졸버는 크기·시간 제한을 두어야 한다(SHOULD). 오리진이 다운되면 조회가 실패한다 |
| 증폭 | 조회 | 리졸버는 호출자당 고정 횟수만 fetch한다. 증폭 요소는 없다 |
| 중간자 | 조회 | TLS 서버 인증. `http` 금지, 오리진 변경 리다이렉트 거부, `jwks_uri` 동일 오리진 강제(AAID 제약) |

**잔여 위험.** (1) DNS·인증서·웹 호스트 침해 - 이 메서드는 원장형의 변조 증거를 제공하지 않으며, 오리진 보안이 곧 DID 보안이다. (2) `alsoKnownAs`는 동일한 기준 URL `B`에 의해 두 DID가 동일한 에이전트 subject를 식별한다는 AAID의 관계를 표현한다. 이는 두 surface에서 쓰이는 키가 동일하거나 상호 인증되었음을 의미하지 않는다. 반대 surface의 키를 신뢰하려면 그 DID를 별도로 조회해야 한다. (3) 폐기 지연 - 키 제거·비활성은 재조회 시에만 관찰된다(캐시는 문서의 `max-age` 이하, 최대 24시간). 즉시 폐기가 필요하면 자격증명 수준 상태 목록(예: Bitstring Status List)을 함께 쓴다(SHOULD). (4) 리졸버 구현 오류(서명 검증 생략, 오리진 검사 누락)는 위 보호를 무효화한다.

**무결성·갱신 인증.** 갱신과 비활성은 오리진에 대한 쓰기 권한으로 인증된다. 조회 결과의 무결성은 TLS(전 문서)와 신원 키 서명(Agent Card)으로 보장된다.

**엔드포인트 인증.** 문서 URL의 인증은 TLS 서버 인증이다. 리졸버는 인증서를 검증해야 한다(MUST).

**유일성.** DID는 surface·DNS 호스트·경로로 유일성이 정해진다. 같은 호스트·경로를 두 주체가 통제할 수 없으므로 DID는 유일하게 배정된다.

## 4. 프라이버시 고려사항

RFC 6973 §5 기준.

- **감시·상관관계(correlation)·식별:** DID가 호스트와 경로를 드러내고, 조회는 오리진에 접근 로그(리졸버 IP·시각)를 남긴다. 반대 surface 탐색은 접근 로그를 한 건 더 남긴다. 에이전트 신원은 공개가 목적이므로 이는 설계상 의도다. 상관관계를 피해야 하는 주체는 이 메서드를 쓰지 않아야 한다.
- **저장 데이터 침해:** 문서는 공개키만 담는다. 개인키는 오리진의 별도 보호 대상이다.
- **원치 않는 트래픽:** 리졸버가 오리진에 요청을 보낸다. 리졸버는 캐시로 반복 요청을 줄여야 한다(SHOULD).
- **오귀속(misattribution):** 오리진 침해 시 타인의 행위가 에이전트에게 귀속될 수 있다(§3).
- **2차 이용·공개(disclosure):** Agent Card와 CIMD는 공개 문서다. 인간 주체의 개인정보를 넣지 않아야 한다(SHOULD NOT).
- **배제(exclusion):** DID 주체는 자기 문서를 직접 게시하므로 제3자에 의해 배제되지 않는다. 다만 DNS·호스팅 사업자에 의존한다.

## 5. 예시

`did:aaid:mcp:example.com:agents:billing` 조회. 신원 문서는 `B` 자체(CIMD)이고, 같은 `B`에 Agent Card도 존재한다.

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

`GET https://example.com/agents/billing/agent-card.json` → `200`, JSON (탐색만, 키는 읽지 않음)

조회 결과
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

`did:aaid:a2a:example.com:agents:billing`를 조회하면 대칭적으로 `B/agent-card.json`에서 키를 읽고(서명 검증 포함) `B`(CIMD)를 탐색하여 `alsoKnownAs`에 `did:aaid:mcp:…`를 넣는다.

## 참고문헌

DID Core 1.0 · A2A Protocol Specification(`a2a.proto`, Agent Card signature: JCS + JWS) · draft-ietf-oauth-client-id-metadata-document-02 · RFC 7515 · RFC 7517 · RFC 3552 · RFC 6973 · RFC 2119 / 8174

---
변경 이력 - v1.0: `alsoKnownAs`가 "동일한 에이전트 subject를 식별하는 관계"임을 §1에 명시하고, §3에서 이것이 키 동일성을 뜻하지 않음을 구분. 최초 안정판. v0.4: (①) `mcp` 문서 URL을 `B` 자체로 정정(CIMD 규격), (②) A2A well-known을 재정의하지 않음을 명시하고 경로 형식은 AAID 관례로 분리, (③) A2A 서명은 선택(MAY)이며 AAID가 MUST로 올린다고 서술 정정, (④) `jwks_uri` 동일 오리진은 CIMD가 아니라 AAID의 추가 제약임을 명시. v0.3: 기본형 제거, `surface` 필수화, 반대 surface 탐색으로 결속. v0.2: 문서를 두 가지로 한정. v0.1: 최초 초안.
