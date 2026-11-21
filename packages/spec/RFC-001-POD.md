# RFC-001: Proof-of-Delegation (PoD) Protocol
## A Cryptographic Handshake for Authorized Autonomous Web Agents

* **Status:** Proposed Standard / Draft
* **Author:** Abhiraj Kumar P
* **Target Working Group:** Agentic Web Architecture / W3C WebAppSec / UN ITU-T SG17
* **Date:** November 2026

---

### Abstract
This specification defines the **Proof-of-Delegation (PoD)** protocol, a client-side cryptographic standard allowing autonomous software agents to present verifiable proof of human authorization when interacting with web services. By utilizing hardware-attested asymmetric keypairs (Ed25519 / WebAuthn), ephemeral scoped tokens, and deterministic cryptographic rate-limiting, PoD provides an open alternative to traditional CAPTCHAs and heuristic bot detection systems without compromising user privacy or service availability.

---

### 1. Introduction & Motivation

#### 1.1 The Failure of Legacy Bot Mitigation
Modern web defense architectures rely heavily on Turing challenges (CAPTCHAs), TLS fingerprinting (JA3/JA4), and behavioral telemetry to distinguish human users from automated scripts. While effective against primitive scrapers, this paradigm introduces three critical failure modes in the emerging Agentic Web:

1. **Accessibility and Agent Paralysis:** Legitimate autonomous agents acting on behalf of paying human users cannot solve visual CAPTCHAs deterministically without incurring high latency, token cost, or outright failure.
2. **Asymmetric Verification Efficacy:** Advancements in multi-modal vision models enable malicious bots to solve graphical CAPTCHAs faster and more accurately than human operators.
3. **Absence of Accountability:** Once an IP or session bypasses a legacy challenge, it retains unmetered access until re-challenged, enabling botnets to execute distributed denial-of-service (DDoS) or high-volume data harvesting.

#### 1.2 The Proof-of-Delegation Paradigm
PoD inverts the paradigm: instead of demanding that an agent prove it is biologically human at the moment of request dispatch, the agent presents a mathematically verifiable token demonstrating that a **verified human principal cryptographically delegated a bounded action budget to that agent**.

```
┌──────────────┐         1. Sign Delegation (Ed25519)         ┌──────────────┐
│ Human User   │─────────────────────────────────────────────►│ Agent Client │
└──────────────┘                                              └──────┬───────┘
                                                                     │
                                    2. HTTP Request with Header      │
                                       Sec-Proof-Of-Delegation       │
                                                                     ▼
                                                              ┌──────────────┐
                                                              │ Web Service  │
                                                              │ (PoD Guard)  │
                                                              └──────────────┘
```

---

### 2. The `Sec-Proof-Of-Delegation` HTTP Header

Clients MUST transmit delegation proofs via the standard HTTP request header:

```http
Sec-Proof-Of-Delegation: <base64url-header>.<base64url-payload>.<base64url-signature>
```

The token uses a three-part compact serialization formatted as follows:

#### 2.1 JOSE Header
```json
{
  "alg": "EdDSA",
  "crv": "Ed25519",
  "typ": "PoD+jwt"
}
```

#### 2.2 Payload Claims
| Claim | Type | Description | Mandatory |
| :--- | :--- | :--- | :--- |
| `iss` | `string` | Base64URL-encoded public key of the delegator (Issuer). | Yes |
| `aud` | `string` | The fully qualified target origin (e.g., `https://api.airline.com`). | Yes |
| `iat` | `integer` | UNIX timestamp (seconds) when the token was created. | Yes |
| `exp` | `integer` | UNIX timestamp when the token expires (MUST NOT exceed `iat + 60s`). | Yes |
| `jti` | `string` | Cryptographically random UUID/nonce to prevent replay attacks. | Yes |
| `lim` | `integer` | Declared maximum requests allowed per minute for this key (e.g., `10`). | Yes |
| `scp` | `string` | Bounded action scope (e.g., `query:flights` or `read:catalog`). | Yes |

#### 2.3 Cryptographic Signature
The signature MUST be computed using Ed25519 over the UTF-8 ASCII representation of `base64url(header) + "." + base64url(payload)`.

---

### 3. Server-Side Verification Algorithm

When a web server or reverse proxy receives an HTTP request containing `Sec-Proof-Of-Delegation`, the verification pipeline executes the following checks in constant time:

1. **Structural Validation:** Ensure the token contains exactly three dot-separated base64url segments. Parse header and verify `alg == "EdDSA"`.
2. **Domain Matching (`aud`):** Verify that the `aud` claim matches the server's current host and origin. If mismatched, reject with `401 Unauthorized (Audience Mismatch)`.
3. **Temporal Validity (`iat` & `exp`):**
   * Reject if `now < iat - 5` (clock skew tolerance: 5 seconds).
   * Reject if `now > exp`. Tokens MUST NOT have a lifetime exceeding 60 seconds.
4. **Replay Protection (`jti`):**
   * Check the local ephemeral Bloom filter or memory cache for `jti`.
   * If `jti` exists within the validity window: Reject with `409 Conflict (Replay Detected)`.
   * Insert `jti` with TTL equal to `exp - now`.
5. **Cryptographic Integrity:**
   * Extract public key from `iss`.
   * Verify Ed25519 signature over `header.payload`.
   * If signature is invalid: Reject with `403 Forbidden (Signature Invalid)`.
6. **Sliding-Window Rate Verification (`lim`):**
   * Increment request counter for `iss` in a 60-second sliding window.
   * If counter exceeds the minimum of (`lim`, `server_max_limit`):
     * Return `429 Too Many Requests`.
     * Flag key for revocation if abuse exceeds 200% of threshold.
7. **Bypass Decision:**
   * If all checks pass: Bypass CAPTCHA challenge and proceed to request handler with `req.podVerified = true`.

---

### 4. Threat Model & Security Considerations

#### 4.1 Sybil Attacks (Infinite Key Generation)
* **Risk:** An adversary writes a loop generating 1,000,000 Ed25519 keypairs, obtaining 10 requests per key to execute a DDoS attack.
* **Mitigation:** PoD supports **Hardware Attestation (FIDO2 / WebAuthn)** and **Proof-of-Work (Hashcash) Dynamic Escalation**. When a server experiences abnormal key churn, it issues a 402/428 computational challenge requiring a 20ms SHA-256 pre-image calculation, raising the computational cost of mass key rotation to economically unviable levels.

#### 4.2 Token Interception & Replay
* **Risk:** A man-in-the-middle captures an in-flight PoD token and replays it.
* **Mitigation:** Tokens are strictly bound to HTTPS TLS channels, locked to a single `aud` origin, enforced with an ephemeral 60-second lifespan, and uniquely identified via a single-use `jti` nonce.

#### 4.3 Scope Escalation
* **Risk:** A token signed for read access is reused to invoke write/transaction endpoints.
* **Mitigation:** The server enforces scope binding. An endpoint requiring `write:orders` rejects tokens declaring `read:catalog`.

---

### 5. Reference Implementation Status
* **Client SDK:** `@open-pod/client` (Browser WebCrypto & Node.js)
* **Server Middleware:** `@open-pod/middleware` (Express, Fastify, Next.js, Cloudflare Workers)
* **User Agent Extension:** `OpenPoD Chrome Extension (Manifest V3)`
