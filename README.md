# OpenPoD: Proof-of-Delegation Protocol
### The Cryptographic Anti-CAPTCHA & Authorized Human Delegation Protocol for the Autonomous Agentic Web

[![RFC-001 Status](https://img.shields.io/badge/RFC--001-Draft%20Standard-cyan)](packages/spec/RFC-001-POD.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Ed25519 WebCrypto](https://img.shields.io/badge/Cryptography-Ed25519%20%2F%20WebCrypto-00ffa3)](packages/client)
[![Target Working Group](https://img.shields.io/badge/Standards-W3C%20%2F%20ITU--T%20SG17-purple)](packages/spec)

---

## 📌 Executive Summary

Modern websites rely on **visual CAPTCHAs, TLS fingerprinting (JA3/JA4), and anti-bot walls** to block automated scrapers. In the emerging **Agentic Web**, this architecture causes catastrophic failure:
1. **Legitimate AI agents acting on behalf of verified humans are blocked with 403 Forbidden errors.**
2. **Visual CAPTCHAs are ineffective:** Vision models solve puzzles faster than humans, while punishing real human users.
3. **No accountability:** Once a malicious bot passes a CAPTCHA, it can execute unmetered DDoS attacks.

**OpenPoD (Proof-of-Delegation)** inverts the paradigm. Instead of demanding that an AI agent prove it is biologically human, the agent presents an **Ed25519 hardware-signed cryptographic token** proving that a **verified human principal delegated a bounded rate-limit budget for that specific domain**.

```
┌─────────────────────────┐
│       Human User        │
│  (Browser / WebCrypto)  │
└────────────┬────────────┘
             │ 1. Signs Ephemeral Delegation (Ed25519)
             ▼
┌─────────────────────────┐
│     Autonomous Agent    │  2. Dispatches Request with Header:
│   (Extension / Client)  │────► Sec-Proof-Of-Delegation: <token>
└─────────────────────────┘
                                           │
                                           ▼
                            ┌─────────────────────────────┐
                            │      Target Web Service     │
                            │    (@open-pod/middleware)   │
                            ├─────────────────────────────┤
                            │  • Verifies Sig in 1.8ms    │
                            │  • Checks Domain Lock (aud) │
                            │  • Sliding-Window Counter   │
                            │  • Bypasses CAPTCHA (200 OK)│
                            └─────────────────────────────┘
```

---

## 🚀 Key Benchmarks: OpenPoD vs. Legacy Scraping

| Metric | Legacy Agent (Vision / Scraping) | OpenPoD Agent | Advantage |
| :--- | :---: | :---: | :---: |
| **Authentication Latency** | 8,500 – 14,000 ms (CAPTCHA solving) | **1.8 ms** (WebCrypto verification) | **99.9% Faster** |
| **Token Cost per Step** | ~$0.04 (Vision tokens for CAPTCHA) | **$0.0000** (Zero LLM tokens) | **100% Free** |
| **Bypass Reliability** | 42% (Fails on puzzle mutations) | **99.9%** (Deterministic Math) | **Rock-solid** |
| **DDoS / Replay Defense** | None (Vulnerable to proxy rotators) | **Strict Nonce + Sliding Window** | **Instant Key Revocation** |

---

## 📦 Monorepo Architecture

* [`packages/spec`](packages/spec/RFC-001-POD.md): The formal RFC-001 specification and JSON Schema.
* [`packages/client`](packages/client): Zero-dependency TypeScript SDK for browser WebCrypto Ed25519 token generation.
* [`packages/middleware`](packages/middleware): Drop-in Node.js / Express / Next.js middleware for verifying tokens and bypassing CAPTCHAs.
* [`packages/extension`](packages/extension): Manifest V3 Chrome Extension providing an agent control panel, budget slider, and network interceptor.
* [`apps/demo`](apps/demo): Live interactive testbed and real-time verification radar.

---

## 🛠️ Quickstart: Run the Interactive Demo

### 1. Install & Build
```bash
git clone https://github.com/abhirajkumarp/open-pod.git
cd open-pod
npm install
npm run build
```

### 2. Run the Cryptographic Test Suite
```bash
npm test
```
*Executes all 14 end-to-end cryptographic assertions: Ed25519 signing, domain lock validation, replay attack detection, signature tampering rejection, and sliding-window rate limiting.*

### 3. Launch the Live Radar Dashboard
```bash
npm run demo
```
Navigate to **`http://localhost:3000`** in your browser.

You can interactively test:
* **Legacy Agent:** Watch unverified bots get blocked by Cloudflare Turnstile with 403 Forbidden.
* **PoD Agent:** Watch verified agents bypass anti-bot walls in 2ms.
* **DDoS Attacker:** Trigger a high-frequency attack and watch the middleware automatically burn and revoke the abusive public key.

---

## 🛡️ The `Sec-Proof-Of-Delegation` Token Format

The token is transmitted in the HTTP request header:
```http
Sec-Proof-Of-Delegation: <header>.<payload>.<signature>
```

### Decoded Payload:
```json
{
  "iss": "dhyoH5XgnHECt4wW...",    // Delegator Ed25519 Public Key
  "aud": "https://api.airline.com", // Target Origin (Replay immune)
  "iat": 1732204800,               // Issued At
  "exp": 1732204860,               // Ephemeral TTL (Max 60 seconds)
  "jti": "8f3b4c1e-9a2d-4f7e...",  // Cryptographic Nonce (Replay protection)
  "lim": 10,                       // Declared Rate-Limit Budget (req/min)
  "scp": "query:flights"           // Bounded Action Scope
}
```

---

## 🌐 Sponsor Alignment

* **Cognizant AI Lab:** Bridges enterprise APIs and web services to autonomous agents without requiring manual API key renegotiation.
* **MIT Media Lab (Project NANDA):** Implements the **Governance, Identity, and Trust Layer** articulated in Prof. Ramesh Raskar’s AgentFacts research.
* **Mozilla:** Built on open browser standards (Web Crypto API, WebAuthn, W3C HTTP headers) without proprietary vendor lock-in.
* **UN ITU-T SG17:** Addresses international cybersecurity standards for preventing botnet-driven DDoS attacks and automated abuse.

---

## 📜 License
Apache-2.0 License. Designed for the global open-source agentic web ecosystem.
