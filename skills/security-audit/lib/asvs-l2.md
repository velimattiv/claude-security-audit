# OWASP ASVS 5.0 Level 2 — Checklist Reference

Companion to `steps/phase-06-config.md §6.9`. One sub-agent per top-level
category walks its sub-items and emits JSONL status rows.

**License / attribution.** The ASVS standard is published by OWASP under
CC-BY-SA-4.0. This file restates the L2 category topics for the sub-agent
prompt; the canonical IDs and text live at
`https://github.com/OWASP/ASVS`. Phase 7 synthesis links back to the
OWASP source in the report footer.

The categories below use ASVS 5.0 numbering. If the OWASP project
re-numbers, update this file in lockstep — coverage tracking depends on
ID stability.

## Categories (17 top-level)

### V1 — Architecture, Design & Threat Modeling
Primarily for design review; few grep-detectable items. Sub-agent scans
for `threat-model`/`THREAT`/`architecture` docs and tags their presence.

### V2 — Authentication
- V2.1 Password Security
- V2.2 General Authenticator
- V2.3 Authenticator Lifecycle
- V2.4 Credential Storage
- V2.5 Credential Recovery
- V2.6 Look-up Secret Verifier
- V2.7 Out of Band Verifier
- V2.8 Single or Multi-Factor One-Time Verifier
- V2.9 Cryptographic Software
- V2.10 Service Authentication
- V2.11 Storage of Secrets

Sub-agent reads `profile.auth.*` + cat-01 findings; maps to V2.*.

### V3 — Session Management
- V3.1 Fundamental Session Management
- V3.2 Session Binding
- V3.3 Session Logout and Timeout
- V3.4 Cookie-based Session Management
- V3.5 Token-based Session Management
- V3.6 Federated Re-authentication
- V3.7 Defenses against Session Management Exploits

Maps to cat-01 session-regeneration + §6.3 cookie-security findings.

### V4 — Access Control
- V4.1 General Access Control Design
- V4.2 Operation Level Access Control
- V4.3 Other Access Control Considerations

Maps to cat-02 (IDOR) + cat-01 (role checks).

### V5 — Validation, Sanitization & Encoding
- V5.1 Input Validation
- V5.2 Sanitization and Sandboxing
- V5.3 Output Encoding and Injection Prevention
- V5.4 Memory, String, and Unmanaged Code
- V5.5 Deserialization Prevention

Maps to cat-08 (Injection/SSRF/Deserialization).

### V6 — Stored Cryptography
- V6.1 Data Classification
- V6.2 Algorithms
- V6.3 Random Values
- V6.4 Secret Management

Maps to cat-05 (Crypto) + cat-06 (Secret sprawl).

### V7 — Error Handling & Logging
- V7.1 Log Content
- V7.2 Log Processing
- V7.3 Log Protection
- V7.4 Error Handling

Maps to §6.4 error-handling audit.

### V8 — Data Protection
- V8.1 General Data Protection
- V8.2 Client-side Data Protection
- V8.3 Sensitive Private Data

Maps to `profile.pii.*` + LINDDUN (§6.12).

### V9 — Communications
- V9.1 Communications Security
- V9.2 Server Communications Security

Maps to cat-04 (MITM/Transport).

### V10 — Malicious Code
- V10.1 Code Integrity
- V10.2 Malicious Code Search
- V10.3 Deployed Application Integrity

Maps to §6.8 CI config + cat-07 deployment; usually mostly manual.

### V11 — Business Logic
Scanner-unfriendly category; sub-agent flags surfaces with money /
quota / rate-limit logic for manual review.

### V12 — Files and Resources
- V12.1 File Upload
- V12.2 File Integrity
- V12.3 File Execution
- V12.4 File Storage
- V12.5 File Download

Maps to cat-08 file-upload + §6.4 file-serving.

### V13 — API and Web Service
- V13.1 Generic Web Service
- V13.2 RESTful Web Service
- V13.3 SOAP Web Service
- V13.4 GraphQL and other Web Service Data Layer Security

Maps to entire Phase 2 surface inventory.

### V14 — Configuration
- V14.1 Build and Deploy
- V14.2 Dependency
- V14.3 Unintended Security Disclosure
- V14.4 HTTP Security Headers
- V14.5 Validation of HTTP Request

Maps to §6.1 CORS, §6.2 headers, §6.8 CI, cat-07 deployment.

### V15-V17
Reserved / lower priority for automated audit. Sub-agent lists any
relevant files discovered but rarely produces findings.

## Sub-agent invocation (per category)

Invoke one sub-agent per V* category (above). Each:
- Reads the category's mapping targets (pointed to by this file).
- Walks the relevant files applying the ASVS L2 sub-item questions.
- Emits JSONL rows into `phase-06-asvs.jsonl`:
  ```json
  {"asvs_id":"V2.4.1","status":"PASS","file":"lib/auth/hash.ts","line":14,"message":"Argon2id 19MiB, 2 iterations — meets 2026 OWASP baseline","severity":"INFO"}
  ```
  Valid `status` values: `PASS | FAIL | N/A | MANUAL_REVIEW`.

Concurrency cap: same 8-agent cap as Phase 5. Some categories (V11
Business Logic) are nearly always MANUAL_REVIEW; don't fan out those.
