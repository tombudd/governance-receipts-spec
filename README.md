# Governance Receipts Specification

> An open specification for cryptographically verifiable AI decision receipts — making AI actions auditable, non-repudiable, and independently verifiable.

[![Spec Version](https://img.shields.io/badge/Spec-v0.3.0-blue)]()
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-blue.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Status: Draft RFC](https://img.shields.io/badge/Status-Draft%20RFC-orange)]()

---

## The Problem

AI systems make consequential decisions. We have no standard way to:

- Prove that a specific decision was made at a specific time
- Verify that the decision was made by the stated system
- Reconstruct the reasoning without access to the original system
- Detect if a logged decision was tampered with after the fact

Server logs are mutable. Prompts can be changed. Models can be updated. Without an external, verifiable receipt, accountability claims are unverifiable.

The Governance Receipt Specification (GRS) defines a lightweight, system-agnostic format for AI decision receipts that addresses all four problems.

---

## What Is a Governance Receipt?

A Governance Receipt is a signed, timestamped record of an AI decision that:

1. **Identifies** the decision uniquely (UUID + timestamp)
2. **Hashes** the inputs and outputs (SHA-256, non-reversible)
3. **Summarises** the reasoning (human-readable, not model weights)
4. **Records** which constraints were checked and their results
5. **Signs** the whole payload (HMAC-SHA256 or asymmetric)
6. **Stores** in an append-only chain (each receipt references the previous)

---

## Specification

### Receipt Schema (v0.3.0)

```json
{
  "$schema": "https://governance-receipts.io/schema/v0.3.0",
  "receipt": {
    "id": "uuid-v4",
    "version": "0.3.0",
    "timestamp": "ISO8601-UTC",
    "system_id": "string (identifies the AI system, not the model weights)",
    "session_id": "uuid-v4 (links receipts within a session)",
    "chain_prev": "sha256 of previous receipt | null if first",

    "inputs": {
      "hash": "sha256(canonical_json(inputs))",
      "type": "string (e.g. 'user_message', 'api_call', 'sensor_reading')",
      "redacted": "boolean (true if inputs contain PII and were not hashed verbatim)"
    },

    "outputs": {
      "hash": "sha256(canonical_json(outputs))",
      "type": "string",
      "confidence": "float 0.0-1.0"
    },

    "reasoning": {
      "summary": "string (max 500 chars, human-readable)",
      "method": "string (e.g. 'chain-of-thought', 'tool-call', 'retrieval')"
    },

    "governance": {
      "constraints_checked": [
        {
          "constraint_id": "string",
          "description": "string",
          "result": "PASS | FAIL | SKIP | WARN",
          "detail": "string | null"
        }
      ],
      "override_applied": "boolean",
      "override_reason": "string | null",
      "human_reviewed": "boolean"
    },

    "signature": {
      "algorithm": "HMAC-SHA256 | ED25519",
      "key_id": "string (identifies signing key, not the key itself)",
      "value": "hex-encoded signature over canonical_json(receipt minus signature)"
    }
  }
}
```

### Canonical JSON

For consistent hashing, inputs and outputs are serialised using RFC 8785 (JSON Canonicalization Scheme) before hashing. This ensures identical content produces identical hashes regardless of key ordering or whitespace.

### Receipt Chain

Each receipt includes `chain_prev` — the SHA-256 hash of the previous receipt in the session. This creates a tamper-evident chain: altering any receipt invalidates all subsequent receipts.

```
Receipt_1 (chain_prev: null)
    │ sha256
    ▼
Receipt_2 (chain_prev: hash_of_1)
    │ sha256
    ▼
Receipt_3 (chain_prev: hash_of_2)
    ...
```

---

## Reference Implementation

A reference implementation in Python is provided in [`src/`](src/).

### Generate a receipt

```python
from grs import ReceiptGenerator, ConstraintResult

generator = ReceiptGenerator(system_id="my-ai-system", signing_key=key)

receipt = generator.generate(
    inputs={"user_message": "What is the capital of France?"},
    outputs={"response": "Paris."},
    reasoning_summary="Factual retrieval from training knowledge. No governance flags.",
    constraints=[
        ConstraintResult("no-harm", "PASS"),
        ConstraintResult("no-deception", "PASS"),
        ConstraintResult("stays-in-scope", "PASS"),
    ],
    confidence=0.99,
)
```

### Verify a receipt

```python
from grs import ReceiptVerifier

verifier = ReceiptVerifier(public_key=public_key)
result = verifier.verify(receipt)

print(result.valid)          # True
print(result.chain_intact)   # True
print(result.constraints)    # All PASS
```

### Audit a session

```python
from grs import SessionAuditor

auditor = SessionAuditor()
report = auditor.audit_session(receipts=session_receipts)

print(report.chain_valid)       # True — no tampering detected
print(report.constraint_fails)  # [] — no violations
print(report.coverage)          # 1.0 — all decisions receipted
```

---

## Storage Backends

The spec is storage-agnostic. Reference adapters are provided for:

- **Local file** (append-only JSONL) — for development
- **PostgreSQL** (append-only table with trigger enforcement)
- **S3/GCS** (object storage with versioning)
- **IPFS** (content-addressed, tamper-evident by design)

---

## Design Decisions

**Why SHA-256 hashes rather than storing full inputs?**
Privacy. Storing full inputs may include PII, confidential data, or information the user didn't intend to retain. Hashes allow verification without retention.

**Why HMAC rather than public-key signatures by default?**
Simplicity and speed. HMAC is sufficient when the verifier trusts the key holder. For multi-party accountability (where the system itself might be adversarial), ED25519 is recommended.

**Why a chain rather than independent receipts?**
A chain makes it impossible to delete receipts without detection. An attacker cannot silently remove a record from the middle of a chain.

**Why 500-char reasoning summaries?**
Long enough to be meaningful, short enough to be human-readable. The goal is auditability by humans, not full reconstruction of model internals.

---

## Relation to Existing Standards

| Standard | Relation |
|----------|----------|
| W3C Verifiable Credentials | Compatible — GRS receipts can be wrapped as VCs |
| OpenTelemetry | Complementary — OTel covers system traces, GRS covers decision accountability |
| NIST AI RMF | GRS implements the "GOVERN" and "MANAGE" function requirements |
| EU AI Act (Article 13) | GRS addresses transparency and traceability requirements |

---

## Status

This is a draft RFC. Feedback welcome via GitHub Issues.

**v0.3.0 changes:** Added `chain_prev`, `session_id`, and multi-algorithm signature support.

---

© 2025–2026 Tom Budd / ResoVerse Technologies · CC BY 4.0
