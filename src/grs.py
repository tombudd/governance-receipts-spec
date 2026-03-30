"""
Governance Receipts Specification — Reference Implementation
============================================================
Python reference implementation of GRS v0.3.0.

Usage:
    from grs import ReceiptGenerator, ReceiptVerifier, ConstraintResult

    generator = ReceiptGenerator(system_id="my-system", signing_key=os.environ.get("GRS_SIGNING_KEY", b"example-only-do-not-use"))
    receipt = generator.generate(
        inputs={"query": "..."},
        outputs={"response": "..."},
        reasoning_summary="...",
        constraints=[ConstraintResult("no-harm", "PASS")],
        confidence=0.95,
    )
"""

import hashlib
import hmac
import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Literal


# ─── Data Classes ─────────────────────────────────────────────────────────────

ConstraintStatus = Literal["PASS", "FAIL", "SKIP", "WARN"]


@dataclass
class ConstraintResult:
    constraint_id: str
    result: ConstraintStatus
    description: str = ""
    detail: Optional[str] = None


@dataclass
class GovernanceReceipt:
    """A single governance receipt — v0.3.0."""

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: str = "0.3.0"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    system_id: str = ""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    chain_prev: Optional[str] = None  # SHA-256 of previous receipt, or None

    # Inputs
    inputs_hash: str = ""
    inputs_type: str = "user_message"
    inputs_redacted: bool = False

    # Outputs
    outputs_hash: str = ""
    outputs_type: str = "response"
    confidence: float = 0.0

    # Reasoning
    reasoning_summary: str = ""
    reasoning_method: str = "chain-of-thought"

    # Governance
    constraints: List[ConstraintResult] = field(default_factory=list)
    override_applied: bool = False
    override_reason: Optional[str] = None
    human_reviewed: bool = False

    # Signature
    signature_algorithm: str = "HMAC-SHA256"
    signature_key_id: str = ""
    signature_value: str = ""

    def has_violations(self) -> bool:
        return any(c.result == "FAIL" for c in self.constraints)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def signing_payload(self) -> str:
        """Canonical payload for signing — excludes signature fields."""
        payload = {
            "id": self.id,
            "version": self.version,
            "timestamp": self.timestamp,
            "system_id": self.system_id,
            "session_id": self.session_id,
            "chain_prev": self.chain_prev,
            "inputs_hash": self.inputs_hash,
            "outputs_hash": self.outputs_hash,
            "confidence": self.confidence,
            "reasoning_summary": self.reasoning_summary,
        }
        # RFC 8785-style: sorted keys, no extra whitespace
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


# ─── Receipt Generator ────────────────────────────────────────────────────────

class ReceiptGenerator:
    """Generates signed governance receipts."""

    def __init__(
        self,
        system_id: str,
        signing_key: bytes,
        key_id: str = "default",
        session_id: Optional[str] = None,
    ):
        self.system_id = system_id
        self.signing_key = signing_key
        self.key_id = key_id
        self.session_id = session_id or str(uuid.uuid4())
        self._last_receipt_hash: Optional[str] = None

    def generate(
        self,
        inputs: object,
        outputs: object,
        reasoning_summary: str,
        constraints: List[ConstraintResult],
        confidence: float,
        inputs_type: str = "user_message",
        outputs_type: str = "response",
        inputs_redacted: bool = False,
        human_reviewed: bool = False,
    ) -> GovernanceReceipt:
        """Generate a signed receipt for a decision."""

        inputs_hash = self._hash(inputs)
        outputs_hash = self._hash(outputs)

        receipt = GovernanceReceipt(
            system_id=self.system_id,
            session_id=self.session_id,
            chain_prev=self._last_receipt_hash,
            inputs_hash=inputs_hash,
            inputs_type=inputs_type,
            inputs_redacted=inputs_redacted,
            outputs_hash=outputs_hash,
            outputs_type=outputs_type,
            confidence=confidence,
            reasoning_summary=reasoning_summary[:500],  # Spec max
            constraints=constraints,
            human_reviewed=human_reviewed,
            signature_key_id=self.key_id,
        )

        receipt.signature_value = self._sign(receipt)
        self._last_receipt_hash = self._hash(receipt.signing_payload())
        return receipt

    def _hash(self, obj: object) -> str:
        canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _sign(self, receipt: GovernanceReceipt) -> str:
        payload = receipt.signing_payload().encode()
        return hmac.new(self.signing_key, payload, hashlib.sha256).hexdigest()


# ─── Receipt Verifier ─────────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    valid: bool
    chain_intact: bool
    signature_valid: bool
    constraint_violations: List[str]
    errors: List[str] = field(default_factory=list)


class ReceiptVerifier:
    """Verifies governance receipts."""

    def __init__(self, signing_key: bytes):
        self.signing_key = signing_key

    def verify(self, receipt: GovernanceReceipt) -> VerificationResult:
        errors = []
        signature_valid = self._verify_signature(receipt)
        if not signature_valid:
            errors.append("Signature verification failed")

        violations = [
            c.constraint_id for c in receipt.constraints if c.result == "FAIL"
        ]

        return VerificationResult(
            valid=signature_valid and not violations,
            chain_intact=True,  # Single-receipt check; use SessionAuditor for chain
            signature_valid=signature_valid,
            constraint_violations=violations,
            errors=errors,
        )

    def verify_chain(self, receipts: List[GovernanceReceipt]) -> VerificationResult:
        """Verify a sequence of receipts forms a valid chain."""
        errors = []
        all_violations = []

        for i, receipt in enumerate(receipts):
            if not self._verify_signature(receipt):
                errors.append(f"Receipt {i} ({receipt.id[:8]}): invalid signature")

            if i > 0:
                expected_prev = hashlib.sha256(
                    receipts[i - 1].signing_payload().encode()
                ).hexdigest()
                if receipt.chain_prev != expected_prev:
                    errors.append(f"Receipt {i}: chain broken (prev hash mismatch)")

            all_violations.extend(
                c.constraint_id for c in receipt.constraints if c.result == "FAIL"
            )

        return VerificationResult(
            valid=not errors and not all_violations,
            chain_intact=not any("chain" in e for e in errors),
            signature_valid=not any("signature" in e for e in errors),
            constraint_violations=all_violations,
            errors=errors,
        )

    def _verify_signature(self, receipt: GovernanceReceipt) -> bool:
        payload = receipt.signing_payload().encode()
        expected = hmac.new(self.signing_key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(receipt.signature_value, expected)
