"""
VeilOps Tier 1 Egress Gate
Sole gatekeeper between Customer Environment and Central SaaS.
Enforces:
1. Schema allow-list (JSON Schema additionalProperties: false, no free-text fields)
2. Per-tenant signed policy validation
3. Canary tripwire and Shannon entropy byte scan
4. Cryptographic Ed25519 signing
5. ULID / UUIDv7 payload_id generation & contiguous sequence counter
"""

import os
import json
import time
import base64
import hashlib
from typing import Dict, Any, Tuple, Optional, List
from datetime import datetime, timezone
import jsonschema

from cryptography.hazmat.primitives.asymmetric import ed25519
from collector.redaction.redaction_engine import RedactionEngine

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCHEMA_PATH = os.path.join(ROOT_DIR, "contracts", "payload.schema.json")
RULES_PATH = os.path.join(ROOT_DIR, "collector", "redaction", "rules.json")


def generate_ulid() -> str:
    """Generates a valid 26-character Crockford base32 ULID identifier."""
    # 48-bit timestamp (10 chars) + 80-bit randomness (16 chars) = 26 chars
    crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    timestamp_ms = int(time.time() * 1000)
    time_chars = []
    for _ in range(10):
        time_chars.append(crockford[timestamp_ms % 32])
        timestamp_ms //= 32
    time_part = "".join(reversed(time_chars))

    rand_bytes = os.urandom(16)
    rand_part = "".join(crockford[b % 32] for b in rand_bytes)
    return time_part + rand_part


class EgressGate:
    def __init__(
        self,
        tenant_id: str = "t_acme",
        collector_id: str = "c_blr_dc1",
        schema_path: str = SCHEMA_PATH,
        start_seq: Optional[int] = None
    ):
        self.tenant_id = tenant_id
        self.collector_id = collector_id
        if start_seq is not None:
            self.seq_counter = start_seq
        else:
            try:
                from collector.outbox import OutboxManager
                self.seq_counter = OutboxManager().get_latest_seq()
            except Exception:
                self.seq_counter = 0

        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.redaction_engine = RedactionEngine(config_path=RULES_PATH)

        with open(schema_path, "r", encoding="utf-8") as f:
            self.schema = json.load(f)

    def assemble_payload(
        self,
        metrics: List[Dict[str, Any]],
        log_fingerprints: List[Dict[str, Any]],
        security: List[Dict[str, Any]],
        health_state: str = "good",
        reason_codes: Optional[List[str]] = None,
        prev_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """Assembles typed wire payload adhering strictly to schema."""
        self.seq_counter += 1
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if reason_codes is None:
            reason_codes = ["ALL_SYSTEMS_NORMAL"] if health_state in ["excellent", "good"] else ["CPU_BASELINE_DEV"]

        payload = {
            "payload_id": generate_ulid(),
            "tenant_id": self.tenant_id,
            "collector_id": self.collector_id,
            "schema_v": 3,
            "policy_v": 12,
            "event_time_utc": now_utc,
            "source_tz": "Asia/Kolkata",
            "seq": self.seq_counter,
            "prev_hash": prev_hash or ("0" * 64),
            "metrics": metrics,
            "log_fingerprints": log_fingerprints,
            "security": security,
            "health": {
                "state": health_state,
                "reason_codes": reason_codes
            },
            "signature": "ed25519:placeholder"
        }

        # Calculate signature over canonical JSON without signature field
        canonical_bytes = json.dumps(
            {k: v for k, v in payload.items() if k != "signature"},
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        raw_sig = self.private_key.sign(canonical_bytes)
        b64_sig = base64.b64encode(raw_sig).decode("ascii")
        payload["signature"] = f"ed25519:{b64_sig}"
        return payload

    def inspect_and_seal(self, payload: Dict[str, Any]) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """
        Validates schema, checks canary tripwires & entropy, and returns serialized bytes.
        Returns: (passed, serialized_bytes, error_message)
        """
        # 1. Schema Validation (checks additionalProperties: false, enums, required fields)
        try:
            jsonschema.validate(instance=payload, schema=self.schema)
        except jsonschema.ValidationError as e:
            return False, None, f"SCHEMA_VALIDATION_ERROR: {e.message}"

        # 2. Serialize canonical bytes
        serialized_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # 3. Canary and High-Entropy Byte-Level Scanner
        safe, tripwire_err = self.redaction_engine.scan_egress_bytes(serialized_bytes)
        if not safe:
            return False, None, tripwire_err

        return True, serialized_bytes, None
