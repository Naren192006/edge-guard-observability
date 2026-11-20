"""
VeilOps Tier 1 Redaction Engine & Security Scanner
Implements:
1. Regex-based secret scrubbing
2. Shannon-entropy calculation & high-entropy token detection (> 4.2 bits/char)
3. Salted HMAC-SHA256 entity pseudonymization (h_*, p_*)
4. Pre-egress canary tripwire detection & hard-block gate
"""

import math
import hmac
import hashlib
import json
import re
import os
from typing import Tuple, List, Dict, Any, Optional

DEFAULT_SALT = b"veilops_local_collector_salt_2026_unshared"


def calculate_shannon_entropy(token: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not token:
        return 0.0
    length = len(token)
    freq: Dict[str, int] = {}
    for char in token:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def generate_hmac_pseudonym(raw_id: str, salt: bytes = DEFAULT_SALT, prefix: str = "h_") -> str:
    """Generates deterministic, non-reversible pseudonym using local-only salt."""
    digest = hmac.new(salt, raw_id.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{prefix}{digest[:6]}"


class RedactionEngine:
    def __init__(self, config_path: Optional[str] = None, salt: Optional[bytes] = None):
        self.salt = salt or DEFAULT_SALT
        if config_path and os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = json.load(f)
        else:
            self.config = {
                "entropy_threshold": 4.2,
                "min_entropy_token_len": 16,
                "canary_tokens": [
                    "CANARY_AKIA_IOSFODNN7EXAMPLE",
                    "CANARY_PASSWD_SECRET999!",
                    "CANARY_JWT_TOKEN_SECRET_SIMULATOR"
                ],
                "regex_rules": [
                    {"name": "aws_key", "pattern": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])", "replacement": "[REDACTED_AWS_KEY]"},
                    {"name": "jwt", "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "replacement": "[REDACTED_JWT]"},
                    {"name": "pwd", "pattern": r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*['\"]?([^&\s'\"]+)", "replacement": r"\1=[REDACTED_SECRET]"},
                    {"name": "email", "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b", "replacement": "[REDACTED_EMAIL]"}
                ]
            }

        self.compiled_rules = [
            (r["name"], re.compile(r["pattern"]), r["replacement"])
            for r in self.config.get("regex_rules", [])
        ]
        self.canary_tokens = set(self.config.get("canary_tokens", []))
        self.entropy_threshold = self.config.get("entropy_threshold", 4.2)
        self.min_entropy_len = self.config.get("min_entropy_token_len", 16)
        self.leak_blocked_count = 0

    def scrub_text(self, text: str) -> str:
        """Applies regex scrubbing rules to free-text."""
        scrubbed = text
        for _, pattern, repl in self.compiled_rules:
            scrubbed = pattern.sub(repl, scrubbed)
        return scrubbed

    def check_entropy_leak(self, text: str) -> List[str]:
        """Detects tokens exceeding Shannon entropy threshold."""
        leaks = []
        tokens = re.split(r"[\s,;:=]+", text)
        for token in tokens:
            clean_token = token.strip(" '\"()[]{}")
            if len(clean_token) >= self.min_entropy_len:
                entropy = calculate_shannon_entropy(clean_token)
                if entropy >= self.entropy_threshold:
                    leaks.append(clean_token)
        return leaks

    def scan_egress_bytes(self, payload_bytes: bytes) -> Tuple[bool, Optional[str]]:
        """
        Byte-level Canary & Entropy inspection at Egress Gate.
        Returns: (is_safe, error_reason)
        """
        payload_str = payload_bytes.decode("utf-8", errors="replace")

        # 1. Canary tripwire check
        for canary in self.canary_tokens:
            if canary in payload_str:
                self.leak_blocked_count += 1
                return False, f"TRIPWIRE_TRIGGERED: Planted canary '{canary[:8]}...' detected in outbound payload"

        # 2. Entropy check on payload string values
        # Scan string literals in JSON
        string_literals = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', payload_str)
        for val in string_literals:
            if len(val) >= self.min_entropy_len and not val.startswith("ed25519:") and len(val) != 64 and len(val) != 26:
                entropy = calculate_shannon_entropy(val)
                if entropy >= self.entropy_threshold:
                    self.leak_blocked_count += 1
                    return False, f"ENTROPY_GATE_TRIGGERED: High entropy string (H={entropy:.2f}) detected"

        return True, None
