"""
VeilOps Tier 1 Processing Pipeline
Stages:
1. Normalize (UTC ISO 8601, source timezone, event model)
2. Redact (Regex secret scrubbing, Shannon entropy checks, Salted HMAC pseudonyms)
3. Fingerprint (Drain3 online log template miner)
4. Aggregate (5-second tumbling window calculations)
5. Local Security (Sliding window failed-login detector)
"""

import re
import math
import hashlib
import hmac
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone
from collector.redaction.redaction_engine import (
    RedactionEngine,
    calculate_shannon_entropy,
    generate_hmac_pseudonym,
    DEFAULT_SALT
)


class EventNormalizer:
    def __init__(self, source_tz: str = "Asia/Kolkata"):
        self.source_tz = source_tz

    def normalize_metric(self, raw_metric: Dict[str, Any]) -> Dict[str, Any]:
        ts = raw_metric.get("timestamp")
        if not ts:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "src": raw_metric.get("src", "unknown_host"),
            "name": raw_metric.get("name"),
            "value": float(raw_metric.get("value", 0.0)),
            "unit": raw_metric.get("unit", "count"),
            "event_time_utc": ts,
            "source_tz": self.source_tz
        }


class Drain3Fingerprinter:
    """
    Online parse tree log miner that abstracts dynamic tokens into <*>
    and produces truncated MD5 hex hashes.
    """
    def __init__(self):
        self.templates: Dict[str, str] = {}
        # Dynamic variable regexes (IPs, numbers, UUIDs, quoted strings, file paths)
        self.var_patterns = [
            re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
            re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
            re.compile(r"/[\w\-./]+"),
            re.compile(r"\b(?:for\s+user|for|user)\s+([a-zA-Z0-9._-]+)", re.IGNORECASE),
            re.compile(r"\b\d+\b"),
            re.compile(r"['\"][^'\"]*['\"]")
        ]

    def mine_template(self, log_line: str) -> Tuple[str, str]:
        """Returns (template_text, template_hash_6hex)."""
        masked = log_line
        for pat in self.var_patterns:
            masked = pat.sub("<*>", masked)

        # Normalize whitespace
        template_text = re.sub(r"\s+", " ", masked).strip()
        tpl_hash = hashlib.md5(template_text.encode("utf-8")).hexdigest()[:6]
        self.templates[tpl_hash] = template_text
        return template_text, tpl_hash


class WindowAggregator:
    """Aggregates raw metric samples into 5-second tumbling windows."""
    def __init__(self, win_s: int = 5):
        self.win_s = win_s
        self.metric_buckets: Dict[Tuple[str, str], List[float]] = {}
        self.fingerprint_buckets: Dict[Tuple[str, str, str], int] = {}

    def add_sample(self, src: str, metric_name: str, value: float):
        key = (src, metric_name)
        if key not in self.metric_buckets:
            self.metric_buckets[key] = []
        self.metric_buckets[key].append(value)

    def add_fingerprint(self, src: str, tpl: str, sev: str):
        key = (src, tpl, sev)
        self.fingerprint_buckets[key] = self.fingerprint_buckets.get(key, 0) + 1

    def flush_metrics(self) -> List[Dict[str, Any]]:
        results = []
        for (src, name), values in self.metric_buckets.items():
            if not values:
                continue
            sorted_v = sorted(values)
            n = len(values)
            p95_idx = int(0.95 * n) if n > 1 else 0
            results.append({
                "src": src,
                "name": name,
                "win_s": self.win_s,
                "mean": round(sum(values) / n, 2),
                "p95": round(sorted_v[p95_idx], 2),
                "max": round(max(values), 2),
                "min": round(min(values), 2),
                "n": n
            })
        self.metric_buckets.clear()
        return results

    def flush_fingerprints(self) -> List[Dict[str, Any]]:
        results = []
        for (src, tpl, sev), count in self.fingerprint_buckets.items():
            results.append({
                "src": src,
                "tpl": tpl,
                "sev": sev,
                "count": count
            })
        self.fingerprint_buckets.clear()
        return results


class LocalSecurityDetector:
    """
    Local sliding-window detector for failed logins and brute-force events.
    Never transmits raw usernames or cleartext passwords!
    """
    def __init__(self, win_s: int = 60, high_risk_threshold: int = 15):
        self.win_s = win_s
        self.high_risk_threshold = high_risk_threshold
        self.fail_counts: Dict[str, int] = {}

    def record_auth_failure(self, pseudonymous_src: str):
        self.fail_counts[pseudonymous_src] = self.fail_counts.get(pseudonymous_src, 0) + 1

    def evaluate_risk(self) -> List[Dict[str, Any]]:
        results = []
        for src, count in self.fail_counts.items():
            if count >= self.high_risk_threshold:
                risk = "high"
            elif count >= 5:
                risk = "medium"
            else:
                risk = "low"

            results.append({
                "src": src,
                "cat": "auth_fail",
                "count": count,
                "win_s": self.win_s,
                "risk": risk
            })
        self.fail_counts.clear()
        return results
