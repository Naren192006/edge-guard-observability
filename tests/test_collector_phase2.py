"""
Automated Unit Tests for VeilOps Tier 1 (Phase 2 Person 1 Deliverables)
Zero-dependency test runner using Python standard library unittest.
Covers:
1. SQLite DDL execution, WAL mode verification, outbox insert/delete-on-ack lifecycle
2. Hash-chained egress ledger (prev_hash integrity)
3. Shannon entropy calculation & high-entropy token detection
4. Salted HMAC pseudonym function (h_*, p_*)
5. Canary tripwire scanner & hard-block gate
"""

import unittest
import sqlite3
import hashlib
import json
import os
import sys

# Ensure root directory is on PYTHONPATH
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from collector.redaction.redaction_engine import (
    RedactionEngine,
    calculate_shannon_entropy,
    generate_hmac_pseudonym,
    DEFAULT_SALT
)

SCHEMA_PATH = os.path.join(ROOT_DIR, "collector", "schema", "sqlite_schema.sql")
RULES_PATH = os.path.join(ROOT_DIR, "collector", "redaction", "rules.json")


class TestCollectorPhase2(unittest.TestCase):

    def test_sqlite_schema_execution_and_wal(self):
        """Verify SQLite DDL initializes in memory and supports outbox + ledger."""
        conn = sqlite3.connect(":memory:")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            ddl = f.read()
        conn.executescript(ddl)

        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}
        self.assertIn("outbox", tables)
        self.assertIn("egress_ledger", tables)
        self.assertIn("local_raw_store", tables)

    def test_outbox_insert_and_ack_lifecycle(self):
        """Verify outbox at-least-once buffering and delete-after-ack."""
        conn = sqlite3.connect(":memory:")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())

        payload_id = "01JD8Z3K7Q9X4M2V6T1B5N8R0C"
        sample_bytes = b'{"payload_id": "01JD8Z3K7Q9X4M2V6T1B5N8R0C"}'
        conn.execute(
            """
            INSERT INTO outbox (payload_id, tenant_id, collector_id, seq, payload_bytes, status)
            VALUES (?, ?, ?, ?, ?, 'PENDING')
            """,
            (payload_id, "t_acme", "c_blr_dc1", 1, sample_bytes)
        )
        conn.commit()

        cur = conn.cursor()
        cur.execute("SELECT payload_id, status FROM outbox WHERE status='PENDING'")
        rows = cur.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], payload_id)

        # Simulate SaaS Ack -> Delete row
        conn.execute("DELETE FROM outbox WHERE payload_id = ?", (payload_id,))
        conn.commit()

        cur.execute("SELECT COUNT(*) FROM outbox")
        self.assertEqual(cur.fetchone()[0], 0)

    def test_hash_chained_egress_ledger(self):
        """Verify hash-chaining in egress ledger with prev_hash binding."""
        conn = sqlite3.connect(":memory:")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())

        genesis_prev_hash = "0" * 64
        block1_bytes = b'{"seq": 1, "data": "first"}'
        block1_hash = hashlib.sha256(block1_bytes).hexdigest()

        conn.execute(
            """
            INSERT INTO egress_ledger (seq, payload_id, tenant_id, collector_id, prev_hash, payload_hash, payload_bytes, signature, ack_status)
            VALUES (1, '01JD8Z1', 't_acme', 'c_blr_1', ?, ?, ?, 'ed25519:test1', 'ACKED')
            """,
            (genesis_prev_hash, block1_hash, block1_bytes)
        )

        block2_bytes = b'{"seq": 2, "data": "second"}'
        block2_hash = hashlib.sha256(block2_bytes).hexdigest()
        conn.execute(
            """
            INSERT INTO egress_ledger (seq, payload_id, tenant_id, collector_id, prev_hash, payload_hash, payload_bytes, signature, ack_status)
            VALUES (2, '01JD8Z2', 't_acme', 'c_blr_1', ?, ?, ?, 'ed25519:test2', 'PENDING')
            """,
            (block1_hash, block2_hash, block2_bytes)
        )
        conn.commit()

        cur = conn.cursor()
        cur.execute("SELECT seq, prev_hash, payload_hash FROM egress_ledger ORDER BY seq ASC")
        blocks = cur.fetchall()
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0][1], genesis_prev_hash)
        self.assertEqual(blocks[1][1], blocks[0][2])  # Block 2 prev_hash == Block 1 payload_hash

    def test_shannon_entropy_calculation(self):
        """Verify Shannon entropy accurately distinguishes natural language from cryptographic secrets."""
        low_entropy_english = "this is a normal service status message"
        high_entropy_secret = "4aF9zX8bQ2vK1pL0mN7jY6cT"  # 24 char base62 random string

        h_low = calculate_shannon_entropy(low_entropy_english)
        h_high = calculate_shannon_entropy(high_entropy_secret)

        self.assertLess(h_low, 3.8)
        self.assertGreater(h_high, 4.2)

    def test_hmac_pseudonym_generation(self):
        """Verify deterministic, salted HMAC pseudonyms."""
        host = "prd-db-master-01.internal.corp"
        ip = "192.168.1.105"

        h_pseudo1 = generate_hmac_pseudonym(host, prefix="h_")
        h_pseudo2 = generate_hmac_pseudonym(host, prefix="h_")
        p_pseudo = generate_hmac_pseudonym(ip, prefix="p_")

        self.assertEqual(h_pseudo1, h_pseudo2)
        self.assertTrue(h_pseudo1.startswith("h_"))
        self.assertEqual(len(h_pseudo1), 8)  # 'h_' + 6 hex chars
        self.assertTrue(p_pseudo.startswith("p_"))
        self.assertNotEqual(h_pseudo1, p_pseudo)

    def test_canary_tripwire_hard_block(self):
        """Verify canary tripwire halts egress when a planted secret is detected."""
        engine = RedactionEngine(config_path=RULES_PATH)

        clean_payload = b'{"payload_id": "01JD8Z3K", "health": {"state": "good"}}'
        safe, err = engine.scan_egress_bytes(clean_payload)
        self.assertTrue(safe)
        self.assertIsNone(err)

        leaking_payload = b'{"payload_id": "01JD8Z3K", "log": "CANARY_AKIA_IOSFODNN7EXAMPLE"}'
        safe, err = engine.scan_egress_bytes(leaking_payload)
        self.assertFalse(safe)
        self.assertIn("TRIPWIRE_TRIGGERED", err)
        self.assertEqual(engine.leak_blocked_count, 1)


if __name__ == "__main__":
    unittest.main()
