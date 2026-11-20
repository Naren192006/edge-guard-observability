"""
VeilOps Tier 1 SQLite WAL Outbox & Hash-Chained Ledger Manager
Implements:
1. Crash-safe outbox buffer with exponential backoff & jitter
2. Delete-only-after-ack lifecycle
3. Bounded buffer management with graceful coarsening
4. Tamper-evident hash-chained egress ledger (prev_hash)
5. Local raw store with 24-hour rolling retention
"""

import sqlite3
import hashlib
import json
import time
import random
import os
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta, timezone

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DB_PATH = os.path.join(ROOT_DIR, "collector", "veilops_collector.db")
SCHEMA_PATH = os.path.join(ROOT_DIR, "collector", "schema", "sqlite_schema.sql")


class OutboxManager:
    def __init__(self, db_path: str = DEFAULT_DB_PATH, max_buffer_records: int = 10000):
        self.db_path = db_path
        self.max_buffer_records = max_buffer_records
        self._mem_conn = None
        if self.db_path == ":memory:":
            # Keep persistent anchor connection for shared in-memory SQLite database
            self._mem_conn = sqlite3.connect("file:collector_mem?mode=memory&cache=shared", uri=True)
            self._mem_conn.execute("PRAGMA journal_mode = WAL;")
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            conn = sqlite3.connect("file:collector_mem?mode=memory&cache=shared", uri=True)
            return conn
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def init_db(self):
        if self.db_path != ":memory:":
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            ddl = f.read()
        conn = self.get_connection()
        conn.executescript(ddl)
        conn.close()

    def store_raw_diagnostic(self, source_id: str, event_type: str, raw_text: str):
        """Stores unredacted raw diagnostic log locally for on-prem inspection (24h retention)."""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=24)
        conn = self.get_connection()
        conn.execute(
            """
            INSERT INTO local_raw_store (source_id, event_type, raw_payload, captured_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (source_id, event_type, raw_text, now.isoformat(), expires.isoformat())
        )
        conn.commit()
        conn.close()

    def get_latest_seq(self) -> int:
        """Returns the highest monotonic sequence number recorded, or 0."""
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT MAX(seq) FROM egress_ledger")
        row = cur.fetchone()
        conn.close()
        return row[0] if (row and row[0] is not None) else 0

    def get_latest_ledger_hash(self) -> str:
        """Returns payload_hash of the latest record in the hash-chained ledger, or 64 zeroes."""
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT payload_hash FROM egress_ledger ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        conn.close()
        return row[0] if row else ("0" * 64)

    def write_payload_to_outbox_and_ledger(
        self,
        payload: Dict[str, Any],
        payload_bytes: bytes
    ) -> str:
        """
        Atomically records outbound payload in SQLite outbox buffer AND hash-chained egress ledger.
        Enforces size cap by coarsening/pruning oldest pending records if threshold reached.
        """
        payload_id = payload["payload_id"]
        seq = payload["seq"]
        tenant_id = payload["tenant_id"]
        collector_id = payload["collector_id"]
        prev_hash = payload["prev_hash"]
        signature = payload["signature"]
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()

        conn = self.get_connection()
        cursor = conn.cursor()

        # Enforce buffer capacity (graceful coarsening / oldest drop if exceeding cap)
        cursor.execute("SELECT COUNT(*) FROM outbox WHERE status = 'PENDING'")
        pending_count = cursor.fetchone()[0]
        if pending_count >= self.max_buffer_records:
            cursor.execute("""
                DELETE FROM outbox WHERE payload_id IN (
                    SELECT payload_id FROM outbox WHERE status = 'PENDING' ORDER BY seq ASC LIMIT 50
                )
            """)

        # 1. Write to Outbox
        cursor.execute(
            """
            INSERT INTO outbox (payload_id, tenant_id, collector_id, seq, payload_bytes, status)
            VALUES (?, ?, ?, ?, ?, 'PENDING')
            """,
            (payload_id, tenant_id, collector_id, seq, payload_bytes)
        )

        # 2. Write to Hash-Chained Egress Ledger
        cursor.execute(
            """
            INSERT INTO egress_ledger (seq, payload_id, tenant_id, collector_id, prev_hash, payload_hash, payload_bytes, signature, ack_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')
            """,
            (seq, payload_id, tenant_id, collector_id, prev_hash, payload_hash, payload_bytes, signature)
        )

        conn.commit()
        conn.close()
        return payload_hash

    def get_pending_outbox_batch(self, limit: int = 10) -> List[Tuple[str, bytes, int]]:
        """Returns list of (payload_id, payload_bytes, retry_count) ready to send."""
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT payload_id, payload_bytes, retry_count
            FROM outbox
            WHERE status = 'PENDING'
            ORDER BY seq ASC
            LIMIT ?
            """,
            (limit,)
        )
        rows = cur.fetchall()
        conn.close()
        return rows

    def record_send_failure(self, payload_id: str, error_msg: str, retry_count: int):
        """Calculates exponential backoff with jitter (1s to 30s) and updates status."""
        delay = min(30.0, (2 ** retry_count) + random.uniform(0.5, 2.0))
        next_retry = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat()

        conn = self.get_connection()
        conn.execute(
            """
            UPDATE outbox
            SET retry_count = retry_count + 1,
                last_error = ?,
                next_retry_at = ?
            WHERE payload_id = ?
            """,
            (error_msg, next_retry, payload_id)
        )
        conn.commit()
        conn.close()

    def acknowledge_payload(self, payload_id: str, saas_stored_hash: Optional[str] = None):
        """
        Deletes payload from Outbox upon SaaS confirmation, and marks ledger row as ACKED.
        If saas_stored_hash is provided and matches, marks saas_verified = 1.
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        # Update Ledger Status
        verified = 0
        if saas_stored_hash:
            cursor.execute("SELECT payload_hash FROM egress_ledger WHERE payload_id = ?", (payload_id,))
            row = cursor.fetchone()
            if row and row[0] == saas_stored_hash:
                verified = 1

        cursor.execute(
            """
            UPDATE egress_ledger
            SET ack_status = 'ACKED', saas_verified = ?, sent_at = CURRENT_TIMESTAMP
            WHERE payload_id = ?
            """,
            (verified, payload_id)
        )

        # Delete from Outbox
        cursor.execute("DELETE FROM outbox WHERE payload_id = ?", (payload_id,))
        conn.commit()
        conn.close()

    def purge_expired_raw_logs(self) -> int:
        """Deletes raw records past their 24h retention threshold."""
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM local_raw_store WHERE expires_at < CURRENT_TIMESTAMP")
        purged = cur.rowcount
        conn.commit()
        conn.close()
        return purged
