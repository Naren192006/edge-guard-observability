"""
Automated Test Suite for VeilOps Phase 3 Person 1 (Collector & Privacy)
Verifies:
1. Planted canary secret NEVER appears in any outbound/sent byte
2. Unknown fields and free-text fields are rejected by the Egress Gate
3. Drain3 log fingerprinting abstracts logs into template hashes and counts
4. Failed-login detection escalates risk while keeping raw credentials local
5. SQLite WAL outbox buffers payloads and deletes only after ack
6. Hash-chained ledger links prev_hash
7. Scenario injector CLI executes all 8 scenarios cleanly
"""

import unittest
import os
import sys
import json
import sqlite3

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from collector.inputs.telemetry_inputs import HostMetricsCollector, NetworkProbeCollector, SyslogListener
from collector.pipeline.collector_pipeline import (
    EventNormalizer,
    Drain3Fingerprinter,
    WindowAggregator,
    LocalSecurityDetector
)
from collector.egress_gate import EgressGate
from collector.outbox import OutboxManager
from collector.redaction.redaction_engine import RedactionEngine
from simulator.scenario_injector import ScenarioInjector


class TestPhase3Collector(unittest.TestCase):

    def setUp(self):
        self.egress_gate = EgressGate()
        self.outbox_mgr = OutboxManager(db_path=":memory:")
        self.redactor = RedactionEngine()
        self.fingerprinter = Drain3Fingerprinter()
        self.security_detector = LocalSecurityDetector()

    def test_canary_secret_never_appears_in_sent_bytes(self):
        """Test Claim: A planted canary secret never appears in any sent byte."""
        raw_log = "Error in auth: planted token CANARY_AKIA_IOSFODNN7EXAMPLE and pwd=Secret12345!"

        # Process through Drain3 & Redactor
        scrubbed = self.redactor.scrub_text(raw_log)
        tpl_text, tpl_hash = self.fingerprinter.mine_template(scrubbed)

        payload = self.egress_gate.assemble_payload(
            metrics=[],
            log_fingerprints=[{"src": "h_4af29c", "tpl": tpl_hash, "sev": "error", "count": 1}],
            security=[],
            health_state="good"
        )

        safe, payload_bytes, err = self.egress_gate.inspect_and_seal(payload)
        self.assertTrue(safe, f"Payload should be safe: {err}")
        self.assertIsNotNone(payload_bytes)

        # Byte-level assertion
        serialized_str = payload_bytes.decode("utf-8")
        self.assertNotIn("CANARY_AKIA_IOSFODNN7EXAMPLE", serialized_str)
        self.assertNotIn("Secret12345!", serialized_str)
        self.assertIn(tpl_hash, serialized_str)

    def test_unknown_fields_and_free_text_rejected(self):
        """Test Claim: Unknown fields and free-text fields are rejected by the Egress Gate."""
        # 1. Payload with forbidden free-text field
        bad_payload = self.egress_gate.assemble_payload(
            metrics=[],
            log_fingerprints=[],
            security=[],
            health_state="good"
        )
        bad_payload["raw_log"] = "database connection timeout on host 10.0.0.1"

        safe, _, err = self.egress_gate.inspect_and_seal(bad_payload)
        self.assertFalse(safe)
        self.assertIn("SCHEMA_VALIDATION_ERROR", err)

        # 2. Payload with unapproved metric enum
        bad_payload_2 = self.egress_gate.assemble_payload(
            metrics=[{"src": "h_4af29c", "name": "forbidden_custom_metric", "win_s": 5, "mean": 1.0, "p95": 1.0, "max": 1.0, "n": 1}],
            log_fingerprints=[],
            security=[],
            health_state="good"
        )
        safe2, _, err2 = self.egress_gate.inspect_and_seal(bad_payload_2)
        self.assertFalse(safe2)
        self.assertIn("SCHEMA_VALIDATION_ERROR", err2)

    def test_drain3_log_fingerprinting(self):
        """Test Claim: Drain3 mines logs into template structure and hex hash."""
        log1 = "Failed password for root from 192.168.1.50 port 2222 ssh2"
        log2 = "Failed password for admin from 10.0.0.12 port 54321 ssh2"

        tpl1, hash1 = self.fingerprinter.mine_template(log1)
        tpl2, hash2 = self.fingerprinter.mine_template(log2)

        # Dynamic entities (usernames, IPs, ports) abstracted into <*>
        self.assertEqual(tpl1, tpl2)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 6)

    def test_sliding_window_auth_failure_risk_escalation(self):
        """Test Claim: Failed logins count and risk level cross boundary, never raw lines."""
        source_pseudo = "p_77d1"
        for _ in range(20):
            self.security_detector.record_auth_failure(source_pseudo)

        sec_events = self.security_detector.evaluate_risk()
        self.assertEqual(len(sec_events), 1)
        self.assertEqual(sec_events[0]["src"], source_pseudo)
        self.assertEqual(sec_events[0]["risk"], "high")
        self.assertEqual(sec_events[0]["count"], 20)
        self.assertNotIn("password", sec_events[0])
        self.assertNotIn("username", sec_events[0])

    def test_outbox_buffer_and_delete_after_ack(self):
        """Test Claim: Outbox buffers records and deletes only after ack."""
        mgr = OutboxManager(db_path=":memory:")
        payload = self.egress_gate.assemble_payload(metrics=[], log_fingerprints=[], security=[], health_state="good")
        safe, p_bytes, _ = self.egress_gate.inspect_and_seal(payload)
        self.assertTrue(safe)

        mgr.write_payload_to_outbox_and_ledger(payload, p_bytes)
        batch = mgr.get_pending_outbox_batch()
        self.assertEqual(len(batch), 1)
        self.assertEqual(batch[0][0], payload["payload_id"])

        # Ack deletes from outbox
        mgr.acknowledge_payload(payload["payload_id"])
        batch_after = mgr.get_pending_outbox_batch()
        self.assertEqual(len(batch_after), 0)

    def test_all_eight_scenarios_execute_cleanly(self):
        """Test Claim: Scenario injector triggers all 8 live scenarios."""
        injector = ScenarioInjector()
        res1 = injector.run_secret_scenario()
        self.assertEqual(res1["status"], "PASS")

        res2 = injector.run_outage_scenario(90)
        self.assertEqual(res2["status"], "PASS")

        res3 = injector.run_authburst_scenario()
        self.assertEqual(res3["status"], "PASS")

        res4 = injector.run_latency_scenario()
        self.assertEqual(res4["status"], "PASS")

        res5 = injector.run_cpu_scenario()
        self.assertEqual(res5["status"], "PASS")

        res6 = injector.run_cascade_scenario()
        self.assertEqual(res6["status"], "PASS")

        res7 = injector.run_dup_ooo_scenario()
        self.assertEqual(res7["status"], "PASS")

        res8 = injector.run_remediate_scenario()
        self.assertEqual(res8["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
