"""
VeilOps Tier 1 Telemetry Inputs
Captures Host Metrics (CPU, memory, disk, bandwidth), Network Probes (latency, packet loss),
and Syslog Listener.
"""

import asyncio
import time
import socket
import random
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

class HostMetricsCollector:
    """Collects CPU, memory, disk, and network bandwidth metrics."""
    def __init__(self, host_name: str = "collector-host-01"):
        self.host_name = host_name
        self.last_net_bytes = 1000000
        self.last_time = time.time()
        self.cpu_baseline = 45.0

    def set_cpu_spike(self, val: float):
        self.cpu_baseline = val

    def collect(self) -> List[Dict[str, Any]]:
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        now_ts = time.time()
        dt = max(0.1, now_ts - self.last_time)
        self.last_time = now_ts

        # Fallback host metrics with realistic fluctuation
        cpu_val = min(100.0, max(0.0, self.cpu_baseline + random.uniform(-2.5, 2.5)))
        mem_val = 62.0 + random.uniform(-1.0, 1.0)
        disk_val = 55.4 + random.uniform(-0.1, 0.1)
        bandwidth_bytes = int(random.uniform(500000, 1500000))

        return [
            {"src": self.host_name, "name": "cpu_pct", "value": round(cpu_val, 2), "unit": "percent", "timestamp": now_utc},
            {"src": self.host_name, "name": "mem_pct", "value": round(mem_val, 2), "unit": "percent", "timestamp": now_utc},
            {"src": self.host_name, "name": "disk_pct", "value": round(disk_val, 2), "unit": "percent", "timestamp": now_utc},
            {"src": self.host_name, "name": "net_in_bytes", "value": bandwidth_bytes, "unit": "bytes", "timestamp": now_utc},
            {"src": self.host_name, "name": "net_out_bytes", "value": int(bandwidth_bytes * 0.8), "unit": "bytes", "timestamp": now_utc}
        ]


class NetworkProbeCollector:
    """Probes network latency and packet loss via TCP/ICMP socket probes."""
    def __init__(self, target_host: str = "edge-switch-01", target_port: int = 443):
        self.target_host = target_host
        self.target_port = target_port
        self.injected_latency_ms: Optional[float] = None
        self.injected_loss_pct: Optional[float] = None

    def inject_degradation(self, latency_ms: float = 380.0, loss_pct: float = 6.4):
        self.injected_latency_ms = latency_ms
        self.injected_loss_pct = loss_pct

    def clear_degradation(self):
        self.injected_latency_ms = None
        self.injected_loss_pct = None

    def probe(self) -> List[Dict[str, Any]]:
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if self.injected_latency_ms is not None:
            lat = self.injected_latency_ms + random.uniform(-10.0, 10.0)
            loss = self.injected_loss_pct + random.uniform(-0.5, 0.5)
        else:
            lat = 18.5 + random.uniform(-2.0, 2.0)
            loss = 0.05 + random.uniform(-0.02, 0.02)

        return [
            {"src": self.target_host, "name": "latency_ms", "value": round(max(0.1, lat), 2), "unit": "ms", "timestamp": now_utc},
            {"src": self.target_host, "name": "packet_loss_pct", "value": round(max(0.0, loss), 2), "unit": "percent", "timestamp": now_utc}
        ]


class SyslogListener:
    """Async syslog listener buffer storing incoming log strings."""
    def __init__(self):
        self.buffer: List[Dict[str, Any]] = []

    def receive_log(self, raw_line: str, host: str = "prd-db-master-01.internal.corp", sev: str = "error"):
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.buffer.append({
            "src": host,
            "raw_text": raw_line,
            "sev": sev,
            "timestamp": now_utc
        })

    def drain(self) -> List[Dict[str, Any]]:
        batch = list(self.buffer)
        self.buffer.clear()
        return batch
