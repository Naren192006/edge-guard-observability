"""
VeilOps Tier 1 Telemetry Stream Adapter & Fallback Generator
Reads external organizer stream or runs high-fidelity synthetic fallback generation.
"""

import time
import math
import random
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class StreamAdapter:
    def __init__(self, mode: str = "fallback"):
        self.mode = mode
        self.running = False
        self.start_time = time.time()

    def generate_sample(self, t_sec: Optional[float] = None) -> Dict[str, Any]:
        """Generates continuous sinusoidal telemetry with noise and occasional bursts."""
        now_t = t_sec if t_sec is not None else time.time()
        now_utc = datetime.fromtimestamp(now_t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        elapsed = now_t - self.start_time

        # Sinusoidal diurnal wave (period = 86400s, accelerated for demo)
        omega = 2.0 * math.pi / 3600.0  # 1 hour cyclic period
        sine_wave = math.sin(omega * elapsed)

        cpu = max(5.0, min(95.0, 50.0 + 20.0 * sine_wave + random.gauss(0, 3.0)))
        mem = max(20.0, min(90.0, 60.0 + 10.0 * sine_wave + random.gauss(0, 1.5)))
        disk = min(98.0, 45.0 + (elapsed / 3600.0) * 0.5)
        bandwidth = max(100000, int(1000000 + 400000 * sine_wave + random.gauss(0, 50000)))
        latency = max(5.0, 22.0 + 5.0 * sine_wave + random.gauss(0, 2.0))
        loss = max(0.0, 0.05 + random.gauss(0, 0.01))

        return {
            "timestamp": now_utc,
            "metrics": [
                {"src": "prd-db-master-01.internal.corp", "name": "cpu_pct", "value": round(cpu, 2)},
                {"src": "prd-db-master-01.internal.corp", "name": "mem_pct", "value": round(mem, 2)},
                {"src": "prd-db-master-01.internal.corp", "name": "disk_pct", "value": round(disk, 2)},
                {"src": "prd-db-master-01.internal.corp", "name": "net_in_bytes", "value": bandwidth},
                {"src": "prd-db-master-01.internal.corp", "name": "net_out_bytes", "value": int(bandwidth * 0.7)},
                {"src": "edge-switch-01.internal.corp", "name": "latency_ms", "value": round(latency, 2)},
                {"src": "edge-switch-01.internal.corp", "name": "packet_loss_pct", "value": round(loss, 3)}
            ]
        }
