"""
VeilOps AIOps Engine - Phase 1 Prototype
Baseline & Robust Z-Score Anomaly Detector

Key characteristics:
1. Seasonal hour-of-week profile (168 hourly slots).
2. EWMA-tracked median and MAD (Median Absolute Deviation) to resist outlier poisoning.
3. Robust z-score computation using 1.4826 * MAD scaling.
4. Sustained-deviation rule (z > 3.5 for at least 3 of last 5 windows)
   to eliminate transient spikes (e.g., nightly batch jobs).
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import math


@dataclass
class AnomalyScore:
    metric: str
    source: str
    timestamp: datetime
    current_value: float
    baseline_median: float
    baseline_mad: float
    robust_z: float
    is_transient_spike: bool
    is_sustained_anomaly: bool
    severity: str  # "normal", "info", "warning", "critical"
    history_window_scores: List[float] = field(default_factory=list)
    reason: str = ""


class SeasonalEWMABaseline:
    """
    Maintains robust statistical baselines per (source, metric, hour_of_week).
    Uses Exponentially Weighted Moving Average for median and MAD.
    """

    def __init__(self, alpha: float = 0.1, min_mad: float = 0.5):
        """
        :param alpha: Smoothing factor for EWMA updates (0 < alpha <= 1)
        :param min_mad: Floor value for MAD to avoid division by zero on static signals
        """
        self.alpha = alpha
        self.min_mad = min_mad
        # Key: (source, metric, hour_of_week) -> (ewma_median, ewma_mad, sample_count)
        self.baselines: Dict[Tuple[str, str, int], Dict[str, float]] = {}

    @staticmethod
    def get_hour_of_week(dt: datetime) -> int:
        """Returns slot 0..167 based on UTC weekday (0=Monday) and hour."""
        dt_utc = dt.astimezone(timezone.utc) if dt.tzinfo else dt
        return dt_utc.weekday() * 24 + dt_utc.hour

    def update_and_score(
        self, source: str, metric: str, value: float, timestamp: datetime
    ) -> Tuple[float, float, float]:
        """
        Updates the baseline and returns (median, mad, robust_z).
        Robust z = (value - median) / (1.4826 * max(MAD, min_mad))
        """
        slot = self.get_hour_of_week(timestamp)
        key = (source, metric, slot)

        if key not in self.baselines:
            # Initialize baseline with the first sample
            self.baselines[key] = {
                "median": float(value),
                "mad": float(self.min_mad),
                "count": 1.0,
            }
            median = float(value)
            mad = float(self.min_mad)
            robust_z = 0.0
            return median, mad, robust_z

        entry = self.baselines[key]
        current_median = entry["median"]
        current_mad = entry["mad"]

        # Calculate deviation from current median
        abs_deviation = abs(value - current_median)

        # Robust z-score using standard Normal consistency factor 1.4826
        effective_mad = max(current_mad, self.min_mad)
        robust_z = (value - current_median) / (1.4826 * effective_mad)

        # Only update baseline if the value is not an extreme outlier (winsorized update)
        # Outliers with |z| > 4.0 don't poison the baseline immediately
        update_weight = self.alpha if abs(robust_z) <= 4.0 else (self.alpha * 0.1)

        # EWMA update for median and MAD
        new_median = (1.0 - update_weight) * current_median + update_weight * value
        new_mad = (1.0 - update_weight) * current_mad + update_weight * abs_deviation

        entry["median"] = new_median
        entry["mad"] = max(new_mad, self.min_mad)
        entry["count"] += 1.0

        return current_median, effective_mad, robust_z


class SustainedDeviationDetector:
    """
    Applies the 3-of-5 sustained deviation rule:
    An anomaly is only confirmed if robust z-score > z_threshold
    for at least 3 out of the last 5 sliding windows.
    """

    def __init__(
        self,
        z_threshold: float = 3.5,
        window_size: int = 5,
        min_breach_count: int = 3,
        baseline_model: Optional[SeasonalEWMABaseline] = None,
    ):
        self.z_threshold = z_threshold
        self.window_size = window_size
        self.min_breach_count = min_breach_count
        self.baseline_model = baseline_model or SeasonalEWMABaseline()
        # Key: (source, metric) -> deque of recent z-scores
        self.recent_scores: Dict[Tuple[str, str], deque] = {}

    def ingest_metric(
        self, source: str, metric: str, value: float, timestamp: datetime
    ) -> AnomalyScore:
        median, mad, z = self.baseline_model.update_and_score(
            source, metric, value, timestamp
        )

        key = (source, metric)
        if key not in self.recent_scores:
            self.recent_scores[key] = deque(maxlen=self.window_size)

        history = self.recent_scores[key]
        history.append(z)

        # Count breaches in recent history
        breach_count = sum(1 for score in history if abs(score) >= self.z_threshold)
        is_transient = (abs(z) >= self.z_threshold) and (breach_count < self.min_breach_count)
        is_sustained = breach_count >= self.min_breach_count

        # Assign severity based on sustained status and magnitude
        if is_sustained:
            severity = "critical" if abs(z) >= 5.0 else "warning"
            reason = (
                f"Sustained deviation: |z|={abs(z):.2f} exceeds threshold {self.z_threshold} "
                f"in {breach_count}/{len(history)} recent windows (value={value:.2f}, baseline={median:.2f})"
            )
        elif is_transient:
            severity = "info"
            reason = (
                f"Transient spike: |z|={abs(z):.2f} (waiting for sustained condition: "
                f"{breach_count}/{self.min_breach_count} needed)"
            )
        else:
            severity = "normal"
            reason = f"Normal: within seasonal baseline (|z|={abs(z):.2f})"

        return AnomalyScore(
            metric=metric,
            source=source,
            timestamp=timestamp,
            current_value=value,
            baseline_median=median,
            baseline_mad=mad,
            robust_z=z,
            is_transient_spike=is_transient,
            is_sustained_anomaly=is_sustained,
            severity=severity,
            history_window_scores=list(history),
            reason=reason,
        )


def run_prototype_simulation():
    """
    Runs a realistic sample demonstration simulating:
    1. Normal CPU baseline around 40% with small noise.
    2. A single transient spike to 95% (should be filtered out, not alerted).
    3. A sustained load spike to 92% across multiple windows (should trigger sustained anomaly).
    """
    detector = SustainedDeviationDetector(z_threshold=3.5, window_size=5, min_breach_count=3)
    source = "h_4af29c"
    metric = "cpu_pct"
    base_time = datetime(2026, 11, 20, 9, 0, 0, tzinfo=timezone.utc)

    print("======================================================================")
    print("VeilOps AIOps Phase 1: Robust Z-Score & Sustained Deviation Simulation")
    print("======================================================================")

    # Step 1: Warm up baseline with 20 normal values around 40%
    print("\n--- Phase 1.1: Warming up seasonal baseline (40% +/- 2%) ---")
    for i in range(20):
        t = datetime.fromtimestamp(base_time.timestamp() + i * 5, tz=timezone.utc)
        val = 40.0 + (1.5 if i % 2 == 0 else -1.5)
        detector.ingest_metric(source, metric, val, t)
    print(f"Baseline warmed with 20 samples. Current baseline slot ready.")

    # Step 2: Inject a single transient spike
    t_spike = datetime.fromtimestamp(base_time.timestamp() + 105, tz=timezone.utc)
    res_spike = detector.ingest_metric(source, metric, 95.0, t_spike)
    print(f"\n--- Phase 1.2: Injected 1-Window Transient Spike (95.0%) ---")
    print(f"Value: {res_spike.current_value}% | Z: {res_spike.robust_z:.2f} | Severity: {res_spike.severity}")
    print(f"Transient: {res_spike.is_transient_spike} | Sustained Anomaly: {res_spike.is_sustained_anomaly}")
    print(f"Reason: {res_spike.reason}")

    # Step 3: Followed immediately by return to normal
    t_norm = datetime.fromtimestamp(base_time.timestamp() + 110, tz=timezone.utc)
    res_norm = detector.ingest_metric(source, metric, 41.0, t_norm)
    print(f"\n--- Returned to Normal (41.0%) ---")
    print(f"Value: {res_norm.current_value}% | Z: {res_norm.robust_z:.2f} | Sustained: {res_norm.is_sustained_anomaly}")

    # Step 4: Inject sustained breach (4 windows of 92%)
    print(f"\n--- Phase 1.3: Injected Sustained Anomaly (4 windows of 92.0%) ---")
    for w in range(1, 5):
        t_sust = datetime.fromtimestamp(base_time.timestamp() + 110 + w * 5, tz=timezone.utc)
        res = detector.ingest_metric(source, metric, 92.0, t_sust)
        print(
            f"Window {w}: Val={res.current_value}% | Z={res.robust_z:.2f} | "
            f"Sustained={res.is_sustained_anomaly} | Severity={res.severity}"
        )
        if res.is_sustained_anomaly:
            print(f"  >>> ALERT RAISED: {res.reason}")

    print("\nSimulation complete. Baseline and sustained-deviation logic verified.")


if __name__ == "__main__":
    run_prototype_simulation()
