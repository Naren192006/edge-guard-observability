"""
VeilOps AIOps Phase 2 - Advanced Baselines & Anomaly Detection

Features:
1. Seasonal hour-of-week profile (168 bins: 7 days x 24 hours).
2. EWMA-tracked median and MAD (Median Absolute Deviation) to prevent outlier poisoning.
3. Robust z-score computation using 1.4826 * MAD consistency scaling.
4. Sustained-deviation rule (z > 3.5 for at least 3 of last 5 windows).
5. Joint multi-signal anomaly model using River Half-Space Trees (HSTrees),
   which detects multidimensional covariance shifts that univariate z-scores miss.
"""

from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
import math

try:
    from river.anomaly import HalfSpaceTrees
    RIVER_AVAILABLE = True
except ImportError:
    RIVER_AVAILABLE = False


class SeasonalEWMABaseline:
    """
    Tracks robust statistical baselines partitioned by (source, metric, hour_of_week).
    Updates streaming median and MAD with exponential decay to guard against poisoning.
    """

    def __init__(self, alpha: float = 0.1, min_mad: float = 0.5):
        self.alpha = alpha
        self.min_mad = min_mad
        # (source, metric, hour_of_week) -> {"median": float, "mad": float, "count": float}
        self.baselines: Dict[Tuple[str, str, int], Dict[str, float]] = {}

    @staticmethod
    def get_hour_of_week(dt: datetime) -> int:
        dt_utc = dt.astimezone(timezone.utc) if dt.tzinfo else dt
        return dt_utc.weekday() * 24 + dt_utc.hour

    def update_and_score(
        self, source: str, metric: str, value: float, timestamp: datetime
    ) -> Tuple[float, float, float]:
        """
        Calculates robust z-score and updates baseline.
        Robust Z = (value - median) / (1.4826 * MAD)
        """
        slot = self.get_hour_of_week(timestamp)
        key = (source, metric, slot)

        if key not in self.baselines:
            self.baselines[key] = {
                "median": float(value),
                "mad": float(self.min_mad),
                "count": 1.0,
            }
            return float(value), float(self.min_mad), 0.0

        entry = self.baselines[key]
        current_median = entry["median"]
        current_mad = entry["mad"]

        effective_mad = max(current_mad, self.min_mad)
        robust_z = (value - current_median) / (1.4826 * effective_mad)

        # Winsorized weight: extreme outliers (|z| > 4.0) do not poison baseline
        weight = self.alpha if abs(robust_z) <= 4.0 else (self.alpha * 0.05)

        new_median = (1.0 - weight) * current_median + weight * value
        new_mad = (1.0 - weight) * current_mad + weight * abs(value - current_median)

        entry["median"] = new_median
        entry["mad"] = max(new_mad, self.min_mad)
        entry["count"] += 1.0

        return current_median, effective_mad, robust_z


class SustainedDeviationDetector:
    """
    Evaluates whether an anomaly is sustained (at least 3 breaches in last 5 windows).
    Filters out batch jobs, quick restarts, and momentary hiccups.
    """

    def __init__(
        self,
        z_threshold: float = 3.5,
        window_size: int = 5,
        min_breach_count: int = 3,
        baseline_engine: Optional[SeasonalEWMABaseline] = None,
    ):
        self.z_threshold = z_threshold
        self.window_size = window_size
        self.min_breach_count = min_breach_count
        self.baseline_engine = baseline_engine or SeasonalEWMABaseline()
        self.history: Dict[Tuple[str, str], deque] = {}

    def ingest(
        self, source: str, metric: str, value: float, timestamp: datetime
    ) -> Dict[str, Any]:
        median, mad, z = self.baseline_engine.update_and_score(
            source, metric, value, timestamp
        )

        key = (source, metric)
        if key not in self.history:
            self.history[key] = deque(maxlen=self.window_size)

        self.history[key].append(z)
        breaches = sum(1 for s in self.history[key] if abs(s) >= self.z_threshold)

        is_transient = (abs(z) >= self.z_threshold) and (breaches < self.min_breach_count)
        is_sustained = breaches >= self.min_breach_count

        return {
            "source": source,
            "metric": metric,
            "timestamp": timestamp,
            "value": value,
            "median": median,
            "mad": mad,
            "robust_z": z,
            "breach_count": breaches,
            "is_transient": is_transient,
            "is_sustained": is_sustained,
            "severity": "critical" if abs(z) >= 5.0 and is_sustained else ("warning" if is_sustained else ("info" if is_transient else "normal")),
        }

    def ingest_metric(self, source: str, metric: str, value: float, timestamp: datetime):
        return self.ingest(source, metric, value, timestamp)


class JointMultiSignalHSTrees:
    """
    Streaming Half-Space Trees model for joint multi-signal anomaly detection.
    
    Complements univariate Robust Z-Score:
    - Univariate z-scores inspect single metrics in isolation.
    - HSTrees inspects the joint feature subspace:
      e.g. CPU = 72% (normal), Memory = 75% (normal), Latency = +50ms (normal)
      independently look fine, but CO-OCCURRING together they represent a systemic degradation.
    """

    def __init__(
        self,
        n_trees: int = 25,
        height: int = 8,
        window_size: int = 100,
        limits: Optional[Dict[str, Tuple[float, float]]] = None,
    ):
        self.window_size = window_size
        self.limits = limits or {
            "cpu_pct": (0.0, 100.0),
            "memory_pct": (0.0, 100.0),
            "latency_ms": (0.0, 1000.0),
            "packet_loss_pct": (0.0, 100.0),
        }
        self.sample_count = 0
        if RIVER_AVAILABLE:
            self.model = HalfSpaceTrees(
                n_trees=n_trees,
                height=height,
                window_size=window_size,
                limits=self.limits,
                seed=42,
            )
        else:
            self.model = None

    def learn_and_score(self, feature_dict: Dict[str, float]) -> float:
        """
        Updates the online model with the multi-metric vector and returns anomaly score [0.0, 1.0].
        Scores above 0.65 represent multi-signal anomalous correlation.
        """
        self.sample_count += 1
        # Clamp features to specified limits
        bounded = {}
        for k, (low, high) in self.limits.items():
            val = float(feature_dict.get(k, low))
            bounded[k] = max(low, min(high, val))

        if self.model is not None:
            score = self.model.score_one(bounded)
            self.model.learn_one(bounded)
            return float(score)

        # Fallback multi-signal heuristic if river is not available
        normalized_sum = sum(
            (bounded[k] - low) / (high - low + 1e-6) for k, (low, high) in self.limits.items()
        )
        return min(1.0, normalized_sum / len(self.limits))
