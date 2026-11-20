"""
VeilOps AIOps Phase 2 - Multi-Factor Root Cause Ranking Engine

Formula:
S(c) = w_onset * S_onset(c) + w_topo * S_topo(c) + w_blast * S_blast(c)
where:
- w_onset = 0.40 (Causes precede effects: earlier onset receives higher score)
- w_topo  = 0.35 (Topological position: upstream nodes explain downstream alerts)
- w_blast = 0.25 (Blast radius: fraction of total incident alerts explained)
"""

from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from .schemas import (
    MetricAlert,
    LikelyCause,
    AlternativeElimination,
)
from .correlate import TopologyGraph


class CauseRanker:
    """
    Ranks candidate components to pinpoint root causes and generate
    counterfactual elimination evidence.
    """

    def __init__(
        self,
        topology: TopologyGraph,
        w_onset: float = 0.40,
        w_topo: float = 0.35,
        w_blast: float = 0.25,
    ):
        self.topology = topology
        self.w_onset = w_onset
        self.w_topo = w_topo
        self.w_blast = w_blast

    def rank_causes(
        self, alerts: List[MetricAlert], affected_components: List[str]
    ) -> Tuple[LikelyCause, List[AlternativeElimination], float]:
        """
        Ranks all candidate components in affected_components.
        Returns:
            (LikelyCause, List[AlternativeElimination], confidence_score)
        """
        if not affected_components:
            raise ValueError("Cannot rank causes for empty component list")

        if len(affected_components) == 1:
            comp = affected_components[0]
            cause = LikelyCause(
                component_id=comp,
                confidence_score=0.95,
                reasoning=f"Sole affected component with {len(alerts)} alerts.",
            )
            return cause, [], 0.95

        # 1. Compute component earliest onset times
        comp_onsets: Dict[str, datetime] = {}
        comp_alerts: Dict[str, List[MetricAlert]] = {c: [] for c in affected_components}

        for a in alerts:
            if a.component_id in comp_alerts:
                comp_alerts[a.component_id].append(a)
                if a.component_id not in comp_onsets or a.onset_time_utc < comp_onsets[a.component_id]:
                    comp_onsets[a.component_id] = a.onset_time_utc

        min_time = min(comp_onsets.values())
        max_time = max(comp_onsets.values())
        time_span = (max_time - min_time).total_seconds()

        # 2. Score each candidate
        total_alerts = len(alerts)
        candidate_scores: Dict[str, Dict[str, float]] = {}

        for c in affected_components:
            # Onset score: earlier onset = higher score (causes precede effects)
            if time_span > 0:
                elapsed = (comp_onsets[c] - min_time).total_seconds()
                s_onset = max(0.0, 1.0 - (elapsed / time_span))
            else:
                s_onset = 1.0

            # Topology score: how many downstream affected nodes does c reach?
            downstream = self.topology.get_downstream_nodes(c)
            downstream_affected = downstream.intersection(set(affected_components))
            s_topo = (len(downstream_affected) + 1.0) / len(affected_components)

            # Blast radius score: fraction of alerts on this component + downstream
            reachable_nodes = downstream.union({c})
            explained_alerts = sum(
                1 for a in alerts if a.component_id in reachable_nodes
            )
            s_blast = explained_alerts / total_alerts

            # Weighted composite score
            composite = (
                self.w_onset * s_onset
                + self.w_topo * s_topo
                + self.w_blast * s_blast
            )

            candidate_scores[c] = {
                "composite": composite,
                "s_onset": s_onset,
                "s_topo": s_topo,
                "s_blast": s_blast,
                "explained_alerts": explained_alerts,
                "onset_delay_s": (comp_onsets[c] - min_time).total_seconds(),
            }

        # 3. Sort candidates by composite score descending
        ranked = sorted(
            candidate_scores.items(), key=lambda kv: kv[1]["composite"], reverse=True
        )

        winner_id, winner_stats = ranked[0]
        winner_confidence = round(min(0.99, max(0.60, winner_stats["composite"])), 2)

        winner_reasoning = (
            f"Earliest onset ({comp_onsets[winner_id].strftime('%H:%M:%SZ')}), "
            f"upstream in topology explaining {winner_stats['explained_alerts']} of {total_alerts} alerts "
            f"(composite score: {winner_stats['composite']:.2f})."
        )

        likely_cause = LikelyCause(
            component_id=winner_id,
            confidence_score=winner_confidence,
            reasoning=winner_reasoning,
        )

        # 4. Generate counterfactual elimination reasons for all other candidates
        alternatives: List[AlternativeElimination] = []
        for cand_id, stats in ranked[1:]:
            delay_s = int(stats["onset_delay_s"])
            reasons = []
            if delay_s > 0:
                reasons.append(f"onset occurred {delay_s}s after root cause")
            if stats["s_topo"] < winner_stats["s_topo"]:
                reasons.append("downstream of root cause in topology")
            if stats["explained_alerts"] < winner_stats["explained_alerts"]:
                reasons.append(f"explains only {stats['explained_alerts']} of {total_alerts} alerts")

            reason_str = "; ".join(reasons) if reasons else "lower composite score"
            alternatives.append(
                AlternativeElimination(
                    candidate_id=cand_id,
                    elimination_reason=f"{cand_id}: {reason_str}.",
                )
            )

        return likely_cause, alternatives, winner_confidence
