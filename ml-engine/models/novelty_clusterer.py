"""Online Semantic Novelty Clustering Engine.

Aggregates unlabelled novel network events into coherent behavioral proto-clusters
and generates natural-language proto-signatures for SOC triaging.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import numpy as np


@dataclass
class ProtoCluster:
    cluster_id: str
    centroid: np.ndarray
    feature_mean: np.ndarray
    sample_count: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    top_deviations: List[Dict[str, Any]] = field(default_factory=list)
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "sample_count": self.sample_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "signature": self.signature,
            "top_deviations": self.top_deviations,
        }


class OnlineNoveltyClusterer:
    """Online clustering of novel network behaviors in world model latent space."""

    def __init__(
        self,
        distance_threshold: float = 1.8,
        max_clusters: int = 50,
        feature_names: Optional[List[str]] = None,
    ):
        self.distance_threshold = distance_threshold
        self.max_clusters = max_clusters
        self.feature_names = feature_names or []
        self.clusters: List[ProtoCluster] = []

    def assign_or_create(
        self,
        latent_embedding: np.ndarray,
        raw_features: np.ndarray,
        baseline_mean: Optional[np.ndarray] = None,
    ) -> ProtoCluster:
        """Assign novel sample to the nearest proto-cluster or instantiate a new one."""
        emb = np.asarray(latent_embedding, dtype=np.float32).flatten()
        feats = np.asarray(raw_features, dtype=np.float32).flatten()

        best_cluster = None
        min_dist = float("inf")

        for cluster in self.clusters:
            dist = float(np.linalg.norm(cluster.centroid - emb))
            if dist < min_dist:
                min_dist = dist
                best_cluster = cluster

        now = time.time()

        if best_cluster is not None and min_dist <= self.distance_threshold:
            # Update existing cluster online
            n = best_cluster.sample_count
            best_cluster.centroid = (best_cluster.centroid * n + emb) / (n + 1)
            best_cluster.feature_mean = (best_cluster.feature_mean * n + feats) / (n + 1)
            best_cluster.sample_count += 1
            best_cluster.last_seen = now
            best_cluster.signature = self._generate_signature(best_cluster, baseline_mean)
            return best_cluster

        # Create new proto-cluster
        cluster_idx = len(self.clusters) + 1
        new_cluster = ProtoCluster(
            cluster_id=f"proto_cluster_{cluster_idx}",
            centroid=emb.copy(),
            feature_mean=feats.copy(),
            sample_count=1,
            first_seen=now,
            last_seen=now,
        )
        new_cluster.signature = self._generate_signature(new_cluster, baseline_mean)

        if len(self.clusters) >= self.max_clusters:
            # Prune oldest cluster with smallest support
            self.clusters.sort(key=lambda c: (c.sample_count, c.last_seen))
            self.clusters.pop(0)

        self.clusters.append(new_cluster)
        return new_cluster

    def _generate_signature(
        self,
        cluster: ProtoCluster,
        baseline_mean: Optional[np.ndarray] = None,
    ) -> str:
        """Synthesize explainable proto-signature highlighting most distinctive dimensions."""
        if baseline_mean is None or len(baseline_mean) != len(cluster.feature_mean):
            return f"Emerging behavioral pattern ({cluster.sample_count} instances observed)"

        diff = cluster.feature_mean - baseline_mean
        abs_diff = np.abs(diff)
        top_idx = np.argsort(abs_diff)[::-1][:3]

        deviations = []
        traits = []
        for idx in top_idx:
            fname = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
            direction = "elevated" if diff[idx] > 0 else "suppressed"
            mag = float(abs_diff[idx])
            deviations.append({"feature": fname, "direction": direction, "magnitude": round(mag, 3)})
            traits.append(f"{direction} {fname}")

        cluster.top_deviations = deviations
        return f"Proto-Signature: {', '.join(traits)} ({cluster.sample_count} events)"

    def get_active_clusters(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in sorted(self.clusters, key=lambda x: x.sample_count, reverse=True)]
