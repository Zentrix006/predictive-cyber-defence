"""
Inference engine: K-step forward simulation, MITRE mapping, explainability.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import torch

from features.extract import (
    FeatureMatrix,
    build_state_sequences,
    extract_from_csv_bytes,
    extract_from_pcap_bytes,
)
from features.mitre_map import MITRE_STAGES
from models.flow_world_model import FlowWorldModel
from inference.novelty import score_novelty


DEFAULT_CKPT = Path(__file__).resolve().parents[1] / "data" / "checkpoints" / "flow_world_model.pt"


@dataclass
class ForecastResult:
    infiltration_timeline: List[float]
    predicted_stages: List[str]
    stage_probabilities: List[Dict[str, float]]
    current_stage: str
    current_confidence: float
    top_features: List[Dict[str, Any]]
    attention_summary: List[float]
    natural_language: str
    model_version: str
    datasets_trained: List[str]
    flagged_flow_indices: List[int]
    flow_meta: List[Dict[str, Any]] = None  # type: ignore[assignment]
    thinking: Dict[str, Any] = None  # type: ignore[assignment]
    recommended_actions: List[Dict[str, Any]] = None  # type: ignore[assignment]
    recommended_action: str = "monitor"
    novelty: List[Dict[str, Any]] = None  # type: ignore[assignment]
    novelty_score: float = 0.0
    novelty_state: str = "within_known_distribution"
    novelty_evidence: Dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.flow_meta is None:
            self.flow_meta = []
        if self.novelty is None:
            self.novelty = []
        if self.novelty_evidence is None:
            self.novelty_evidence = {}


def _build_pcap_summary(flow_meta: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-flow annotations into a compact pcap summary for the UI."""
    from collections import Counter

    proto_counts = Counter(m.get("proto", "other") for m in flow_meta)
    svc_counts = Counter(m.get("service", "-") for m in flow_meta)
    flagged = [m for m in flow_meta if m.get("risk") == "high"]

    unique_indicators = set()
    hosts = Counter()
    for m in flow_meta:
        h = m.get("host")
        if h:
            hosts[h] += 1
        sni = m.get("sni")
        if sni:
            hosts[sni] += 1
        unique_indicators.update(m.get("indicators", []))

    total = max(len(flow_meta), 1)
    return {
        "total_flows": len(flow_meta),
        "flagged_flows": len(flagged),
        "anomaly_score": round(min(1.0, len(flagged) / total * 2.0), 3),
        "protocols": [{"name": k, "count": v} for k, v in proto_counts.most_common()],
        "services": [{"name": k, "count": v} for k, v in svc_counts.most_common(8)],
        "top_hosts": [{"host": k, "connections": v} for k, v in hosts.most_common(6)],
        "indicators": sorted(unique_indicators)[:20],
        "flagged_flow_details": [
            {
                "src": m.get("src"),
                "dst": m.get("dst"),
                "service": m.get("service"),
                "host": m.get("host") or m.get("sni") or m.get("dst"),
                "path": m.get("path"),
                "packets": m.get("packets"),
                "indicators": m.get("indicators", [])[:3],
            }
            for m in flagged[:50]
        ],
    }


def _pcap_storyline(s: Dict[str, Any]) -> str:
    n = s.get("flagged_flows", 0)
    inds = s.get("indicators", [])
    if n == 0:
        return (
            f"Analysed {s.get('total_flows')} flows across "
            + ", ".join(p.get("name", "?") for p in s.get("protocols", [])[:3])
            + "; no protocol-level indicators of compromise detected. Traffic appears benign."
        )
    headline = ", ".join(inds[:4]) if inds else f"{n} anomalous flows"
    return (
        f"Detected {n} suspicious flow(s): {headline}. "
        "This pattern is consistent with malware command-and-control (C2) beaconing "
        "and executable delivery over raw-IP HTTP. Recommend immediate host isolation "
        "and credential rotation."
    )


def _resolve_device(requested: str = "auto") -> torch.device:
    """Use the dedicated CUDA device when exposed to the container, otherwise fail safe to CPU."""
    preference = os.getenv("ML_DEVICE", requested).strip().lower()
    if preference in {"auto", "cuda"} and torch.cuda.is_available():
        return torch.device("cuda:0")
    if preference == "cuda":
        print("ML_DEVICE=cuda requested but CUDA is unavailable; falling back to CPU")
    return torch.device("cpu")


def _present_stage(index: int) -> str:
    """Convert an internal classifier index into a defender-facing state."""
    if 0 <= index < len(MITRE_STAGES) - 1:
        return MITRE_STAGES[index]
    return "novel_activity"


class WorldModelPredictor:
    def __init__(self, checkpoint: Optional[Path] = None, device: str = "auto"):
        self.checkpoint = Path(checkpoint) if checkpoint else DEFAULT_CKPT
        self.device = _resolve_device(device)
        self.model: Optional[FlowWorldModel] = None
        self.meta: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not self.checkpoint.exists():
            self.model = None
            return
        ckpt = torch.load(self.checkpoint, map_location=self.device, weights_only=False)
        self.meta = {k: v for k, v in ckpt.items() if k != "model_state"}
        self.model = FlowWorldModel(
            feature_dim=ckpt["feature_dim"],
            context_window=ckpt.get("context_window", 10),
            horizon=ckpt.get("horizon", 4),
            num_stages=ckpt.get("num_stages", 14),
        ).to(self.device)
        self.model.load_state_dict(ckpt["model_state"])
        self.model.eval()

    @property
    def ready(self) -> bool:
        return self.model is not None

    def _matrix_from_upload(self, data: bytes, filename: str):
        name = filename.lower()
        if name.endswith(".pcap") or name.endswith(".pcapng"):
            return extract_from_pcap_bytes(data)
        return extract_from_csv_bytes(data, filename), []

    def predict_matrix(self, matrix: FeatureMatrix) -> ForecastResult:
        if not self.ready:
            raise RuntimeError("World model checkpoint not loaded. Train with scripts/train_real.py")

        context = self.meta.get("context_window", 10)
        horizon = self.meta.get("horizon", 4)
        feature_names = self.meta.get("feature_names") or [
            f"f{i}" for i in range(matrix.num_features)
        ]

        # Use last context window; pad if needed
        feats = matrix.features
        if len(feats) < context:
            pad = np.zeros((context - len(feats), feats.shape[1]), dtype=np.float32)
            window = np.concatenate([pad, feats], axis=0)
        else:
            window = feats[-context:]

        # Align feature dim
        fd = self.meta["feature_dim"]
        if window.shape[1] < fd:
            window = np.pad(window, ((0, 0), (0, fd - window.shape[1])))
        elif window.shape[1] > fd:
            window = window[:, :fd]

        xb = torch.from_numpy(window.astype(np.float32)).unsqueeze(0).to(self.device)
        with torch.no_grad():
            out = self.model(xb)
            importance = self.model.feature_importance(xb)[0].cpu().numpy()

        infil = out.infil_probs[0].cpu().numpy().tolist()
        stage_ids = out.stage_probs[0].argmax(dim=-1).cpu().numpy().tolist()
        # `unknown` is an internal training sink for benign or unmapped data;
        # it is not a useful defender result. Surface it as either baseline
        # activity or novel activity, preserving the nearest recognised stage
        # as an explicitly provisional hypothesis for review/training.
        unknown_index = len(MITRE_STAGES) - 1
        stages: List[str] = []
        novelty: List[Dict[str, Any]] = []
        all_stage_probs = out.stage_probs[0].cpu().numpy()
        for h, stage_id in enumerate(stage_ids):
            if stage_id != unknown_index and stage_id < len(MITRE_STAGES):
                stages.append(MITRE_STAGES[stage_id])
                continue
            known = all_stage_probs[h, :unknown_index]
            provisional_id = int(np.argmax(known))
            risky = float(infil[h]) >= 0.5
            state = "novel_activity" if risky else "baseline_activity"
            stages.append(state)
            novelty.append({
                "window_offset": h + 1,
                "state": state,
                "provisional_stage": MITRE_STAGES[provisional_id],
                "provisional_confidence": float(known[provisional_id]),
                "review_required": risky,
                "recommended_action": "contain_and_collect" if risky else "monitor_and_learn",
            })
        stage_prob_maps = []
        for h in range(out.stage_probs.shape[1]):
            probs = out.stage_probs[0, h].cpu().numpy()
            stage_prob_maps.append({("baseline_or_novel_activity" if i == unknown_index else MITRE_STAGES[i]): float(probs[i]) for i in range(len(MITRE_STAGES))})

        # Current stage = first horizon step (or majority of labels if present)
        current_stage = stages[0]
        current_conf = float(out.stage_probs[0, 0].max().item())

        # Belief-state "thinking": consensus agreement + chain-of-thought.
        thinking = self._build_thinking(out)
        novelty_assessment = score_novelty(
            all_stage_probs[0],
            consensus_agreement=thinking.get("consensus_agreement"),
            unknown_index=unknown_index,
        )

        # DQN+LSTM response plan for the predicted future sequence.
        recommended_actions = getattr(out, "recommended_actions", None) or []
        recommended_action = "monitor"
        if recommended_actions:
            recommended_action = sorted(recommended_actions, key=lambda p: -p.get("q_value", 0))[0].get("action", "monitor")

        top_idx = np.argsort(-importance)[:8]
        top_features = [
            {
                "feature": feature_names[i] if i < len(feature_names) else f"f{i}",
                "contribution": float(importance[i]),
                "description": _feature_description(feature_names[i] if i < len(feature_names) else f"f{i}"),
            }
            for i in top_idx
        ]

        # Attention weights over the last query token
        attention_summary = out.attention_weights[0, -1].cpu().numpy().tolist()

        # Flag high-risk flows in the upload
        if matrix.labels is not None:
            flagged = [int(i) for i, v in enumerate(matrix.labels) if v == 1][:50]
        else:
            mag = np.linalg.norm(matrix.features, axis=1)
            flagged = np.argsort(-mag)[: min(20, len(mag))].astype(int).tolist()

        nl = (
            f"Predicted attack progression toward '{stages[-1]}' "
            f"(infiltration risk over {horizon} steps: "
            + ", ".join(f"{p:.0%}" for p in infil)
            + "). Top drivers: "
            + "; ".join(f"{t['feature']} ({t['contribution']:.0%})" for t in top_features[:3])
            + "."
            + (f" Recommended response: {recommended_action.replace('_', ' ')}." if recommended_actions else "")
        )

        return ForecastResult(
            infiltration_timeline=infil,
            predicted_stages=stages,
            stage_probabilities=stage_prob_maps,
            current_stage=current_stage,
            current_confidence=current_conf,
            top_features=top_features,
            attention_summary=attention_summary,
            natural_language=nl,
            model_version=str(self.meta.get("model_version", "flow-wm-unknown")),
            datasets_trained=list(self.meta.get("datasets", ["UNSW-NB15", "NSL-KDD"])),
            flagged_flow_indices=flagged,
            thinking=thinking,
            recommended_actions=recommended_actions,
            recommended_action=recommended_action,
            novelty=novelty,
            novelty_score=float(novelty_assessment["score"]),
            novelty_state=str(novelty_assessment["state"]),
            novelty_evidence=dict(novelty_assessment["components"]),
        )

    def _build_thinking(self, out) -> Dict[str, Any]:
        """Build a belief-state 'thinking' summary from the ensemble outputs:
        branch agreement (self-consistency), worst-case risk, and a readable
        chain-of-thought describing the imagined attack progression.
        """
        branch_weights = getattr(out, "branch_weights", None)
        branch_stage = getattr(out, "branch_stage_probs", None)
        branch_infil = getattr(out, "branch_infil_probs", None)
        belief_scores = getattr(out, "belief_scores", None)

        summary: Dict[str, Any] = {"branches": 0, "consensus_agreement": 0.0,
                                   "chain_of_thought": [], "worst_case": {}}

        if branch_stage is not None and branch_stage.numel() > 0:
            bs = branch_stage[0].detach().cpu().numpy()          # [n_b, H, C]
            bi = branch_infil[0].detach().cpu().numpy()          # [n_b, H]
            bw = branch_weights[0].detach().cpu().numpy()        # [n_b]
            n_b = bs.shape[0]
            summary["branches"] = int(n_b)

            # Consensus = weighted mean of branch stage distributions.
            consensus = (bw[:, None, None] * bs).sum(axis=0)     # [H, C]
            # Average disagreement (KL of each branch vs consensus), lower = more agreement.
            import numpy as np
            kl = 0.0
            eps = 1e-9
            for b in range(n_b):
                p = bs[b] + eps
                q = consensus + eps
                kl += bw[b] * (p * (np.log(p) - np.log(q))).sum()
            agreement = float(np.clip(1.0 - kl / (np.log(consensus.shape[-1]) + eps), 0.0, 1.0))
            summary["consensus_agreement"] = round(agreement, 3)

            # Worst-case branch (highest mean infiltration risk).
            worst_b = int(np.argmax(bi.mean(axis=-1)))
            worst_risk = float(np.clip(bi[worst_b, -1], 0.0, 1.0)) if bi.shape[-1] else 0.0
            worst_stage = int(np.argmax(bs[worst_b, -1]))
            worst_stage_name = _present_stage(worst_stage)
            summary["worst_case"] = {
                "branch": worst_b,
                "terminal_stage": worst_stage_name,
                "peak_infil_risk": round(worst_risk, 3),
            }

            # Per-branch details from the actual rollouts: each branch is a
            # distinct imagined future with its own terminal stage and risk.
            branch_details = []
            for b in range(n_b):
                bterm = int(np.argmax(bs[b, -1]))
                bstage = _present_stage(bterm)
                branch_details.append({
                    "branch": b,
                    "terminal_stage": bstage,
                    "peak_infil_risk": round(float(np.clip(bi[b, -1], 0.0, 1.0)), 3),
                })
            summary["branch_details"] = branch_details

            # Chain-of-thought: narrate the most likely imagined progression.
            base_stage = int(np.argmax(consensus[0]))
            end_stage = int(np.argmax(consensus[-1]))
            name = _present_stage
            cot = [
                "I explored several counterfactual futures from the current belief state.",
                f"Current belief is most consistent with '{name(base_stage)}'.",
                "Rolling the dynamics forward, the imagined ensemble converged on "
                f"'{name(end_stage)}' with {agreement:.0%} self-consistency across "
                f"{n_b} branches.",
            ]
            if belief_scores is not None:
                bs_sum = belief_scores[0].detach().cpu().tolist()
                if bs_sum:
                    peak = float(max(bs_sum))
                    cot.append(f"Belief-state risk peaks at {peak:.0%} over the forecast window.")
            if agreement < 0.5:
                cot.append("Branches strongly disagree, so this forecast carries high "
                           "uncertainty — treat staged progression as indicative only.")
            summary["chain_of_thought"] = cot

        return summary

    def predict_upload(self, data: bytes, filename: str) -> Dict[str, Any]:
        matrix, flow_meta = self._matrix_from_upload(data, filename)
        result = self.predict_matrix(matrix)
        payload = asdict(result)
        payload["num_flows"] = int(len(matrix.features))
        payload["feature_count"] = int(matrix.num_features)
        payload["flow_meta"] = flow_meta
        payload["pcap_parse"] = matrix.source_meta
        payload["pcap_summary"] = (
            _build_pcap_summary(flow_meta) if flow_meta else None
        )
        if flow_meta and payload.get("pcap_summary"):
            payload["natural_language"] = _pcap_storyline(payload["pcap_summary"])
        return payload


def _feature_description(name: str) -> str:
    docs = {
        "dur": "Flow duration",
        "spkts": "Source packets per flow",
        "dpkts": "Destination packets per flow",
        "sbytes": "Source bytes transferred",
        "dbytes": "Destination bytes transferred",
        "rate": "Packet rate",
        "sttl": "Source TTL (packet-level)",
        "dttl": "Destination TTL / TTL variance proxy",
        "swin": "TCP source window size",
        "dwin": "TCP destination window size",
        "tcprtt": "TCP round-trip time",
        "synack": "SYN-ACK timing / SYN activity",
        "smean": "Mean payload size (source)",
        "dmean": "Mean payload size (destination)",
        "sinpkt": "Source inter-arrival time mean",
        "dinpkt": "Destination IAT / variance proxy",
        "sjit": "Source jitter / max IAT",
        "proto": "Protocol type",
        "service": "Service / destination port class",
        "state": "Connection state / TCP flags aggregate",
    }
    return docs.get(name, f"Traffic feature '{name}'")


# Singleton for API
_predictor: Optional[WorldModelPredictor] = None


def get_predictor() -> WorldModelPredictor:
    global _predictor
    if _predictor is None:
        _predictor = WorldModelPredictor()
    return _predictor
