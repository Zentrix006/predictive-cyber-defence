"""Episodic Replay Buffer and Elastic Weight Consolidation (EWC) for Continual Learning.

Prevents catastrophic forgetting when retraining world models on newly identified
network behaviors and analyst feedback.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple
import random
import torch
import torch.nn as nn
from torch.utils.data import Dataset


class EpisodicReplayBuffer(Dataset):
    """
    Class-balanced reservoir replay buffer preserving historical attack exemplars.
    """

    def __init__(self, max_size_per_stage: int = 250):
        self.max_size_per_stage = max_size_per_stage
        # stage_id -> list of (x, future, stage, malicious) tuples
        self.stage_buckets: Dict[int, List[Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]]] = {}

    def add(
        self,
        x: torch.Tensor,
        future: torch.Tensor,
        stage: torch.Tensor,
        malicious: torch.Tensor,
    ) -> None:
        """Add an exemplar using reservoir sampling per primary stage."""
        stage_key = int(stage[0].item()) if stage.ndim > 0 else int(stage.item())
        if stage_key not in self.stage_buckets:
            self.stage_buckets[stage_key] = []

        bucket = self.stage_buckets[stage_key]
        item = (x.detach().cpu(), future.detach().cpu(), stage.detach().cpu(), malicious.detach().cpu())

        if len(bucket) < self.max_size_per_stage:
            bucket.append(item)
        else:
            idx = random.randint(0, len(bucket) - 1)
            bucket[idx] = item

    def sample_batch(self, batch_size: int = 32) -> Optional[Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]]:
        """Sample a balanced batch across all available stages."""
        if not self.stage_buckets:
            return None

        samples = []
        stages = list(self.stage_buckets.keys())
        per_stage = max(1, batch_size // len(stages))

        for s in stages:
            bucket = self.stage_buckets[s]
            k = min(len(bucket), per_stage)
            samples.extend(random.sample(bucket, k))

        if not samples:
            return None

        # Pad or truncate to batch_size
        while len(samples) < batch_size:
            s = random.choice(stages)
            samples.append(random.choice(self.stage_buckets[s]))
        samples = samples[:batch_size]

        xs = torch.stack([s[0] for s in samples])
        futures = torch.stack([s[1] for s in samples])
        stages_t = torch.stack([s[2] for s in samples])
        mals = torch.stack([s[3] for s in samples])
        return xs, futures, stages_t, mals

    def __len__(self) -> int:
        return sum(len(b) for b in self.stage_buckets.values())

    def __getitem__(self, idx: int):
        # Flattened indexing across buckets
        curr = 0
        for b in self.stage_buckets.values():
            if idx < curr + len(b):
                return b[idx - curr]
            curr += len(b)
        raise IndexError("Index out of bounds")


class ElasticWeightConsolidation:
    """
    Elastic Weight Consolidation (EWC) penalty calculator.

    Computes empirical Fisher Information Matrix on reference model to constrain
    weight updates on parameters critical for known attack stages.
    """

    def __init__(self, model: nn.Module, ewc_lambda: float = 400.0):
        self.model = model
        self.ewc_lambda = ewc_lambda
        self.reference_params: Dict[str, torch.Tensor] = {}
        self.fisher_diagonal: Dict[str, torch.Tensor] = {}

        # Snapshot serving reference parameters
        for name, param in model.named_parameters():
            if param.requires_grad:
                self.reference_params[name] = param.detach().clone()
                self.fisher_diagonal[name] = torch.zeros_like(param)

    def compute_fisher(self, dataloader, device: torch.device, num_batches: int = 10) -> None:
        """Estimate the diagonal Fisher information over a representative batch subset."""
        self.model.eval()
        for name in self.fisher_diagonal:
            self.fisher_diagonal[name].zero_()

        batches_processed = 0
        for batch in dataloader:
            if batches_processed >= num_batches:
                break
            x, future, stage, mal = [v.to(device) for v in batch]
            self.model.zero_grad()
            out = self.model(x)

            # Stage log-likelihood surrogate
            valid_mask = stage >= 0
            if valid_mask.any():
                log_probs = torch.log_softmax(out.stage_logits[valid_mask], dim=-1)
                loss = -log_probs.mean()
            else:
                loss = nn.functional.mse_loss(out.future_states, future)

            loss.backward()

            for name, param in self.model.named_parameters():
                if param.grad is not None and name in self.fisher_diagonal:
                    self.fisher_diagonal[name] += (param.grad.detach() ** 2)

            batches_processed += 1

        if batches_processed > 0:
            for name in self.fisher_diagonal:
                self.fisher_diagonal[name] /= float(batches_processed)

    def penalty(self, current_model: nn.Module) -> torch.Tensor:
        """Compute the quadratic EWC regularization loss."""
        loss = torch.tensor(0.0, device=next(current_model.parameters()).device)
        for name, param in current_model.named_parameters():
            if name in self.reference_params and name in self.fisher_diagonal:
                ref = self.reference_params[name].to(param.device)
                fisher = self.fisher_diagonal[name].to(param.device)
                loss += (fisher * (param - ref) ** 2).sum()
        return (self.ewc_lambda / 2.0) * loss
