"""Unit tests for EpisodicReplayBuffer and ElasticWeightConsolidation."""
import pytest
import torch
from torch.utils.data import DataLoader, TensorDataset

from models.flow_world_model import FlowWorldModel
from training.episodic_replay import EpisodicReplayBuffer, ElasticWeightConsolidation


def test_episodic_replay_buffer():
    buffer = EpisodicReplayBuffer(max_size_per_stage=5)

    # Add exemplars for stage 1 (Initial Access) and stage 8 (Lateral Movement)
    for _ in range(10):
        x = torch.randn(5, 8)
        future = torch.randn(2, 8)
        stage = torch.tensor([1, 1])
        mal = torch.tensor([1.0, 1.0])
        buffer.add(x, future, stage, mal)

    for _ in range(10):
        x = torch.randn(5, 8)
        future = torch.randn(2, 8)
        stage = torch.tensor([8, 8])
        mal = torch.tensor([1.0, 1.0])
        buffer.add(x, future, stage, mal)

    # Max size per stage is 5, so total buffer size should be 10
    assert len(buffer) == 10
    assert len(buffer.stage_buckets[1]) == 5
    assert len(buffer.stage_buckets[8]) == 5

    # Sample batch
    batch = buffer.sample_batch(batch_size=6)
    assert batch is not None
    xs, futures, stages, mals = batch
    assert xs.shape == (6, 5, 8)
    assert futures.shape == (6, 2, 8)
    assert stages.shape == (6, 2)
    assert mals.shape == (6, 2)


def test_elastic_weight_consolidation():
    model = FlowWorldModel(feature_dim=8, d_model=16, nhead=2, num_layers=1, context_window=4, horizon=2, n_branches=2)
    ewc = ElasticWeightConsolidation(model, ewc_lambda=100.0)

    # Synthetic loader
    xs = torch.randn(8, 4, 8)
    futures = torch.randn(8, 2, 8)
    stages = torch.randint(0, 5, (8, 2))
    mals = torch.randint(0, 2, (8, 2)).float()
    dataset = TensorDataset(xs, futures, stages, mals)
    loader = DataLoader(dataset, batch_size=4)

    ewc.compute_fisher(loader, device=torch.device("cpu"), num_batches=2)

    # Penalty on unchanged model should be 0.0
    initial_penalty = ewc.penalty(model)
    assert initial_penalty.item() == pytest.approx(0.0, abs=1e-5)

    # Perturb weights: penalty must strictly increase
    with torch.no_grad():
        for param in model.parameters():
            param.add_(0.05)

    perturbed_penalty = ewc.penalty(model)
    assert perturbed_penalty.item() > 0.0
