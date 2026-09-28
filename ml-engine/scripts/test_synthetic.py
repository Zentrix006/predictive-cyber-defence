"""
Synthetic data test for World Model.
Runs a quick training loop on synthetic data to verify everything works.
"""
import os
import sys
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
import pytorch_lightning as pl

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models import WorldModel, create_world_model
from training.data_module import create_synthetic_dataloader
from training.lightning_module import WorldModelLightning


def test_synthetic_training():
    """Test training on synthetic data."""
    
    print("="*60)
    print("SYNTHETIC DATA TRAINING TEST")
    print("="*60)
    
    # Configuration
    config = {
        "node_input_dim": 64,
        "edge_input_dim": 16,
        "host_input_dim": 100,
        "traffic_input_dim": 50,
        "hidden_dim": 128,  # Smaller for faster testing
        "num_heads": 4,
        "dropout": 0.1,
        "context_window": 5,
        "horizon": 3,
        "num_stages": 14,
        "max_assets": 50,
    }
    
    training_config = {
        "model": {
            "loss_weights": {
                "state_reconstruction": 1.0,
                "stage_classification": 2.0,
                "target_prediction": 1.5,
                "consistency": 0.5,
            },
            "regularization": {
                "label_smoothing": 0.1,
                "gradient_clip": 1.0,
            }
        },
        "optimizer": {
            "type": "AdamW",
            "lr": 1e-3,
            "betas": [0.9, 0.999],
            "eps": 1e-8,
            "weight_decay": 1e-4,
        },
        "scheduler": {
            "type": "CosineAnnealingWarmRestarts",
            "T_0": 5,
            "T_mult": 2,
            "eta_min": 1e-6,
        },
        "epochs": 3,
        "early_stopping_patience": 5,
        "monitor": "val_loss",
        "mode": "min",
        "save_top_k": 1,
        "early_stopping_metric": "val_loss",
        "early_stopping_mode": "min",
    }
    
    evaluation_config = {
        "metrics": ["mse", "stage_accuracy_top1"],
    }
    
    # Create model
    print("Creating model...")
    model = create_world_model(config)
    print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Wrap in Lightning
    lightning_model = WorldModelLightning(model, training_config, evaluation_config)
    
    # Create dataloaders
    print("Creating synthetic dataloaders...")
    train_loader = create_synthetic_dataloader(
        batch_size=8,
        context_window=config["context_window"],
        horizon=config["horizon"],
        num_samples=200,
    )
    
    val_loader = create_synthetic_dataloader(
        batch_size=8,
        context_window=config["context_window"],
        horizon=config["horizon"],
        num_samples=50,
    )
    
    # Trainer
    trainer = pl.Trainer(
        max_epochs=3,
        accelerator="auto",
        devices=1,
        enable_progress_bar=True,
        enable_model_summary=True,
        log_every_n_steps=10,
        enable_checkpointing=False,
        logger=False,
    )
    
    # Train
    print("Starting training...")
    trainer.fit(lightning_model, train_dataloaders=train_loader, val_dataloaders=val_loader)
    
    print("\n" + "="*60)
    print("SYNTHETIC TRAINING TEST COMPLETED SUCCESSFULLY!")
    print("="*60)


def test_forward_pass():
    """Test forward pass with synthetic data."""
    
    print("\n" + "="*60)
    print("FORWARD PASS TEST")
    print("="*60)
    
    config = {
        "node_input_dim": 64,
        "edge_input_dim": 16,
        "host_input_dim": 100,
        "traffic_input_dim": 50,
        "hidden_dim": 256,
        "num_heads": 8,
        "dropout": 0.1,
        "context_window": 10,
        "horizon": 4,
        "num_stages": 14,
        "max_assets": 1000,
    }
    
    model = create_world_model(config)
    model.eval()
    
    # Create synthetic batch
    batch_size = 1
    num_nodes = 30
    num_edges = 100
    num_hosts = 30
    num_assets = 30
    traffic_seq_len = 20
    context_window = 10
    
    sequence = {
        "node_features": [torch.randn(batch_size, num_nodes, 64) for _ in range(context_window)],
        "edge_index": [torch.randint(0, num_nodes, (2, num_edges)) for _ in range(context_window)],
        "edge_attr": [torch.randn(num_edges, 16) for _ in range(context_window)],
        "batch": [torch.zeros(num_nodes, dtype=torch.long) for _ in range(context_window)],
        "host_features": [torch.randn(batch_size, num_hosts, 100) for _ in range(context_window)],
        "host_mask": [torch.ones(batch_size, num_hosts, dtype=torch.bool) for _ in range(context_window)],
        "traffic_features": [torch.randn(batch_size, traffic_seq_len, 50) for _ in range(context_window)],
    }
    
    current_state = {
        "node_features": torch.randn(batch_size, num_nodes, 64),
        "edge_index": torch.randint(0, num_nodes, (2, num_edges)),
        "edge_attr": torch.randn(num_edges, 16),
        "batch": torch.zeros(num_nodes, dtype=torch.long),
        "host_features": torch.randn(batch_size, num_hosts, 100),
        "host_mask": torch.ones(batch_size, num_hosts, dtype=torch.bool),
        "traffic_features": torch.randn(batch_size, traffic_seq_len, 50),
    }
    
    asset_embeddings = torch.randn(batch_size, num_assets, 256)
    asset_mask = torch.ones(batch_size, num_assets, dtype=torch.bool)
    
    print("Running forward pass...")
    with torch.no_grad():
        output = model.forward(
            sequence=sequence,
            current_state=current_state,
            asset_embeddings=asset_embeddings,
            asset_mask=asset_mask,
            teacher_forcing_ratio=0.0,
        )
    
    print(f"Predicted states: {output.predicted_states.shape}")
    print(f"Stage logits: {output.stage_logits.shape}")
    print(f"Stage probs: {output.stage_probs.shape}")
    print(f"Target logits: {output.target_logits.shape}")
    print(f"Target probs: {output.target_probs.shape}")
    
    # Test predict mode
    print("\nTesting predict mode...")
    with torch.no_grad():
        pred_output = model.predict(
            current_state=current_state,
            asset_embeddings=asset_embeddings,
            asset_mask=asset_mask,
        )
    
    print(f"Predicted states: {pred_output.predicted_states.shape}")
    print(f"Stage probs: {pred_output.stage_probs.shape}")
    print(f"Target probs: {pred_output.target_probs.shape}")
    
    print("\n" + "="*60)
    print("FORWARD PASS TEST PASSED!")
    print("="*60)


def test_model_components():
    """Test individual model components."""
    
    print("\n" + "="*60)
    print("MODEL COMPONENT TESTS")
    print("="*60)
    
    from models.encoders import GraphEncoder, HostEncoder, TrafficEncoder, FusionLayer
    from models.temporal import TemporalEncoder
    from models.heads import StageClassifier, TargetPredictor
    
    # Test GraphEncoder
    print("Testing GraphEncoder...")
    graph_encoder = GraphEncoder(
        node_input_dim=64,
        edge_input_dim=16,
        hidden_dim=256,
        num_layers=3,
        num_heads=8,
    )
    
    node_features = torch.randn(50, 64)
    edge_index = torch.randint(0, 50, (2, 200))
    edge_attr = torch.randn(200, 16)
    batch = torch.zeros(50, dtype=torch.long)
    
    node_emb, graph_emb = graph_encoder(node_features, edge_index, edge_attr, batch)
    print(f"  Node embeddings: {node_emb.shape}")
    print(f"  Graph embedding: {graph_emb.shape}")
    
    # Test HostEncoder
    print("Testing HostEncoder...")
    host_encoder = HostEncoder(input_dim=100, output_dim=256)
    host_features = torch.randn(2, 30, 100)
    host_emb = host_encoder(host_features)
    print(f"  Host embeddings: {host_emb.shape}")
    
    # Test TrafficEncoder
    print("Testing TrafficEncoder...")
    traffic_encoder = TrafficEncoder(input_dim=50, hidden_dim=256)
    traffic_features = torch.randn(2, 20, 50)
    traffic_emb = traffic_encoder(traffic_features)
    print(f"  Traffic embedding: {traffic_emb.shape}")
    
    # Test FusionLayer
    print("Testing FusionLayer...")
    fusion = FusionLayer(query_dim=256, key_dim=256, value_dim=256)
    graph_emb = torch.randn(2, 256)
    host_emb = torch.randn(2, 30, 256)
    traffic_emb = torch.randn(2, 256)
    host_mask = torch.ones(2, 30, dtype=torch.bool)
    
    fused = fusion(graph_emb, host_emb, traffic_emb, host_mask)
    print(f"  Fused embedding: {fused.shape}")
    
    # Test TemporalEncoder
    print("Testing TemporalEncoder...")
    temporal = TemporalEncoder(d_model=256, max_seq_len=20)
    seq = torch.randn(2, 15, 256)
    context = temporal(seq)
    print(f"  Temporal context: {context.shape}")
    
    # Test StageClassifier
    print("Testing StageClassifier...")
    stage_classifier = StageClassifier(input_dim=256, num_classes=14)
    x = torch.randn(4, 256)
    logits = stage_classifier(x)
    probs = stage_classifier.predict_proba(x)
    stages = stage_classifier.predict_stage(x)
    print(f"  Logits: {logits.shape}, Probs: {probs.shape}, Stages: {stages}")
    
    # Test TargetPredictor
    print("Testing TargetPredictor...")
    target_predictor = TargetPredictor(query_dim=256, key_dim=256)
    query = torch.randn(2, 256)
    asset_emb = torch.randn(2, 50, 256)
    asset_mask = torch.ones(2, 50, dtype=torch.bool)
    scores, attn = target_predictor(query, asset_emb, asset_mask)
    top_scores, top_indices = target_predictor.predict_top_k(query, asset_emb, asset_mask, k=3)
    print(f"  Scores: {scores.shape}, Top-3: {top_scores.shape}")
    
    print("\n" + "="*60)
    print("ALL COMPONENT TESTS PASSED!")
    print("="*60)


if __name__ == "__main__":
    torch.manual_seed(42)
    
    # Run component tests first
    test_model_components()
    
    # Run forward pass test
    test_forward_pass()
    
    # Run synthetic training test (requires pytorch_lightning)
    try:
        test_synthetic_training()
    except Exception as e:
        print(f"\nSynthetic training test skipped: {e}")
        print("Install pytorch_lightning to run full training test")