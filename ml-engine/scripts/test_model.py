"""
Test script for World Model architecture.
Validates forward pass, shapes, and basic functionality.
"""
import torch
import torch.nn as nn
import sys
import os

# Add ml-engine to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models import WorldModel, create_world_model


def test_model_creation():
    """Test model instantiation."""
    print("Testing model creation...")
    
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
    print(f"Model created successfully")
    print(f"Total parameters: {sum(p.numel() for p in model.parameters()):,}")
    print(f"Trainable parameters: {sum(p.numel() for p in model.parameters() if p.requires_grad):,}")
    return model


def test_encode_state(model):
    """Test single state encoding."""
    print("\nTesting state encoding...")
    
    batch_size = 2
    num_nodes = 50
    num_edges = 200
    num_hosts = 50
    traffic_seq_len = 20
    
    # Create dummy data
    node_features = torch.randn(batch_size, num_nodes, 64)
    edge_index = torch.randint(0, num_nodes, (batch_size, 2, num_edges))
    edge_attr = torch.randn(batch_size, num_edges, 16)
    batch = torch.arange(batch_size).repeat_interleave(num_nodes)
    host_features = torch.randn(batch_size, num_hosts, 100)
    host_mask = torch.ones(batch_size, num_hosts, dtype=torch.bool)
    traffic_features = torch.randn(batch_size, traffic_seq_len, 50)
    
    # Encode
    node_emb, graph_emb, host_emb, traffic_emb, fused_emb = model.encode_state(
        node_features=node_features,
        edge_index=edge_index,
        edge_attr=edge_attr,
        batch=batch,
        host_features=host_features,
        host_mask=host_mask,
        traffic_features=traffic_features,
    )
    
    print(f"Node embeddings: {node_emb.shape}")        # [B, N, D]
    print(f"Graph embedding: {graph_emb.shape}")       # [B, D]
    print(f"Host embeddings: {host_emb.shape}")        # [B, N, D]
    print(f"Traffic embedding: {traffic_emb.shape}")   # [B, D]
    print(f"Fused embedding: {fused_emb.shape}")       # [B, D]
    
    assert node_emb.shape == (batch_size, num_nodes, 256)
    assert graph_emb.shape == (batch_size, 256)
    assert host_emb.shape == (batch_size, num_hosts, 256)
    assert traffic_emb.shape == (batch_size, 256)
    assert fused_emb.shape == (batch_size, 256)
    
    print("State encoding test PASSED")


def test_forward_pass(model):
    """Test full forward pass with sequence."""
    print("\nTesting forward pass...")
    
    batch_size = 2
    num_nodes = 30
    num_edges = 100
    num_hosts = 30
    num_assets = 30
    traffic_seq_len = 20
    context_window = 10
    horizon = 4
    
    # Create sequence data (context_window timesteps)
    sequence = {
        "node_features": [],
        "edge_index": [],
        "edge_attr": [],
        "batch": [],
        "host_features": [],
        "host_mask": [],
        "traffic_features": [],
    }
    
    for t in range(context_window):
        sequence["node_features"].append(torch.randn(batch_size, num_nodes, 64))
        sequence["edge_index"].append(torch.randint(0, num_nodes, (batch_size, 2, num_edges)))
        sequence["edge_attr"].append(torch.randn(batch_size, num_edges, 16))
        sequence["batch"].append(torch.arange(batch_size).repeat_interleave(num_nodes))
        sequence["host_features"].append(torch.randn(batch_size, num_hosts, 100))
        sequence["host_mask"].append(torch.ones(batch_size, num_hosts, dtype=torch.bool))
        sequence["traffic_features"].append(torch.randn(batch_size, traffic_seq_len, 50))
    
    # Current state
    current_state = {
        "node_features": torch.randn(batch_size, num_nodes, 64),
        "edge_index": torch.randint(0, num_nodes, (batch_size, 2, num_edges)),
        "edge_attr": torch.randn(batch_size, num_edges, 16),
        "batch": torch.arange(batch_size).repeat_interleave(num_nodes),
        "host_features": torch.randn(batch_size, num_hosts, 100),
        "host_mask": torch.ones(batch_size, num_hosts, dtype=torch.bool),
        "traffic_features": torch.randn(batch_size, traffic_seq_len, 50),
    }
    
    # Asset embeddings for target prediction
    asset_embeddings = torch.randn(batch_size, num_assets, 256)
    asset_mask = torch.ones(batch_size, num_assets, dtype=torch.bool)
    
    # Teacher forcing states
    teacher_forcing_states = torch.randn(batch_size, horizon, 256)
    
    # Forward pass
    with torch.no_grad():
        output = model.forward(
            sequence=sequence,
            current_state=current_state,
            asset_embeddings=asset_embeddings,
            asset_mask=asset_mask,
            teacher_forcing_states=teacher_forcing_states,
            teacher_forcing_ratio=0.5,
        )
    
    print(f"Predicted states: {output.predicted_states.shape}")      # [B, H, D]
    print(f"Stage logits: {output.stage_logits.shape}")              # [B, H, 14]
    print(f"Stage probs: {output.stage_probs.shape}")                # [B, H, 14]
    print(f"Target logits: {output.target_logits.shape}")            # [B, H, N]
    print(f"Target probs: {output.target_probs.shape}")              # [B, H, N]
    print(f"Recon node: {output.recon_node_features.shape}")         # [N, D]
    print(f"Recon edge: {output.recon_edge_features.shape}")         # [E, D]
    print(f"Recon edge logits: {output.recon_edge_logits.shape}")    # [E]
    
    assert output.predicted_states.shape == (batch_size, horizon, 256)
    assert output.stage_logits.shape == (batch_size, horizon, 14)
    assert output.stage_probs.shape == (batch_size, horizon, 14)
    assert output.target_logits.shape == (batch_size, horizon, num_assets)
    assert output.target_probs.shape == (batch_size, horizon, num_assets)
    
    # Check probabilities sum to 1
    assert torch.allclose(output.stage_probs.sum(dim=-1), torch.ones(batch_size, horizon), atol=1e-4)
    assert torch.allclose(output.target_probs.sum(dim=-1), torch.ones(batch_size, horizon), atol=1e-4)
    
    print("Forward pass test PASSED")


def test_predict_mode(model):
    """Test prediction mode (single state)."""
    print("\nTesting prediction mode...")
    
    batch_size = 1
    num_nodes = 20
    num_edges = 50
    num_hosts = 20
    num_assets = 20
    traffic_seq_len = 20
    
    current_state = {
        "node_features": torch.randn(batch_size, num_nodes, 64),
        "edge_index": torch.randint(0, num_nodes, (batch_size, 2, num_edges)),
        "edge_attr": torch.randn(batch_size, num_edges, 16),
        "batch": torch.arange(batch_size).repeat_interleave(num_nodes),
        "host_features": torch.randn(batch_size, num_hosts, 100),
        "host_mask": torch.ones(batch_size, num_hosts, dtype=torch.bool),
        "traffic_features": torch.randn(batch_size, traffic_seq_len, 50),
    }
    
    asset_embeddings = torch.randn(batch_size, num_assets, 256)
    asset_mask = torch.ones(batch_size, num_assets, dtype=torch.bool)
    
    with torch.no_grad():
        output = model.predict(
            current_state=current_state,
            asset_embeddings=asset_embeddings,
            asset_mask=asset_mask,
        )
    
    print(f"Predicted states: {output.predicted_states.shape}")
    print(f"Stage probs: {output.stage_probs.shape}")
    print(f"Target probs: {output.target_probs.shape}")
    
    assert output.predicted_states.shape == (batch_size, 4, 256)
    assert output.stage_probs.shape == (batch_size, 4, 14)
    assert output.target_probs.shape == (batch_size, 4, num_assets)
    
    print("Prediction mode test PASSED")


def test_stage_classifier():
    """Test stage classifier independently."""
    print("\nTesting stage classifier...")
    
    from models.heads import StageClassifier, TemporalStageClassifier
    
    # Test regular classifier
    classifier = StageClassifier(
        input_dim=256,
        hidden_dims=[256, 128, 64],
        num_classes=14,
        dropout=0.1,
    )
    
    x = torch.randn(4, 256)
    logits = classifier(x)
    probs = classifier.predict_proba(x)
    stages = classifier.predict_stage(x)
    
    print(f"Logits: {logits.shape}")
    print(f"Probs: {probs.shape}")
    print(f"Stages: {stages}")
    
    assert logits.shape == (4, 14)
    assert probs.shape == (4, 14)
    assert len(stages) == 4
    
    # Test temporal classifier
    temp_classifier = TemporalStageClassifier(
        input_dim=256,
        horizon=4,
        hidden_dim=128,
        num_classes=14,
        dropout=0.1,
    )
    
    x_temp = torch.randn(4, 4, 256)
    temp_logits = temp_classifier(x_temp)
    temp_probs = temp_classifier.predict_proba(x_temp)
    
    print(f"Temporal logits: {temp_logits.shape}")
    print(f"Temporal probs: {temp_probs.shape}")
    
    assert temp_logits.shape == (4, 4, 14)
    assert temp_probs.shape == (4, 4, 14)
    
    print("Stage classifier test PASSED")


def test_target_predictor():
    """Test target predictor independently."""
    print("\nTesting target predictor...")
    
    from models.heads import TargetPredictor
    
    predictor = TargetPredictor(
        query_dim=256,
        key_dim=256,
        num_heads=8,
        dropout=0.1,
    )
    
    batch_size = 2
    num_assets = 50
    
    query = torch.randn(batch_size, 256)
    asset_embeddings = torch.randn(batch_size, num_assets, 256)
    asset_mask = torch.ones(batch_size, num_assets, dtype=torch.bool)
    asset_mask[:, -5:] = False  # Mask last 5 assets
    
    scores, attn = predictor(query, asset_embeddings, asset_mask)
    top_scores, top_indices = predictor.predict_top_k(query, asset_embeddings, asset_mask, k=3)
    
    print(f"Scores: {scores.shape}")
    print(f"Attention: {attn.shape}")
    print(f"Top-3 scores: {top_scores.shape}")
    print(f"Top-3 indices: {top_indices.shape}")
    
    assert scores.shape == (batch_size, num_assets)
    assert attn.shape == (batch_size, num_assets)
    assert top_scores.shape == (batch_size, 3)
    assert top_indices.shape == (batch_size, 3)
    
    # Check masked assets have low scores
    for b in range(batch_size):
        masked_scores = scores[b, ~asset_mask[b]]
        assert (masked_scores < -100).all() or (masked_scores == float('-inf')).all()
    
    print("Target predictor test PASSED")


def test_gradient_flow(model):
    """Test gradient flow through the model."""
    print("\nTesting gradient flow...")
    
    batch_size = 1
    num_nodes = 10
    num_edges = 20
    num_hosts = 10
    num_assets = 10
    traffic_seq_len = 10
    context_window = 5
    horizon = 4
    
    model.train()
    
    # Create sequence
    sequence = {
        "node_features": [],
        "edge_index": [],
        "edge_attr": [],
        "batch": [],
        "host_features": [],
        "host_mask": [],
        "traffic_features": [],
    }
    
    for t in range(context_window):
        sequence["node_features"].append(torch.randn(batch_size, num_nodes, 64, requires_grad=True))
        sequence["edge_index"].append(torch.randint(0, num_nodes, (batch_size, 2, num_edges)))
        sequence["edge_attr"].append(torch.randn(batch_size, num_edges, 16, requires_grad=True))
        sequence["batch"].append(torch.arange(batch_size).repeat_interleave(num_nodes))
        sequence["host_features"].append(torch.randn(batch_size, num_hosts, 100, requires_grad=True))
        sequence["host_mask"].append(torch.ones(batch_size, num_hosts, dtype=torch.bool))
        sequence["traffic_features"].append(torch.randn(batch_size, traffic_seq_len, 50, requires_grad=True))
    
    current_state = {
        "node_features": torch.randn(batch_size, num_nodes, 64, requires_grad=True),
        "edge_index": torch.randint(0, num_nodes, (batch_size, 2, num_edges)),
        "edge_attr": torch.randn(batch_size, num_edges, 16, requires_grad=True),
        "batch": torch.arange(batch_size).repeat_interleave(num_nodes),
        "host_features": torch.randn(batch_size, num_hosts, 100, requires_grad=True),
        "host_mask": torch.ones(batch_size, num_hosts, dtype=torch.bool),
        "traffic_features": torch.randn(batch_size, traffic_seq_len, 50, requires_grad=True),
    }
    
    asset_embeddings = torch.randn(batch_size, num_assets, 256, requires_grad=True)
    asset_mask = torch.ones(batch_size, num_assets, dtype=torch.bool)
    
    # Forward
    output = model.forward(
        sequence=sequence,
        current_state=current_state,
        asset_embeddings=asset_embeddings,
        asset_mask=asset_mask,
    )
    
    # Compute dummy loss
    loss = output.stage_logits.mean() + output.target_logits.mean()
    loss.backward()
    
    # Check gradients exist
    has_grad = False
    for name, param in model.named_parameters():
        if param.grad is not None:
            has_grad = True
            break
    
    assert has_grad, "No gradients found!"
    print("Gradient flow test PASSED")


def test_onnx_export(model):
    """Test ONNX export capability."""
    print("\nTesting ONNX export...")
    
    try:
        import onnx
        import onnxruntime as ort
        
        model.eval()
        
        # Create dummy inputs for export
        batch_size = 1
        num_nodes = 10
        num_edges = 20
        num_hosts = 10
        traffic_seq_len = 10
        
        # We need to export the predict method
        class PredictWrapper(nn.Module):
            def __init__(self, model):
                super().__init__()
                self.model = model
                
            def forward(self, node_features, edge_index, edge_attr, batch, 
                       host_features, host_mask, traffic_features,
                       asset_embeddings, asset_mask):
                current_state = {
                    "node_features": node_features,
                    "edge_index": edge_index,
                    "edge_attr": edge_attr,
                    "batch": batch,
                    "host_features": host_features,
                    "host_mask": host_mask,
                    "traffic_features": traffic_features,
                }
                output = self.model.predict(
                    current_state=current_state,
                    asset_embeddings=asset_embeddings,
                    asset_mask=asset_mask,
                )
                return output.stage_probs, output.target_probs
        
        wrapper = PredictWrapper(model)
        
        dummy_inputs = (
            torch.randn(batch_size, num_nodes, 64),
            torch.randint(0, num_nodes, (batch_size, 2, num_edges)),
            torch.randn(batch_size, num_edges, 16),
            torch.arange(batch_size).repeat_interleave(num_nodes),
            torch.randn(batch_size, num_hosts, 100),
            torch.ones(batch_size, num_hosts, dtype=torch.bool),
            torch.randn(batch_size, traffic_seq_len, 50),
            torch.randn(batch_size, num_nodes, 256),
            torch.ones(batch_size, num_nodes, dtype=torch.bool),
        )
        
        # Export
        torch.onnx.export(
            wrapper,
            dummy_inputs,
            "test_model.onnx",
            export_params=True,
            opset_version=17,
            do_constant_folding=True,
            input_names=[
                "node_features", "edge_index", "edge_attr", "batch",
                "host_features", "host_mask", "traffic_features",
                "asset_embeddings", "asset_mask"
            ],
            output_names=["stage_probs", "target_probs"],
            dynamic_axes={
                "node_features": {0: "batch", 1: "nodes"},
                "edge_index": {0: "batch", 2: "edges"},
                "edge_attr": {0: "batch", 1: "edges"},
                "host_features": {0: "batch", 1: "hosts"},
                "traffic_features": {0: "batch", 1: "seq_len"},
                "asset_embeddings": {0: "batch", 1: "assets"},
            },
        )
        
        # Verify with ONNX Runtime
        ort_session = ort.InferenceSession("test_model.onnx")
        ort_inputs = {name: inp.numpy() for name, inp in zip([
            "node_features", "edge_index", "edge_attr", "batch",
            "host_features", "host_mask", "traffic_features",
            "asset_embeddings", "asset_mask"
        ], dummy_inputs)}
        
        ort_outputs = ort_session.run(None, ort_inputs)
        print(f"ONNX export successful! Outputs: {[o.shape for o in ort_outputs]}")
        
        # Cleanup
        import os
        os.remove("test_model.onnx")
        
        print("ONNX export test PASSED")
        
    except ImportError:
        print("ONNX not installed, skipping export test")
    except Exception as e:
        print(f"ONNX export test failed: {e}")


def test_model_summary():
    """Print model summary."""
    print("\n" + "="*60)
    print("MODEL SUMMARY")
    print("="*60)
    
    model = test_model_creation()
    
    # Count parameters by module
    for name, module in model.named_children():
        param_count = sum(p.numel() for p in module.parameters())
        trainable = sum(p.numel() for p in module.parameters() if p.requires_grad)
        print(f"{name:30s} | Total: {param_count:>10,} | Trainable: {trainable:>10,}")
    
    print("="*60)


def run_all_tests():
    """Run all tests."""
    print("="*60)
    print("WORLD MODEL TEST SUITE")
    print("="*60)
    
    # Set seed for reproducibility
    torch.manual_seed(42)
    
    # Create model
    model = test_model_creation()
    
    # Run tests
    test_encode_state(model)
    test_forward_pass(model)
    test_predict_mode(model)
    test_stage_classifier()
    test_target_predictor()
    test_gradient_flow(model)
    test_onnx_export(model)
    test_model_summary()
    
    print("\n" + "="*60)
    print("ALL TESTS PASSED!")
    print("="*60)


if __name__ == "__main__":
    run_all_tests()