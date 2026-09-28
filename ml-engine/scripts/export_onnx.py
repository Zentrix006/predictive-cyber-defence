"""
Export World Model to ONNX format.
"""
import os
import sys
import argparse
import torch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models import WorldModel, create_world_model


def export_onnx(
    checkpoint_path: str,
    config: dict,
    output_path: str = "world_model.onnx",
    opset_version: int = 17,
):
    """Export model to ONNX."""
    
    # Load model
    model = create_world_model(config)
    
    checkpoint = torch.load(checkpoint_path, map_location="cpu")
    
    if "state_dict" in checkpoint:
        state_dict = checkpoint["state_dict"]
        new_state_dict = {}
        for k, v in state_dict.items():
            if k.startswith("model."):
                new_state_dict[k[6:]] = v
            else:
                new_state_dict[k] = v
        model.load_state_dict(new_state_dict, strict=False)
    else:
        model.load_state_dict(checkpoint, strict=False)
    
    model.eval()
    
    # Create wrapper for ONNX export
    class ONNXWrapper(torch.nn.Module):
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
    
    wrapper = ONNXWrapper(model)
    
    # Dummy inputs
    batch_size = 1
    dummy_inputs = (
        torch.randn(batch_size, 50, config["node_input_dim"]),
        torch.randint(0, 50, (batch_size, 2, 200)),
        torch.randn(batch_size, 200, config["edge_input_dim"]),
        torch.arange(batch_size).repeat_interleave(50),
        torch.randn(batch_size, 50, config["host_input_dim"]),
        torch.ones(batch_size, 50, dtype=torch.bool),
        torch.randn(batch_size, 20, config["traffic_input_dim"]),
        torch.randn(batch_size, 50, config["hidden_dim"]),
        torch.ones(batch_size, 50, dtype=torch.bool),
    )
    
    # Export
    print(f"Exporting to {output_path}...")
    torch.onnx.export(
        wrapper,
        dummy_inputs,
        output_path,
        export_params=True,
        opset_version=opset_version,
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
    
    # Optimize with ONNX Simplifier
    try:
        import onnx
        import onnxsim
        model_onnx = onnx.load(output_path)
        model_simp, check = onnxsim.simplify(model_onnx)
        assert check, "Simplified ONNX model could not be validated"
        onnx.save(model_simp, output_path)
        print(f"ONNX model optimized and saved to {output_path}")
    except ImportError:
        print(f"ONNX model saved to {output_path} (onnxsim not installed)")
    
    # Verify with ONNX Runtime
    try:
        import onnxruntime as ort
        ort_session = ort.InferenceSession(output_path)
        ort_inputs = {name: inp.numpy() for name, inp in zip([
            "node_features", "edge_index", "edge_attr", "batch",
            "host_features", "host_mask", "traffic_features",
            "asset_embeddings", "asset_mask"
        ], dummy_inputs)}
        
        ort_outputs = ort_session.run(None, ort_inputs)
        print(f"ONNX Runtime verification successful!")
        print(f"  stage_probs shape: {ort_outputs[0].shape}")
        print(f"  target_probs shape: {ort_outputs[1].shape}")
    except ImportError:
        print("onnxruntime not installed, skipping verification")


def main():
    parser = argparse.ArgumentParser(description="Export World Model to ONNX")
    parser.add_argument("--checkpoint", type=str, required=True, help="Path to model checkpoint")
    parser.add_argument("--config", type=str, default="../configs/model_config.yaml", help="Path to config")
    parser.add_argument("--output", type=str, default="world_model.onnx", help="Output ONNX file")
    parser.add_argument("--opset", type=int, default=17, help="ONNX opset version")
    
    args = parser.parse_args()
    
    # Load config
    import yaml
    with open(args.config, "r") as f:
        config = yaml.safe_load(f)
    
    export_onnx(
        checkpoint_path=args.checkpoint,
        config=config["model"],
        output_path=args.output,
        opset_version=args.opset,
    )


if __name__ == "__main__":
    main()