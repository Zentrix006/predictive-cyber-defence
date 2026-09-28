"""
Evaluation script for World Model.
Computes comprehensive metrics on test set.
"""
import os
import sys
import argparse
import torch
import numpy as np
import json
from pathlib import Path
from tqdm import tqdm

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models import WorldModel, create_world_model
from training.data_module import NetworkDataModule
from training.lightning_module import WorldModelLightning


def load_model(checkpoint_path: str, config: dict) -> WorldModel:
    """Load model from checkpoint."""
    model = create_world_model(config)
    
    # Load checkpoint
    checkpoint = torch.load(checkpoint_path, map_location="cpu")
    
    if "state_dict" in checkpoint:
        # Lightning checkpoint
        state_dict = checkpoint["state_dict"]
        # Remove 'model.' prefix if present
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
    return model


def evaluate_model(
    model: WorldModel,
    dataloader,
    device: torch.device,
    horizon: int = 4,
) -> dict:
    """Evaluate model on dataloader."""
    
    all_stage_probs = []
    all_stage_labels = []
    all_target_probs = []
    all_target_labels = []
    all_predicted_states = []
    
    model.to(device)
    model.eval()
    
    with torch.no_grad():
        for batch in tqdm(dataloader, desc="Evaluating"):
            sequence = batch["sequence"]
            current_state = batch["current_state"]
            
            # Move to device
            for key in sequence:
                if isinstance(sequence[key], list):
                    sequence[key] = [t.to(device) for t in sequence[key]]
                else:
                    sequence[key] = sequence[key].to(device)
            
            for key in current_state:
                if isinstance(current_state[key], list):
                    current_state[key] = [t.to(device) for t in current_state[key]]
                else:
                    current_state[key] = current_state[key].to(device)
            
            # Get asset embeddings
            asset_embeddings = current_state["node_features"].mean(dim=1).unsqueeze(1).repeat(1, 20, 1)
            asset_embeddings = asset_embeddings.to(device)
            asset_mask = torch.ones(asset_embeddings.shape[:2], dtype=torch.bool, device=device)
            
            # Forward pass
            output = model.forward(
                sequence=sequence,
                current_state=current_state,
                asset_embeddings=asset_embeddings,
                asset_mask=asset_mask,
                teacher_forcing_ratio=0.0,
            )
            
            # Collect predictions
            all_stage_probs.append(output.stage_probs.cpu())
            all_target_probs.append(output.target_probs.cpu())
            all_predicted_states.append(output.predicted_states.cpu())
            
            # Collect labels if available
            if "stage_labels" in batch:
                all_stage_labels.append(batch["stage_labels"])
            if "target_labels" in batch:
                all_target_labels.append(batch["target_labels"])
    
    # Concatenate
    stage_probs = torch.cat(all_stage_probs, dim=0)
    target_probs = torch.cat(all_target_probs, dim=0)
    predicted_states = torch.cat(all_predicted_states, dim=0)
    
    results = {
        "stage_probs": stage_probs.numpy(),
        "target_probs": target_probs.numpy(),
        "predicted_states": predicted_states.numpy(),
    }
    
    if all_stage_labels:
        stage_labels = torch.cat(all_stage_labels, dim=0)
        results["stage_labels"] = stage_labels.numpy()
        
        # Compute stage metrics
        results["stage_metrics"] = compute_stage_metrics_detailed(
            stage_probs, stage_labels, horizon
        )
    
    if all_target_labels:
        target_labels = torch.cat(all_target_labels, dim=0)
        results["target_labels"] = target_labels.numpy()
        
        # Compute target metrics
        results["target_metrics"] = compute_target_metrics_detailed(
            target_probs, target_labels, horizon
        )
    
    return results


def compute_stage_metrics_detailed(
    stage_probs: torch.Tensor,
    stage_labels: torch.Tensor,
    horizon: int,
) -> dict:
    """Compute detailed stage prediction metrics."""
    from sklearn.metrics import (
        accuracy_score, precision_recall_fscore_support,
        roc_auc_score, confusion_matrix, classification_report
    )
    
    stage_preds = stage_probs.argmax(dim=-1).numpy()
    labels = stage_labels.numpy()
    
    metrics = {}
    
    # Overall accuracy
    metrics["overall_accuracy"] = float((stage_preds == labels).mean())
    
    # Per-horizon metrics
    for h in range(horizon):
        h_preds = stage_preds[:, h]
        h_labels = labels[:, h]
        
        metrics[f"h{h+1}_accuracy"] = float(accuracy_score(h_labels, h_preds))
        
        # Per-class metrics
        precision, recall, f1, support = precision_recall_fscore_support(
            h_labels, h_preds, average=None, zero_division=0
        )
        
        for i, (p, r, f, s) in enumerate(zip(precision, recall, f1, support)):
            if s > 0:
                metrics[f"h{h+1}_class{i}_precision"] = float(p)
                metrics[f"h{h+1}_class{i}_recall"] = float(r)
                metrics[f"h{h+1}_class{i}_f1"] = float(f)
                metrics[f"h{h+1}_class{i}_support"] = int(s)
        
        # Macro averages
        macro_p, macro_r, macro_f, _ = precision_recall_fscore_support(
            h_labels, h_preds, average="macro", zero_division=0
        )
        metrics[f"h{h+1}_macro_precision"] = float(macro_p)
        metrics[f"h{h+1}_macro_recall"] = float(macro_r)
        metrics[f"h{h+1}_macro_f1"] = float(macro_f)
        
        # Weighted averages
        weighted_p, weighted_r, weighted_f, _ = precision_recall_fscore_support(
            h_labels, h_preds, average="weighted", zero_division=0
        )
        metrics[f"h{h+1}_weighted_precision"] = float(weighted_p)
        metrics[f"h{h+1}_weighted_recall"] = float(weighted_r)
        metrics[f"h{h+1}_weighted_f1"] = float(weighted_f)
        
        # Top-k accuracy
        for k in [3, 5]:
            top_k = np.argsort(stage_probs[:, h].numpy(), axis=-1)[:, -k:]
            hit = np.any(top_k == h_labels[:, None], axis=-1)
            metrics[f"h{h+1}_top{k}_acc"] = float(hit.mean())
        
        # AUC (one-vs-rest)
        try:
            auc = roc_auc_score(
                (h_labels[:, None] == np.arange(stage_probs.shape[-1])).astype(int),
                stage_probs[:, h].numpy(),
                multi_class="ovr",
                average="macro",
            )
            metrics[f"h{h+1}_auc_ovr"] = float(auc)
        except:
            pass
    
    # Confusion matrix for last horizon
    cm = confusion_matrix(labels[:, -1], stage_preds[:, -1])
    metrics["confusion_matrix"] = cm.tolist()
    
    return metrics


def compute_target_metrics_detailed(
    target_probs: torch.Tensor,
    target_labels: torch.Tensor,
    horizon: int,
) -> dict:
    """Compute detailed target prediction metrics."""
    from sklearn.metrics import accuracy_score
    
    target_preds = target_probs.argmax(dim=-1).numpy()
    labels = target_labels.numpy()
    
    metrics = {}
    
    # Overall accuracy
    metrics["overall_accuracy"] = float((target_preds == labels).mean())
    
    # Per-horizon metrics
    for h in range(horizon):
        h_preds = target_preds[:, h]
        h_labels = labels[:, h]
        
        metrics[f"h{h+1}_accuracy"] = float(accuracy_score(h_labels, h_preds))
        
        # Hit@k
        for k in [1, 3, 5, 10]:
            top_k = np.argsort(target_probs[:, h].numpy(), axis=-1)[:, -k:]
            hit = np.any(top_k == h_labels[:, None], axis=-1)
            metrics[f"h{h+1}_hit@{k}"] = float(hit.mean())
        
        # MRR
        ranks = np.argsort(np.argsort(-target_probs[:, h].numpy(), axis=-1), axis=-1)
        true_ranks = ranks[np.arange(len(labels)), h_labels]
        mrr = (1.0 / (true_ranks + 1)).mean()
        metrics[f"h{h+1}_mrr"] = float(mrr)
        
        # Mean rank
        metrics[f"h{h+1}_mean_rank"] = float(true_ranks.mean())
    
    return metrics


def calibration_analysis(
    probs: torch.Tensor,
    labels: torch.Tensor,
    n_bins: int = 10,
) -> dict:
    """Analyze prediction calibration."""
    from sklearn.calibration import calibration_curve
    
    probs_np = probs.numpy()
    labels_np = labels.numpy()
    
    results = {}
    
    # For each class
    for c in range(probs_np.shape[-1]):
        prob_c = probs_np[:, c]
        label_c = (labels_np == c).astype(int)
        
        # Skip if no positive samples
        if label_c.sum() == 0:
            continue
        
        fraction_of_positives, mean_predicted_value = calibration_curve(
            label_c, prob_c, n_bins=n_bins
        )
        
        # ECE (Expected Calibration Error)
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        bin_lowers = bin_boundaries[:-1]
        bin_uppers = bin_boundaries[1:]
        
        ece = 0
        for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
            in_bin = (prob_c > bin_lower) & (prob_c <= bin_upper)
            prop_in_bin = in_bin.mean()
            if prop_in_bin > 0:
                accuracy_in_bin = label_c[in_bin].mean()
                avg_confidence_in_bin = prob_c[in_bin].mean()
                ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
        
        results[f"class_{c}_ece"] = float(ece)
        results[f"class_{c}_fraction_positives"] = fraction_of_positives.tolist()
        results[f"class_{c}_mean_predicted"] = mean_predicted_value.tolist()
    
    # Overall ECE (weighted)
    overall_ece = 0
    total_samples = probs_np.shape[0]
    for c in range(probs_np.shape[-1]):
        prob_c = probs_np[:, c]
        label_c = (labels_np == c).astype(int)
        
        if label_c.sum() == 0:
            continue
        
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        bin_lowers = bin_boundaries[:-1]
        bin_uppers = bin_boundaries[1:]
        
        class_ece = 0
        for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
            in_bin = (prob_c > bin_lower) & (prob_c <= bin_upper)
            prop_in_bin = in_bin.mean()
            if prop_in_bin > 0:
                accuracy_in_bin = label_c[in_bin].mean()
                avg_confidence_in_bin = prob_c[in_bin].mean()
                class_ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
        
        class_weight = label_c.sum() / total_samples
        overall_ece += class_ece * class_weight
    
    results["overall_ece"] = float(overall_ece)
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Evaluate World Model")
    parser.add_argument("--checkpoint", type=str, required=True, help="Path to model checkpoint")
    parser.add_argument("--config", type=str, default="../configs/model_config.yaml", help="Path to config")
    parser.add_argument("--output", type=str, default="evaluation_results.json", help="Output file")
    parser.add_argument("--device", type=str, default="cuda", help="Device (cuda/cpu)")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--num-workers", type=int, default=4, help="Number of workers")
    
    args = parser.parse_args()
    
    # Load config
    import yaml
    with open(args.config, "r") as f:
        config = yaml.safe_load(f)
    
    # Load model
    print(f"Loading model from {args.checkpoint}")
    model = load_model(args.checkpoint, config["model"])
    
    # Create datamodule
    data_module = NetworkDataModule(config["data"])
    data_module.setup("test")
    
    test_loader = data_module.test_dataloader()
    
    # Evaluate
    print("Starting evaluation...")
    device = torch.device(args.device if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    
    results = evaluate_model(model, test_loader, device, config["model"]["horizon"])
    
    # Calibration analysis
    if "stage_labels" in results:
        print("Computing stage calibration...")
        results["stage_calibration"] = calibration_analysis(
            torch.tensor(results["stage_probs"]),
            torch.tensor(results["stage_labels"]),
        )
    
    if "target_labels" in results:
        print("Computing target calibration...")
        results["target_calibration"] = calibration_analysis(
            torch.tensor(results["target_probs"]),
            torch.tensor(results["target_labels"]),
        )
    
    # Convert numpy arrays to lists for JSON serialization
    def convert_to_serializable(obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, dict):
            return {k: convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_to_serializable(v) for v in obj]
        return obj
    
    serializable_results = convert_to_serializable(results)
    
    # Save results
    with open(args.output, "w") as f:
        json.dump(serializable_results, f, indent=2)
    
    print(f"\nResults saved to {args.output}")
    
    # Print summary
    print("\n" + "="*60)
    print("EVALUATION SUMMARY")
    print("="*60)
    
    if "stage_metrics" in results:
        print("\nStage Prediction Metrics:")
        for k, v in results["stage_metrics"].items():
            if isinstance(v, (int, float)):
                print(f"  {k}: {v:.4f}")
    
    if "target_metrics" in results:
        print("\nTarget Prediction Metrics:")
        for k, v in results["target_metrics"].items():
            if isinstance(v, (int, float)):
                print(f"  {k}: {v:.4f}")
    
    if "stage_calibration" in results:
        print(f"\nStage Calibration ECE: {results['stage_calibration'].get('overall_ece', 'N/A'):.4f}")
    
    if "target_calibration" in results:
        print(f"Target Calibration ECE: {results['target_calibration'].get('overall_ece', 'N/A'):.4f}")


if __name__ == "__main__":
    main()