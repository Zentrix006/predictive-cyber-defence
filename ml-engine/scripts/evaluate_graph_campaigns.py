#!/usr/bin/env python3
"""Evaluates the Graph-Temporal World Model on completely unseen Test Campaigns.

Generates evaluation report enforcing the ECE <= 0.08 promotion gate.
Satisfies Component 4 of the Model Update Plan.
"""
import sys
import json
from pathlib import Path
import torch
import torch.nn.functional as F
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
APP_ROOT = ROOT.parent / "backend"
sys.path.insert(0, str(APP_ROOT))

from models.graph_world_model import GraphFlowWorldModel

def calculate_ece(logits, targets, n_bins=10):
    """Calculates Expected Calibration Error (ECE) for multi-class classification."""
    bin_boundaries = torch.linspace(0, 1, n_bins + 1)
    bin_lowers = bin_boundaries[:-1]
    bin_uppers = bin_boundaries[1:]
    
    probs = F.softmax(logits, dim=-1)
    confidences, predictions = torch.max(probs, dim=-1)
    accuracies = predictions.eq(targets)
    
    ece = torch.zeros(1, device=logits.device)
    for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
        in_bin = confidences.gt(bin_lower.item()) * confidences.le(bin_upper.item())
        prop_in_bin = in_bin.float().mean()
        if prop_in_bin.item() > 0:
            accuracy_in_bin = accuracies[in_bin].float().mean()
            avg_confidence_in_bin = confidences[in_bin].mean()
            ece += torch.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
            
    return ece.item()

def evaluate():
    print("="*60)
    print(" G-FLOWWM Unseen Campaign Evaluation & Promotion Gate")
    print("="*60)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    data_dir = Path("/ml-engine/data/graph_campaigns")
    model_dir = Path("/ml-engine/data/graph_candidate_v1")
    
    print("Loading Test Campaigns (Strict Holdout)...")
    test_graphs = torch.load(data_dir / "test.pt")
    
    checkpoint = torch.load(model_dir / "graph_candidate.pt", map_location=device, weights_only=False)
    temp = checkpoint["temperature"]
    
    model = GraphFlowWorldModel(
        node_dim=16, edge_dim=35, d_model=64, num_stages=14
    ).to(device)
    model.load_state_dict(checkpoint["model_state"])
    model.eval()
    
    test_logits = []
    test_labels = []
    
    with torch.no_grad():
        for g in test_graphs[:100]:
            nodes = g["nodes"].unsqueeze(0).to(device)
            edge_index = g["edge_index"].unsqueeze(0).to(device)
            edges = g["edges"].unsqueeze(0).to(device)
            out = model(nodes, edge_index, edges)
            
            # Apply Temperature Scaling!
            calibrated_logits = out.node_stage_logits.squeeze(0) / temp
            test_logits.append(calibrated_logits)
            test_labels.append(g["stage_labels"].to(device))
            
    all_logits = torch.cat(test_logits, dim=0)
    all_labels = torch.cat(test_labels, dim=0)
    
    # Calculate ECE
    ece = calculate_ece(all_logits, all_labels)
    
    # Calculate Mock F1 (In reality use sklearn metric)
    preds = torch.argmax(all_logits, dim=-1)
    acc = (preds == all_labels).float().mean().item()
    
    print("\n--- G-FLOWWM TEST EVALUATION REPORT ---")
    print(f"Model: Graph-Temporal-v1")
    print(f"Test Campaigns Evaluated: {len(test_graphs[:100])}")
    print(f"Nodes Evaluated: {len(all_labels)}")
    print(f"Applied Temperature: {temp:.3f}")
    print(f"Overall Accuracy: {acc:.4f}")
    print(f"Expected Calibration Error (ECE): {ece:.4f}")
    
    promotion_eligible = ece <= 0.08
    print(f"\nPROMOTION GATE CHECK:")
    print(f" ECE <= 0.08: {'PASS' if promotion_eligible else 'FAIL'} ({ece:.4f})")
    print(f" => OVERALL PROMOTION DECISION: {'TRUE' if promotion_eligible else 'FALSE'}")
    
    report = {
        "model": "G-FLOWWM",
        "test_campaigns": len(test_graphs[:100]),
        "accuracy": acc,
        "ece": ece,
        "promotion_recommended": promotion_eligible
    }
    
    with open(model_dir / "campaign_evaluation_report.json", "w") as f:
        json.dump(report, f, indent=4)
        
if __name__ == "__main__":
    evaluate()
