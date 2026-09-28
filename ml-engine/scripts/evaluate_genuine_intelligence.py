#!/usr/bin/env python3
"""Evaluates Genuine Intelligence using Formal Novelty Metrics (AUROC, AUPRC).

Tests known-attack F1, per-stage macro F1, ECE, and Tri-Factor Novelty separability
on held-out CTU-13 / Infiltration families.
"""
import sys
import json
from pathlib import Path
import torch
import torch.nn.functional as F
import numpy as np
from sklearn.metrics import roc_auc_score, average_precision_score, f1_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from models.graph_world_model import GraphFlowWorldModel

def calculate_ece(probs, targets, n_bins=10):
    bin_boundaries = torch.linspace(0, 1, n_bins + 1)
    bin_lowers = bin_boundaries[:-1]
    bin_uppers = bin_boundaries[1:]
    
    confidences, predictions = torch.max(probs, dim=-1)
    accuracies = predictions.eq(targets)
    
    ece = torch.zeros(1, device=probs.device)
    for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
        in_bin = confidences.gt(bin_lower.item()) * confidences.le(bin_upper.item())
        prop_in_bin = in_bin.float().mean()
        if prop_in_bin.item() > 0:
            accuracy_in_bin = accuracies[in_bin].float().mean()
            avg_confidence_in_bin = confidences[in_bin].mean()
            ece += torch.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
            
    return ece.item()

def get_metrics_for_split(model, graphs, temp, device):
    all_logits = []
    all_labels = []
    all_surprisals = []
    
    with torch.no_grad():
        for g in graphs[:200]:
            nodes = g["nodes"].unsqueeze(0).to(device)
            edge_index = g["edge_index"].unsqueeze(0).to(device)
            edges = g["edges"].unsqueeze(0).to(device)
            
            out = model(nodes, edge_index, edges)
            
            # Calibrated logits
            logits = out.node_stage_logits.squeeze(0) / temp
            all_logits.append(logits.cpu())
            all_labels.append(g["stage_labels"])
            
            # JEPA Surprisal
            surprisal = torch.mean((out.latent_state - out.predicted_latent_future[:,0,:,:])**2, dim=-1).squeeze(0)
            all_surprisals.append(surprisal.cpu())
            
    all_logits = torch.cat(all_logits, dim=0)
    all_labels = torch.cat(all_labels, dim=0)
    all_surprisals = torch.cat(all_surprisals, dim=0)
    
    probs = F.softmax(all_logits, dim=-1)
    preds = torch.argmax(probs, dim=-1)
    
    malicious_labels = (all_labels > 0).numpy()
    malicious_preds = (preds > 0).numpy()
    
    malicious_f1 = f1_score(malicious_labels, malicious_preds, zero_division=0)
    macro_f1 = f1_score(all_labels.numpy(), preds.numpy(), average='macro', zero_division=0)
    ece = calculate_ece(probs, all_labels)
    
    return malicious_f1, macro_f1, ece, all_surprisals.numpy(), malicious_labels

def evaluate():
    print("==================================================")
    print(" EVALUATING GENUINE INTELLIGENCE METRICS")
    print("==================================================")
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    data_dir = ROOT / "data" / "genuine_graph_campaigns"
    model_dir = ROOT / "data" / "genuine_graph_candidate"
    
    checkpoint = torch.load(model_dir / "genuine_candidate.pt", map_location=device, weights_only=False)
    temp = checkpoint["temperature"]
    conformal_threshold = checkpoint["conformal_threshold"]
    
    model = GraphFlowWorldModel(node_dim=16, edge_dim=35, d_model=64, num_stages=14).to(device)
    model.load_state_dict(checkpoint["model_state"])
    model.eval()
    
    test_known = torch.load(data_dir / "test_known.pt")
    test_novel = torch.load(data_dir / "test_novel.pt")
    
    print("\nEvaluating Known Attack F1 & ECE...")
    mal_f1, macro_f1, ece, known_surp, _ = get_metrics_for_split(model, test_known, temp, device)
    
    print("Evaluating Novel (OOD) Tri-Factor Metrics...")
    _, _, _, novel_surp, novel_labels = get_metrics_for_split(model, test_novel, temp, device)
    
    # Calculate AUROC / AUPRC for Novelty Detection
    # Known benign/attacks vs Novel attacks (using Surprisal as the score)
    # We label novel instances as 1 and known instances as 0
    novelty_scores = np.concatenate([known_surp, novel_surp])
    novelty_targets = np.concatenate([np.zeros_like(known_surp), np.ones_like(novel_surp)])
    
    try:
        auroc = roc_auc_score(novelty_targets, novelty_scores)
        auprc = average_precision_score(novelty_targets, novelty_scores)
    except ValueError:
        auroc = 0.5
        auprc = 0.5
        
    print("\n--- GENUINE INTELLIGENCE REPORT ---")
    print(f"Malicious F1 (Known): {mal_f1:.4f}")
    print(f"Stage Macro-F1 (Known): {macro_f1:.4f}")
    print(f"Expected Calibration Error: {ece:.4f}")
    print(f"Conformal Threshold: {conformal_threshold:.6f}")
    print(f"Novelty Detection AUROC: {auroc:.4f}")
    print(f"Novelty Detection AUPRC: {auprc:.4f}")
    
    gate_passed = (
        mal_f1 >= 0.95 and
        macro_f1 >= 0.70 and
        ece <= 0.08 and
        auroc >= 0.85
    )
    
    print(f"\nPROMOTION GATE: {'PASS' if gate_passed else 'FAIL'}")
    
    report = {
        "metrics_are_measured": True,
        "metrics": {
            "malicious_f1": mal_f1,
            "stage_macro_f1": macro_f1,
            "ece": ece,
            "conformal_threshold": conformal_threshold,
            "novelty_auroc": auroc,
            "novelty_auprc": auprc
        },
        "gate_passed": bool(gate_passed)
    }
    
    with open(model_dir / "genuine_intelligence_report.json", "w") as f:
        json.dump(report, f, indent=4)

if __name__ == "__main__":
    evaluate()
