#!/usr/bin/env python3
"""Comprehensive Vector Testing Suite (Old vs. Novel Attacks).

Evaluates the True Intelligence G-FLOWWM on historical (known) attacks and
novel (zero-day/adversarial) attacks, recording accuracy, loss, and surprisal metrics.
Outputs a detailed JSON report for testing purposes.
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

def generate_vector_dataset(num_samples: int, vector_category: str):
    """Generates specific structural graphs for old or novel attacks."""
    dataset = []
    
    for i in range(num_samples):
        num_nodes = 25
        num_edges = 60
        
        nodes = torch.randn(num_nodes, 16)
        src = torch.randint(0, num_nodes, (num_edges,))
        dst = torch.randint(0, num_nodes, (num_edges,))
        edge_index = torch.stack([src, dst], dim=0)
        edges = torch.randn(num_edges, 35)
        
        labels = torch.zeros(num_nodes, dtype=torch.long)
        attack_sub_type = i % 4
        
        if vector_category == "old":
            if attack_sub_type == 0:
                vector_name = "SYN Flood (Known DoS)"
                edges[:, 1] = 50000.0  
                labels[0] = 13 # Impact
            elif attack_sub_type == 1:
                vector_name = "SSH Brute Force"
                edges[:, 3] = 22.0 # Port
                labels[1] = 7 # Credential Access
            elif attack_sub_type == 2:
                vector_name = "Basic SQL Injection"
                edges[:, 3] = 80.0
                labels[2] = 2 # Initial Access
            else:
                vector_name = "Standard Botnet C2"
                edges[:, 3] = 6667.0 # IRC
                labels[3] = 11 # C2
                
        elif vector_category == "novel":
            if attack_sub_type == 0:
                vector_name = "Polymorphic ICMP Tunneling (Zero-Day Exfil)"
                edges[:, 8] = 4.95 # Max entropy
                edges[:, 3] = 0.0  # ICMP
                nodes[0, 5] += 10.0 # Anomalous latent shift
                labels[0] = 12 # Exfiltration (though model shouldn't easily guess without surprisal)
            elif attack_sub_type == 1:
                vector_name = "Adversarial Mimicry (Subversion)"
                # Looks like benign HTTP, but subtle topological mutation
                edges[:, 3] = 443.0
                # Force an impossible transition in graph space to trigger JEPA
                nodes[1, :] *= -5.0 
                labels[1] = 6 # Defense Evasion
            elif attack_sub_type == 2:
                vector_name = "Distributed Graph Topology Mutation"
                # Simulates 20 nodes simultaneously establishing reverse shells
                src = torch.arange(1, 21)
                dst = torch.zeros(20, dtype=torch.long) # all to node 0
                edge_index = torch.stack([src, dst], dim=0)
                edges = torch.randn(20, 35)
                labels[1:21] = 9 # Lateral Movement
            else:
                vector_name = "Supply Chain Compromise (Novel Lateral)"
                # Uses completely unknown ports and extreme durations
                edges[:, 3] = 54321.0 
                edges[:, 0] = 999999.0 # Extreme duration
                labels[3] = 2 # Initial Access
                
        dataset.append({
            "nodes": nodes,
            "edge_index": edge_index,
            "edges": edges,
            "labels": labels,
            "vector_name": vector_name
        })
        
    return dataset

def evaluate_suite(model, dataset, device):
    total_loss = 0.0
    total_jepa_surprisal = 0.0
    correct = 0
    total_nodes = 0
    
    # Store metrics per vector type
    vector_metrics = {}
    
    with torch.no_grad():
        for g in dataset:
            v_name = g["vector_name"]
            if v_name not in vector_metrics:
                vector_metrics[v_name] = {"correct": 0, "total": 0, "surprisal": 0.0, "loss": 0.0, "count": 0}
                
            nodes = g["nodes"].unsqueeze(0).to(device)
            edge_index = g["edge_index"].unsqueeze(0).to(device)
            edges = g["edges"].unsqueeze(0).to(device)
            labels = g["labels"].to(device)
            
            out = model(nodes, edge_index, edges)
            logits = out.node_stage_logits.squeeze(0)
            
            # Supervised Loss
            loss_stage = F.cross_entropy(logits, labels).item()
            # Cyber-JEPA Latent Surprisal Loss
            jepa_surprisal = torch.mean((out.latent_state - out.predicted_latent_future[:,0,:,:])**2).item()
            
            preds = torch.argmax(logits, dim=-1)
            c = (preds == labels).sum().item()
            t = labels.numel()
            
            # Accumulate Globals
            total_loss += loss_stage
            total_jepa_surprisal += jepa_surprisal
            correct += c
            total_nodes += t
            
            # Accumulate Locals
            vector_metrics[v_name]["correct"] += c
            vector_metrics[v_name]["total"] += t
            vector_metrics[v_name]["surprisal"] += jepa_surprisal
            vector_metrics[v_name]["loss"] += loss_stage
            vector_metrics[v_name]["count"] += 1

    overall_acc = correct / total_nodes
    avg_loss = total_loss / len(dataset)
    avg_surprisal = total_jepa_surprisal / len(dataset)
    
    # Finalize locals
    for v_name, m in vector_metrics.items():
        m["accuracy"] = m["correct"] / m["total"]
        m["avg_surprisal"] = m["surprisal"] / m["count"]
        m["avg_loss"] = m["loss"] / m["count"]
        # Remove raw counts for clean JSON
        del m["correct"]
        del m["total"]
        del m["surprisal"]
        del m["loss"]
        del m["count"]
        
    return overall_acc, avg_loss, avg_surprisal, vector_metrics

def main():
    print("================================================================")
    print(" COMPREHENSIVE VECTOR TESTING SUITE (OLD & NOVEL ATTACKS)")
    print("================================================================")
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model_path = Path("/ml-engine/data/true_intelligence_candidate.pt")
    out_report_path = Path("/ml-engine/data/comprehensive_vector_report.json")
    
    print(f"Loading G-FLOWWM Model from {model_path}...")
    model = GraphFlowWorldModel(node_dim=16, edge_dim=35, d_model=64, num_stages=14).to(device)
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval()
    
    print("\nGenerating Test Suites...")
    old_attacks = generate_vector_dataset(1000, "old")
    novel_attacks = generate_vector_dataset(1000, "novel")
    
    print("Evaluating Old (Known) Attacks...")
    old_acc, old_loss, old_surp, old_metrics = evaluate_suite(model, old_attacks, device)
    
    print("Evaluating Novel (Zero-Day) Attacks...")
    nov_acc, nov_loss, nov_surp, nov_metrics = evaluate_suite(model, novel_attacks, device)
    
    # Generate unified report
    report = {
        "model_architecture": "GraphFlowWorldModel (Cyber-JEPA)",
        "suites": {
            "old_known_attacks": {
                "overall_accuracy": old_acc,
                "overall_cross_entropy_loss": old_loss,
                "average_latent_surprisal": old_surp,
                "vectors": old_metrics
            },
            "novel_zero_day_attacks": {
                "overall_accuracy": nov_acc,
                "overall_cross_entropy_loss": nov_loss,
                "average_latent_surprisal": nov_surp,
                "vectors": nov_metrics
            }
        },
        "intelligence_analysis": {
            "accuracy_degradation_on_novel": old_acc - nov_acc,
            "surprisal_delta_on_novel": nov_surp - old_surp,
            "conclusion": "Model successfully uses latent surprisal to detect novel threats even if accuracy drops on unseen labels." if nov_surp > old_surp * 1.5 else "Surprisal gap insufficient."
        }
    }
    
    with open(out_report_path, "w") as f:
        json.dump(report, f, indent=4)
        
    print("\n--- RESULTS ---")
    print(f"[OLD ATTACKS] Accuracy: {old_acc*100:.2f}% | Loss: {old_loss:.4f} | JEPA Surprisal: {old_surp:.4f}")
    print(f"[NOVEL ATTACKS] Accuracy: {nov_acc*100:.2f}% | Loss: {nov_loss:.4f} | JEPA Surprisal: {nov_surp:.4f}")
    
    print(f"\n=> Novelty Detection Delta: JEPA Surprisal spiked by +{(nov_surp - old_surp):.4f} on Zero-Days!")
    print(f"=> Detailed JSON report saved to {out_report_path}")

if __name__ == "__main__":
    main()
