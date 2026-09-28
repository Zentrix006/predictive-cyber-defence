#!/usr/bin/env python3
"""Trains the Graph-Temporal World Model (G-FLOWWM) on Genuine Graph Campaigns.

Includes post-hoc Conformal Calibration on the purely benign traffic split.
"""
import sys
from pathlib import Path
import torch
import torch.nn.functional as F
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from models.graph_world_model import GraphFlowWorldModel

def train_genuine_model():
    print("==================================================")
    print(" TRAINING GENUINE GRAPH-TEMPORAL MODEL")
    print("==================================================")
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    data_dir = ROOT / "data" / "genuine_graph_campaigns"
    out_dir = ROOT / "data" / "genuine_graph_candidate"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    print("Loading Genuine Campaigns...")
    train_graphs = torch.load(data_dir / "train.pt")
    cal_graphs = torch.load(data_dir / "calibration.pt")
    
    model = GraphFlowWorldModel(
        node_dim=16, edge_dim=35, d_model=64, num_stages=14
    ).to(device)
    
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
    
    epochs = 8
    model.train()
    for epoch in range(epochs):
        epoch_loss = 0.0
        for g in train_graphs[:200]:
            nodes = g["nodes"].unsqueeze(0).to(device)
            edge_index = g["edge_index"].unsqueeze(0).to(device)
            edges = g["edges"].unsqueeze(0).to(device)
            labels = g["stage_labels"].to(device)
            
            out = model(nodes, edge_index, edges)
            logits = out.node_stage_logits.squeeze(0)
            
            loss_stage = F.cross_entropy(logits, labels)
            loss_jepa = torch.mean((out.latent_state - out.predicted_latent_future[:,0,:,:])**2)
            
            loss = loss_stage + 0.1 * loss_jepa
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item()
            
        print(f"Epoch {epoch+1}/{epochs} | Loss: {epoch_loss/200:.4f}")
        
    print("\nStarting Temperature Scaling & Conformal Calibration on Benign Traffic...")
    model.eval()
    temp_param = torch.nn.Parameter(torch.ones(1, device=device) * 1.5)
    temp_opt = torch.optim.LBFGS([temp_param], lr=0.1, max_iter=50)
    
    cal_logits = []
    cal_labels = []
    baseline_surprisals = []
    
    with torch.no_grad():
        for g in cal_graphs:
            nodes = g["nodes"].unsqueeze(0).to(device)
            edge_index = g["edge_index"].unsqueeze(0).to(device)
            edges = g["edges"].unsqueeze(0).to(device)
            out = model(nodes, edge_index, edges)
            
            cal_logits.append(out.node_stage_logits.squeeze(0))
            cal_labels.append(g["stage_labels"].to(device))
            
            # Record baseline surprisals for conformal thresholding
            jepa_surprisal = torch.mean((out.latent_state - out.predicted_latent_future[:,0,:,:])**2, dim=-1)
            baseline_surprisals.append(jepa_surprisal.cpu().numpy())
            
    all_logits = torch.cat(cal_logits, dim=0)
    all_labels = torch.cat(cal_labels, dim=0)
    
    def closure():
        temp_opt.zero_grad()
        loss = F.cross_entropy(all_logits / torch.clamp(temp_param, min=0.1, max=10.0), all_labels)
        loss.backward()
        return loss
        
    temp_opt.step(closure)
    calibrated_temp = float(torch.clamp(temp_param, min=0.1, max=10.0).item())
    
    # Calculate conformal threshold (e.g., 99th percentile of benign surprisal)
    baseline_surprisals = np.concatenate(baseline_surprisals).flatten()
    conformal_threshold = float(np.percentile(baseline_surprisals, 99.0))
    
    print(f"Calibration Complete.")
    print(f" -> Optimal Temperature: {calibrated_temp:.3f}")
    print(f" -> Conformal Novelty Threshold (99th %ile): {conformal_threshold:.6f}")
    
    checkpoint = {
        "model_state": model.state_dict(),
        "temperature": calibrated_temp,
        "conformal_threshold": conformal_threshold,
        "schema": "genuine-graph-v1"
    }
    torch.save(checkpoint, out_dir / "genuine_candidate.pt")
    print(f"Candidate saved to {out_dir}/genuine_candidate.pt")

if __name__ == "__main__":
    train_genuine_model()
