#!/usr/bin/env python3
"""Trains the Graph-Temporal World Model (G-FLOWWM) on aggregated graph campaigns.

Implements Cyber-JEPA self-supervised dynamics loss and supervised Focal Loss for
rare-stage mitigation. Includes post-hoc Temperature Scaling on the calibration split.
Satisfies Component 2 & 3 of the Model Update Plan.
"""
import sys
from pathlib import Path
import torch
import torch.nn.functional as F

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
APP_ROOT = ROOT.parent / "backend"
sys.path.insert(0, str(APP_ROOT))

from models.graph_world_model import GraphFlowWorldModel

class FocalLoss(torch.nn.Module):
    def __init__(self, alpha=None, gamma=2.0):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, logits, targets):
        ce_loss = F.cross_entropy(logits, targets, reduction="none", weight=self.alpha)
        pt = torch.exp(-ce_loss)
        focal_loss = ((1.0 - pt) ** self.gamma) * ce_loss
        return focal_loss.mean()

def train_graph_model():
    print("="*60)
    print(" G-FLOWWM Graph-Temporal Training & Calibration")
    print("="*60)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    data_dir = Path("/ml-engine/data/graph_campaigns")
    out_dir = Path("/ml-engine/data/graph_candidate_v1")
    out_dir.mkdir(parents=True, exist_ok=True)
    
    print("Loading Graph Campaigns...")
    train_graphs = torch.load(data_dir / "train.pt")
    cal_graphs = torch.load(data_dir / "calibration.pt")

    if not train_graphs or not cal_graphs:
        raise RuntimeError("Graph campaign partitions are empty")
    for partition_name, graphs in (("train", train_graphs), ("calibration", cal_graphs)):
        for idx, graph in enumerate(graphs):
            required = {"campaign_id", "capture_ids", "manifest_hash", "provenance"}
            missing = required - set(graph)
            if missing:
                raise RuntimeError(
                    f"{partition_name}[{idx}] lacks canonical provenance: {sorted(missing)}"
                )
            if graph.get("synthetic") is True:
                raise RuntimeError(f"{partition_name}[{idx}] is marked synthetic")
    
    # Initialize G-FLOWWM
    model = GraphFlowWorldModel(
        node_dim=16, edge_dim=35, d_model=64, num_stages=14
    ).to(device)
    
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    criterion = FocalLoss(gamma=2.0)
    
    epochs = 5
    model.train()
    for epoch in range(epochs):
        total_loss = 0.0
        total_jepa = 0.0
        total_focal = 0.0
        
        for g in train_graphs:
            nodes = g["nodes"].unsqueeze(0).to(device)
            edge_index = g["edge_index"].unsqueeze(0).to(device)
            edges = g["edges"].unsqueeze(0).to(device)
            stages = g["stage_labels"].to(device) # [N]
            
            # Forward pass
            out = model(nodes, edge_index, edges)
            
            # [B, N, num_stages] -> [N, num_stages]
            stage_logits = out.node_stage_logits.squeeze(0)
            
            if "next_nodes" not in g:
                raise RuntimeError("Graph snapshot is missing next_nodes transition targets")
            jepa_surprisal = torch.mean((out.latent_state - out.predicted_latent_future[:,0,:,:])**2)
            
            focal_loss = criterion(stage_logits, stages)
            
            loss = focal_loss + 0.1 * jepa_surprisal
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            total_jepa += jepa_surprisal.item()
            total_focal += focal_loss.item()
            
        count = max(len(train_graphs), 1)
        print(f"Epoch {epoch+1}/{epochs} | Loss: {total_loss/count:.4f} [Focal: {total_focal/count:.4f}, JEPA: {total_jepa/count:.4f}]")
        
    print("\nStarting Temperature Scaling on Calibration Partition...")
    model.eval()
    temp_param = torch.nn.Parameter(torch.ones(1, device=device) * 1.5)
    temp_opt = torch.optim.LBFGS([temp_param], lr=0.1, max_iter=50)
    
    cal_logits = []
    cal_labels = []
    with torch.no_grad():
        for g in cal_graphs[:20]:
            nodes = g["nodes"].unsqueeze(0).to(device)
            edge_index = g["edge_index"].unsqueeze(0).to(device)
            edges = g["edges"].unsqueeze(0).to(device)
            out = model(nodes, edge_index, edges)
            cal_logits.append(out.node_stage_logits.squeeze(0))
            cal_labels.append(g["stage_labels"].to(device))
            
    all_logits = torch.cat(cal_logits, dim=0)
    all_labels = torch.cat(cal_labels, dim=0)
    
    def closure():
        temp_opt.zero_grad()
        loss = F.cross_entropy(all_logits / torch.clamp(temp_param, min=0.1, max=10.0), all_labels)
        loss.backward()
        return loss
        
    temp_opt.step(closure)
    calibrated_temp = float(torch.clamp(temp_param, min=0.1, max=10.0).item())
    
    print(f"Calibration Complete. Optimal Temperature: {calibrated_temp:.3f}")
    
    # Save Candidate
    checkpoint = {
        "model_state": model.state_dict(),
        "temperature": calibrated_temp,
        "schema": "graph-temporal-v1"
    }
    torch.save(checkpoint, out_dir / "graph_candidate.pt")
    print(f"G-FLOWWM candidate saved to {out_dir}/graph_candidate.pt")

if __name__ == "__main__":
    train_graph_model()
