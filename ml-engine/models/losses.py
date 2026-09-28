"""
Loss functions for World Model
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Optional


class WorldModelLoss(nn.Module):
    """
    Combined loss for World Model training.
    """
    
    def __init__(
        self,
        state_recon_weight: float = 1.0,
        stage_classification_weight: float = 2.0,
        target_prediction_weight: float = 1.5,
        consistency_weight: float = 0.5,
        label_smoothing: float = 0.1,
    ):
        super().__init__()
        self.state_recon_weight = state_recon_weight
        self.stage_classification_weight = stage_classification_weight
        self.target_prediction_weight = target_prediction_weight
        self.consistency_weight = consistency_weight
        
        # Loss functions
        self.mse_loss = nn.MSELoss()
        self.bce_loss = nn.BCEWithLogitsLoss()
        self.ce_loss = nn.CrossEntropyLoss(label_smoothing=label_smoothing)
        self.kl_loss = nn.KLDivLoss(reduction='batchmean')
        
    def forward(
        self,
        output,
        batch: Dict,
        current_state: Dict,
    ) -> Dict[str, torch.Tensor]:
        """
        Compute all loss components.
        
        Returns:
            Dictionary of individual losses and total loss
        """
        losses = {}
        
        # 1. State Reconstruction Loss
        if hasattr(output, 'recon_node_features') and output.recon_node_features is not None:
            target_nodes = current_state["node_features"].view(-1, current_state["node_features"].size(-1))
            losses["state_recon"] = self.mse_loss(output.recon_node_features, target_nodes)
        else:
            losses["state_recon"] = torch.tensor(0.0, device=output.predicted_states.device)
        
        # 2. Stage Classification Loss
        if "stage_labels" in batch:
            stage_labels = batch["stage_labels"]  # [B, H]
            stage_logits = output.stage_logits    # [B, H, C]
            losses["stage_classification"] = self.ce_loss(
                stage_logits.view(-1, stage_logits.size(-1)),
                stage_labels.view(-1),
            )
        else:
            losses["stage_classification"] = torch.tensor(0.0, device=output.predicted_states.device)
        
        # 3. Target Prediction Loss
        if "target_labels" in batch:
            target_labels = batch["target_labels"]  # [B, H]
            target_logits = output.target_logits    # [B, H, N]
            losses["target_prediction"] = self.ce_loss(
                target_logits.view(-1, target_logits.size(-1)),
                target_labels.view(-1),
            )
        else:
            losses["target_prediction"] = torch.tensor(0.0, device=output.predicted_states.device)
        
        # 4. Consistency Loss (entropy regularization on stage predictions)
        if output.stage_probs is not None:
            stage_entropy = -(output.stage_probs * output.stage_probs.log()).sum(dim=-1).mean()
            losses["consistency"] = stage_entropy * 0.01
        else:
            losses["consistency"] = torch.tensor(0.0, device=output.predicted_states.device)
        
        # Total weighted loss
        losses["total"] = (
            self.state_recon_weight * losses["state_recon"] +
            self.stage_classification_weight * losses["stage_classification"] +
            self.target_prediction_weight * losses["target_prediction"] +
            self.consistency_weight * losses["consistency"]
        )
        
        return losses


class ContrastiveLoss(nn.Module):
    """Contrastive loss for learning state representations."""
    
    def __init__(self, temperature: float = 0.07):
        super().__init__()
        self.temperature = temperature
        
    def forward(self, z1: torch.Tensor, z2: torch.Tensor) -> torch.Tensor:
        """
        Compute contrastive loss between two views.
        
        Args:
            z1: [B, D] - first view embeddings
            z2: [B, D] - second view embeddings
        """
        # Normalize
        z1 = F.normalize(z1, dim=-1)
        z2 = F.normalize(z2, dim=-1)
        
        # Similarity matrix
        sim = torch.matmul(z1, z2.T) / self.temperature  # [B, B]
        
        # Labels: positive pairs are on diagonal
        labels = torch.arange(z1.size(0), device=z1.device)
        
        # Cross-entropy loss
        loss = F.cross_entropy(sim, labels)
        
        return loss


class GraphReconstructionLoss(nn.Module):
    """Loss for graph structure reconstruction."""
    
    def __init__(self):
        super().__init__()
        self.node_loss = nn.MSELoss()
        self.edge_loss = nn.MSELoss()
        self.edge_existence_loss = nn.BCEWithLogitsLoss()
        
    def forward(
        self,
        recon_node: torch.Tensor,
        target_node: torch.Tensor,
        recon_edge: torch.Tensor,
        target_edge: torch.Tensor,
        recon_edge_logits: torch.Tensor,
        target_edge_mask: torch.Tensor,
    ) -> Dict[str, torch.Tensor]:
        losses = {}
        losses["node_recon"] = self.node_loss(recon_node, target_node)
        losses["edge_recon"] = self.edge_loss(recon_edge, target_edge)
        losses["edge_existence"] = self.edge_existence_loss(
            recon_edge_logits, target_edge_mask.float()
        )
        return losses