"""
Lightning Module for World Model Training.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.optim.lr_scheduler import CosineAnnealingWarmRestarts
import pytorch_lightning as pl
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
from sklearn.metrics import accuracy_score, roc_auc_score, average_precision_score
import warnings
warnings.filterwarnings("ignore")


class WorldModelLightning(pl.LightningModule):
    """
    PyTorch Lightning wrapper for World Model.
    """
    
    def __init__(
        self,
        model: nn.Module,
        training_config: Dict,
        evaluation_config: Dict,
    ):
        super().__init__()
        self.model = model
        self.training_config = training_config
        self.evaluation_config = evaluation_config
        
        # Loss weights
        self.loss_weights = training_config.model.loss_weights
        
        # Horizon
        self.horizon = training_config.model.horizon
        
        # Save hyperparameters
        self.save_hyperparameters(ignore=["model"])
        
        # Metrics storage
        self.validation_step_outputs = []
        self.test_step_outputs = []
    
    def forward(self, *args, **kwargs):
        return self.model(*args, **kwargs)
    
    def training_step(self, batch: Dict, batch_idx: int) -> torch.Tensor:
        """Training step."""
        # Extract data
        sequence = batch["sequence"]
        current_state = batch["current_state"]
        
        # Get asset embeddings (use node features as proxy)
        asset_embeddings = current_state["node_features"].mean(dim=1)  # [B, D]
        asset_embeddings = asset_embeddings.unsqueeze(1).repeat(1, 20, 1)  # [B, N, D]
        asset_mask = torch.ones(asset_embeddings.shape[:2], dtype=torch.bool, device=self.device)
        
        # Forward pass with teacher forcing
        teacher_forcing_ratio = self.training_config.get("teacher_forcing_ratio", 0.5)
        if hasattr(self.training_config, "get"):
            teacher_forcing_ratio = self.training_config.get("teacher_forcing_ratio", 0.5)
        else:
            teacher_forcing_ratio = 0.5
        
        output = self.model.forward(
            sequence=sequence,
            current_state=current_state,
            asset_embeddings=asset_embeddings,
            asset_mask=asset_mask,
            teacher_forcing_ratio=teacher_forcing_ratio,
        )
        
        # Compute losses
        losses = self._compute_losses(output, batch)
        
        # Total loss
        total_loss = (
            self.loss_weights.state_reconstruction * losses["state_recon"] +
            self.loss_weights.stage_classification * losses["stage_classification"] +
            self.loss_weights.target_prediction * losses["target_prediction"] +
            self.loss_weights.consistency * losses["consistency"]
        )
        
        # Log losses
        self.log_dict({
            "train/loss": total_loss,
            "train/state_recon": losses["state_recon"],
            "train/stage_classification": losses["stage_classification"],
            "train/target_prediction": losses["target_prediction"],
            "train/consistency": losses["consistency"],
        }, prog_bar=True, on_step=True, on_epoch=True)
        
        return total_loss
    
    def validation_step(self, batch: Dict, batch_idx: int) -> Dict:
        """Validation step."""
        sequence = batch["sequence"]
        current_state = batch["current_state"]
        
        asset_embeddings = current_state["node_features"].mean(dim=1).unsqueeze(1).repeat(1, 20, 1)
        asset_mask = torch.ones(asset_embeddings.shape[:2], dtype=torch.bool, device=self.device)
        
        # No teacher forcing during validation
        output = self.model.forward(
            sequence=sequence,
            current_state=current_state,
            asset_embeddings=asset_embeddings,
            asset_mask=asset_mask,
            teacher_forcing_ratio=0.0,
        )
        
        losses = self._compute_losses(output, batch)
        
        total_loss = (
            self.loss_weights.state_reconstruction * losses["state_recon"] +
            self.loss_weights.stage_classification * losses["stage_classification"] +
            self.loss_weights.target_prediction * losses["target_prediction"] +
            self.loss_weights.consistency * losses["consistency"]
        )
        
        # Compute metrics
        metrics = self._compute_metrics(output, batch)
        
        # Log
        log_dict = {
            "val/loss": total_loss,
            "val/state_recon": losses["state_recon"],
            "val/stage_classification": losses["stage_classification"],
            "val/target_prediction": losses["target_prediction"],
            "val/consistency": losses["consistency"],
        }
        log_dict.update({f"val/{k}": v for k, v in metrics.items()})
        
        self.log_dict(log_dict, prog_bar=True, on_step=False, on_epoch=True)
        
        self.validation_step_outputs.append({
            "loss": total_loss,
            "metrics": metrics,
            "output": output,
        })
        
        return {"loss": total_loss, "metrics": metrics}
    
    def test_step(self, batch: Dict, batch_idx: int) -> Dict:
        """Test step."""
        return self.validation_step(batch, batch_idx)
    
    def on_validation_epoch_end(self):
        """Aggregate validation metrics."""
        if not self.validation_step_outputs:
            return
        
        avg_loss = torch.stack([x["loss"] for x in self.validation_step_outputs]).mean()
        self.log("val/avg_loss", avg_loss, prog_bar=True)
        
        self.validation_step_outputs.clear()
    
    def on_test_epoch_end(self):
        """Aggregate test metrics."""
        if not self.test_step_outputs:
            return
        
        avg_loss = torch.stack([x["loss"] for x in self.test_step_outputs]).mean()
        self.log("test/avg_loss", avg_loss, prog_bar=True)
        
        self.test_step_outputs.clear()
    
    def _compute_losses(self, output, batch: Dict) -> Dict[str, torch.Tensor]:
        """Compute all loss components."""
        losses = {}
        
        # 1. State Reconstruction Loss
        # Compare reconstructed current state with actual current state
        current_node_features = batch["current_state"]["node_features"]
        current_edge_attr = batch["current_state"]["edge_attr"]
        current_edge_index = batch["current_state"]["edge_index"]
        
        if output.recon_node_features is not None:
            # MSE on node features
            target_nodes = current_node_features.view(-1, current_node_features.size(-1))
            losses["state_recon"] = F.mse_loss(output.recon_node_features, target_nodes)
        else:
            losses["state_recon"] = torch.tensor(0.0, device=self.device)
        
        # 2. Stage Classification Loss
        if "stage_labels" in batch:
            stage_labels = batch["stage_labels"]  # [B, H]
            stage_logits = output.stage_logits    # [B, H, C]
            losses["stage_classification"] = F.cross_entropy(
                stage_logits.view(-1, stage_logits.size(-1)),
                stage_labels.view(-1),
                label_smoothing=self.training_config.model.regularization.get("label_smoothing", 0.1)
            )
        else:
            # Self-supervised: predict stage from state dynamics
            # For now, use dummy labels
            losses["stage_classification"] = torch.tensor(0.0, device=self.device)
        
        # 3. Target Prediction Loss
        if "target_labels" in batch:
            target_labels = batch["target_labels"]  # [B, H]
            target_logits = output.target_logits    # [B, H, N]
            losses["target_prediction"] = F.cross_entropy(
                target_logits.view(-1, target_logits.size(-1)),
                target_labels.view(-1),
            )
        else:
            losses["target_prediction"] = torch.tensor(0.0, device=self.device)
        
        # 4. Consistency Loss
        # Ensure predicted stages align with predicted states
        if output.stage_probs is not None and output.predicted_states is not None:
            # KL divergence between stage distribution from classifier
            # and stage distribution derived from state decoder
            # Simplified: use entropy regularization
            stage_entropy = -(output.stage_probs * output.stage_probs.log()).sum(dim=-1).mean()
            losses["consistency"] = stage_entropy * 0.01
        else:
            losses["consistency"] = torch.tensor(0.0, device=self.device)
        
        return losses
    
    def _compute_metrics(self, output, batch: Dict) -> Dict[str, float]:
        """Compute evaluation metrics."""
        metrics = {}
        
        # Stage prediction metrics
        if "stage_labels" in batch and output.stage_probs is not None:
            stage_labels = batch["stage_labels"].cpu().numpy()  # [B, H]
            stage_probs = output.stage_probs.detach().cpu().numpy()  # [B, H, C]
            stage_preds = stage_probs.argmax(axis=-1)  # [B, H]
            
            # Per-horizon accuracy
            for h in range(self.horizon):
                acc = (stage_preds[:, h] == stage_labels[:, h]).mean()
                metrics[f"stage_acc_h{h+1}"] = acc
            
            # Overall accuracy
            metrics["stage_acc_overall"] = (stage_preds == stage_labels).mean()
            
            # Top-k accuracy
            for k in [3, 5]:
                top_k = np.argsort(stage_probs, axis=-1)[:, :, -k:]
                correct = np.any(top_k == stage_labels[:, :, None], axis=-1)
                metrics[f"stage_top{k}_acc"] = correct.mean()
            
            # AUC (one-vs-rest)
            try:
                for h in range(self.horizon):
                    auc = roc_auc_score(
                        (stage_labels[:, h][:, None] == np.arange(stage_probs.shape[-1])).astype(int),
                        stage_probs[:, h],
                        multi_class="ovr",
                        average="macro",
                    )
                    metrics[f"stage_auc_h{h+1}"] = auc
            except:
                pass
        
        # Target prediction metrics
        if "target_labels" in batch and output.target_probs is not None:
            target_labels = batch["target_labels"].cpu().numpy()  # [B, H]
            target_probs = output.target_probs.detach().cpu().numpy()  # [B, H, N]
            target_preds = target_probs.argmax(axis=-1)  # [B, H]
            
            for h in range(self.horizon):
                acc = (target_preds[:, h] == target_labels[:, h]).mean()
                metrics[f"target_acc_h{h+1}"] = acc
                
                # Hit@k
                for k in [1, 3, 5]:
                    top_k = np.argsort(target_probs[:, h], axis=-1)[:, -k:]
                    hit = np.any(top_k == target_labels[:, h][:, None], axis=-1)
                    metrics[f"target_hit@{k}_h{h+1}"] = hit.mean()
                
                # MRR
                ranks = np.argsort(np.argsort(-target_probs[:, h], axis=-1), axis=-1)
                true_ranks = ranks[np.arange(len(target_labels)), target_labels[:, h]]
                mrr = (1.0 / (true_ranks + 1)).mean()
                metrics[f"target_mrr_h{h+1}"] = mrr
            
            metrics["target_acc_overall"] = (target_preds == target_labels).mean()
        
        return metrics
    
    def configure_optimizers(self):
        """Configure optimizer and scheduler."""
        # Optimizer
        optimizer_type = self.training_config.optimizer.type.lower()
        
        if optimizer_type == "adamw":
            optimizer = torch.optim.AdamW(
                self.parameters(),
                lr=self.training_config.optimizer.lr,
                betas=self.training_config.optimizer.betas,
                eps=self.training_config.optimizer.eps,
                weight_decay=self.training_config.optimizer.weight_decay,
            )
        elif optimizer_type == "adam":
            optimizer = torch.optim.Adam(
                self.parameters(),
                lr=self.training_config.optimizer.lr,
                betas=self.training_config.optimizer.betas,
                eps=self.training_config.optimizer.eps,
                weight_decay=self.training_config.optimizer.weight_decay,
            )
        elif optimizer_type == "sgd":
            optimizer = torch.optim.SGD(
                self.parameters(),
                lr=self.training_config.optimizer.lr,
                momentum=0.9,
                weight_decay=self.training_config.optimizer.weight_decay,
            )
        else:
            raise ValueError(f"Unknown optimizer: {optimizer_type}")
        
        # Scheduler
        scheduler_config = self.training_config.scheduler
        scheduler_type = scheduler_config.type.lower()
        
        if scheduler_type == "cosineannealingwarmrestarts":
            scheduler = CosineAnnealingWarmRestarts(
                optimizer,
                T_0=scheduler_config.T_0,
                T_mult=scheduler_config.T_mult,
                eta_min=scheduler_config.eta_min,
            )
        elif scheduler_type == "cosineannealing":
            scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
                optimizer,
                T_max=self.training_config.epochs,
                eta_min=scheduler_config.eta_min,
            )
        elif scheduler_type == "reducelronplateau":
            scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
                optimizer,
                mode="min",
                factor=0.5,
                patience=5,
                min_lr=scheduler_config.eta_min,
            )
        else:
            scheduler = None
        
        if scheduler is not None:
            if scheduler_type == "reducelronplateau":
                return {
                    "optimizer": optimizer,
                    "lr_scheduler": {
                        "scheduler": scheduler,
                        "monitor": "val/loss",
                        "interval": "epoch",
                    },
                }
            else:
                return {
                    "optimizer": optimizer,
                    "lr_scheduler": {
                        "scheduler": scheduler,
                        "interval": "epoch",
                    },
                }
        
        return optimizer
    
    def predict_step(self, batch: Dict, batch_idx: int, dataloader_idx: int = 0) -> Dict:
        """Prediction step for inference."""
        sequence = batch["sequence"]
        current_state = batch["current_state"]
        
        asset_embeddings = current_state["node_features"].mean(dim=1).unsqueeze(1).repeat(1, 20, 1)
        asset_mask = torch.ones(asset_embeddings.shape[:2], dtype=torch.bool, device=self.device)
        
        output = self.model.predict(
            current_state=current_state,
            asset_embeddings=asset_embeddings,
            asset_mask=asset_mask,
        )
        
        return {
            "stage_probs": output.stage_probs,
            "target_probs": output.target_probs,
            "predicted_states": output.predicted_states,
        }


def compute_stage_metrics(
    stage_probs: torch.Tensor,
    stage_labels: torch.Tensor,
    horizon: int,
) -> Dict[str, float]:
    """Compute stage prediction metrics."""
    metrics = {}
    
    stage_preds = stage_probs.argmax(dim=-1).cpu().numpy()
    labels = stage_labels.cpu().numpy()
    
    # Per-horizon accuracy
    for h in range(horizon):
        acc = (stage_preds[:, h] == labels[:, h]).mean()
        metrics[f"stage_acc_h{h+1}"] = float(acc)
    
    metrics["stage_acc_overall"] = float((stage_preds == labels).mean())
    
    return metrics


def compute_target_metrics(
    target_probs: torch.Tensor,
    target_labels: torch.Tensor,
    horizon: int,
) -> Dict[str, float]:
    """Compute target prediction metrics."""
    metrics = {}
    
    target_preds = target_probs.argmax(dim=-1).cpu().numpy()
    labels = target_labels.cpu().numpy()
    
    for h in range(horizon):
        acc = (target_preds[:, h] == labels[:, h]).mean()
        metrics[f"target_acc_h{h+1}"] = float(acc)
        
        for k in [1, 3, 5]:
            top_k = np.argsort(target_probs[:, h].cpu().numpy(), axis=-1)[:, -k:]
            hit = np.any(top_k == labels[:, h][:, None], axis=-1)
            metrics[f"target_hit@{k}_h{h+1}"] = float(hit.mean())
        
        ranks = np.argsort(np.argsort(-target_probs[:, h].cpu().numpy(), axis=-1), axis=-1)
        true_ranks = ranks[np.arange(len(labels)), labels[:, h]]
        mrr = (1.0 / (true_ranks + 1)).mean()
        metrics[f"target_mrr_h{h+1}"] = float(mrr)
    
    metrics["target_acc_overall"] = float((target_preds == labels).mean())
    
    return metrics