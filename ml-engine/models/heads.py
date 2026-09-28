"""
Prediction Heads for World Model
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, List, Tuple


class StageClassifier(nn.Module):
    """
    MITRE ATT&CK stage classifier from predicted state embeddings.
    """
    
    # MITRE ATT&CK stages
    STAGES = [
        "reconnaissance",
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "command_and_control",
        "exfiltration",
        "impact",
        "unknown",  # For uncertain predictions
    ]
    
    def __init__(
        self,
        input_dim: int,
        hidden_dims: List[int] = [256, 128, 64],
        num_classes: int = 14,
        dropout: float = 0.1,
        use_temporal: bool = False,
        horizon: int = 4,
    ):
        super().__init__()
        self.num_classes = num_classes
        self.use_temporal = use_temporal
        self.horizon = horizon
        
        if use_temporal:
            input_dim = input_dim * horizon
        
        # Build MLP
        layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_dims:
            layers.append(nn.Linear(prev_dim, hidden_dim))
            layers.append(nn.LayerNorm(hidden_dim))
            layers.append(nn.GELU())
            layers.append(nn.Dropout(dropout))
            prev_dim = hidden_dim
        
        # Output layer (no activation for logits)
        layers.append(nn.Linear(prev_dim, num_classes))
        
        self.classifier = nn.Sequential(*layers)
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: State embeddings [B, D] or [B, H, D] if use_temporal
            
        Returns:
            Logits [B, num_classes] or [B, H, num_classes]
        """
        if self.use_temporal and x.dim() == 3:
            # Flatten temporal dimension
            batch_size, horizon, dim = x.shape
            x = x.view(batch_size, horizon * dim)
        
        logits = self.classifier(x)
        return logits
    
    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """Predict class probabilities."""
        logits = self.forward(x)
        return F.softmax(logits, dim=-1)
    
    def predict_stage(self, x: torch.Tensor) -> List[str]:
        """Predict stage names."""
        probs = self.predict_proba(x)
        pred_indices = probs.argmax(dim=-1)
        return [self.STAGES[i] for i in pred_indices.tolist()]


class TargetPredictor(nn.Module):
    """
    Predicts target assets for lateral movement/attack progression.
    Uses attention over asset embeddings.
    """
    
    def __init__(
        self,
        query_dim: int,
        key_dim: int,
        num_heads: int = 8,
        dropout: float = 0.1,
        max_assets: int = 1000,
    ):
        super().__init__()
        self.num_heads = num_heads
        self.head_dim = query_dim // num_heads
        
        assert query_dim % num_heads == 0, "query_dim must be divisible by num_heads"
        
        # Projections
        self.q_proj = nn.Linear(query_dim, query_dim)
        self.k_proj = nn.Linear(key_dim, query_dim)
        self.v_proj = nn.Linear(key_dim, query_dim)
        self.out_proj = nn.Linear(query_dim, query_dim)
        
        # Asset embedding projection (for asset features)
        self.asset_proj = nn.Linear(key_dim, query_dim)
        
        self.dropout = nn.Dropout(dropout)
        self.layer_norm = nn.LayerNorm(query_dim)
        
        # Score projection
        self.score_proj = nn.Linear(query_dim, 1)
        
    def forward(
        self,
        query: torch.Tensor,           # [B, D] - predicted state context
        asset_embeddings: torch.Tensor, # [B, N, D] - asset embeddings
        asset_mask: Optional[torch.Tensor] = None,  # [B, N]
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Predict target asset probabilities.
        
        Args:
            query: State context [B, D]
            asset_embeddings: Asset embeddings [B, N, D]
            asset_mask: Valid asset mask [B, N]
            
        Returns:
            target_logits: [B, N]
            attention_weights: [B, N]
        """
        batch_size, num_assets, _ = asset_embeddings.shape
        
        # Project query
        q = self.q_proj(query).unsqueeze(1)  # [B, 1, D]
        
        # Project assets
        k = self.k_proj(asset_embeddings)  # [B, N, D]
        v = self.v_proj(asset_embeddings)  # [B, N, D]
        
        # Multi-head attention
        q = q.view(batch_size, 1, self.num_heads, self.head_dim).transpose(1, 2)
        k = k.view(batch_size, num_assets, self.num_heads, self.head_dim).transpose(1, 2)
        v = v.view(batch_size, num_assets, self.num_heads, self.head_dim).transpose(1, 2)
        
        # Attention
        attn_weights = torch.matmul(q, k.transpose(-2, -1)) / (self.head_dim ** 0.5)
        
        if asset_mask is not None:
            mask = asset_mask.unsqueeze(1).unsqueeze(1)  # [B, 1, 1, N]
            attn_weights = attn_weights.masked_fill(~mask, float('-inf'))
        
        attn_weights = F.softmax(attn_weights, dim=-1)
        attn_weights = self.dropout(attn_weights)
        
        attn_output = torch.matmul(attn_weights, v)
        attn_output = attn_output.transpose(1, 2).contiguous().view(batch_size, 1, -1)
        
        # Output projection
        output = self.out_proj(attn_output).squeeze(1)  # [B, D]
        output = self.layer_norm(output + query)
        
        # Score for each asset
        # Use attention weights directly or compute scores
        # Here we use the mean attention across heads
        mean_attn = attn_weights.mean(dim=1).squeeze(1)  # [B, N]
        
        # Also compute scores from output
        # Expand output to match assets and compute similarity
        output_expanded = output.unsqueeze(1).expand(-1, num_assets, -1)  # [B, N, D]
        similarity = F.cosine_similarity(output_expanded, asset_embeddings, dim=-1)  # [B, N]
        
        # Combine attention and similarity
        scores = (mean_attn + similarity) / 2
        
        return scores, mean_attn
    
    def predict_top_k(
        self,
        query: torch.Tensor,
        asset_embeddings: torch.Tensor,
        asset_mask: Optional[torch.Tensor] = None,
        k: int = 5,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Predict top-k target assets."""
        scores, _ = self.forward(query, asset_embeddings, asset_mask)
        
        if asset_mask is not None:
            scores = scores.masked_fill(~asset_mask, float('-inf'))
        
        top_k_scores, top_k_indices = torch.topk(scores, k=k, dim=-1)
        
        return top_k_scores, top_k_indices


class ExplanationGenerator(nn.Module):
    """
    Generates feature importance explanations for predictions.
    Uses gradient-based attribution (Integrated Gradients / SHAP-style).
    """
    
    def __init__(
        self,
        model: nn.Module,
        feature_names: List[str],
        n_steps: int = 50,
    ):
        super().__init__()
        self.model = model
        self.feature_names = feature_names
        self.n_steps = n_steps
        
    def integrated_gradients(
        self,
        inputs: torch.Tensor,
        target_idx: int,
        baseline: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Compute Integrated Gradients attribution.
        
        Args:
            inputs: Input features [B, ...]
            target_idx: Target output index
            baseline: Baseline input (zeros if None)
            
        Returns:
            Attributions [B, ...]
        """
        if baseline is None:
            baseline = torch.zeros_like(inputs)
        
        # Interpolate between baseline and input
        alphas = torch.linspace(0, 1, self.n_steps, device=inputs.device)
        interpolated = baseline + alphas.view(-1, 1) * (inputs - baseline)
        interpolated.requires_grad_(True)
        
        # Forward pass
        outputs = self.model(interpolated)
        
        # Select target output
        if outputs.dim() > 1:
            target_outputs = outputs[:, target_idx]
        else:
            target_outputs = outputs
        
        # Compute gradients
        gradients = torch.autograd.grad(
            outputs=target_outputs.sum(),
            inputs=interpolated,
            create_graph=False,
        )[0]
        
        # Average gradients
        avg_gradients = gradients.mean(dim=0)
        
        # Integrated gradients
        attributions = (inputs - baseline) * avg_gradients
        
        return attributions
    
    def feature_importance(
        self,
        inputs: torch.Tensor,
        target_idx: int,
    ) -> dict:
        """Get feature importance as dictionary."""
        attributions = self.integrated_gradients(inputs, target_idx)
        
        # Aggregate over batch and spatial dimensions
        if attributions.dim() > 2:
            attributions = attributions.mean(dim=tuple(range(attributions.dim() - 1)))
        
        # Normalize
        attributions = torch.abs(attributions)
        attributions = attributions / (attributions.sum() + 1e-8)
        
        return {
            name: float(attr)
            for name, attr in zip(self.feature_names, attributions.tolist())
        }


class TemporalStageClassifier(nn.Module):
    """
    Stage classifier that predicts stages for each future time step.
    """
    
    def __init__(
        self,
        input_dim: int,
        horizon: int = 4,
        hidden_dim: int = 128,
        num_classes: int = 14,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.horizon = horizon
        self.num_classes = num_classes
        
        # Per-horizon classifiers
        self.classifiers = nn.ModuleList()
        for _ in range(horizon):
            classifier = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.LayerNorm(hidden_dim),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.LayerNorm(hidden_dim // 2),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim // 2, num_classes),
            )
            self.classifiers.append(classifier)
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Predicted state embeddings [B, H, D]
            
        Returns:
            Logits [B, H, num_classes]
        """
        batch_size, horizon, dim = x.shape
        assert horizon == self.horizon, f"Expected horizon {self.horizon}, got {horizon}"
        
        logits = []
        for t in range(horizon):
            logit = self.classifiers[t](x[:, t])
            logits.append(logit)
        
        return torch.stack(logits, dim=1)  # [B, H, num_classes]
    
    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """Predict class probabilities per horizon step."""
        logits = self.forward(x)
        return F.softmax(logits, dim=-1)


class TemporalTargetPredictor(nn.Module):
    """
    Target predictor for each future time step.
    """
    
    def __init__(
        self,
        query_dim: int,
        key_dim: int,
        horizon: int = 4,
        num_heads: int = 8,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.horizon = horizon
        
        self.predictors = nn.ModuleList()
        for _ in range(horizon):
            predictor = TargetPredictor(
                query_dim=query_dim,
                key_dim=key_dim,
                num_heads=num_heads,
                dropout=dropout,
            )
            self.predictors.append(predictor)
        
    def forward(
        self,
        queries: torch.Tensor,           # [B, H, D]
        asset_embeddings: torch.Tensor,  # [B, N, D]
        asset_mask: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Predict targets for each horizon step.
        
        Args:
            queries: Predicted state contexts [B, H, D]
            asset_embeddings: Asset embeddings [B, N, D]
            asset_mask: Valid asset mask [B, N]
            
        Returns:
            target_logits: [B, H, N]
            attention_weights: [B, H, N]
        """
        batch_size, horizon, _ = queries.shape
        
        all_logits = []
        all_attn = []
        
        for t in range(horizon):
            logits, attn = self.predictors[t](
                queries[:, t], asset_embeddings, asset_mask
            )
            all_logits.append(logits)
            all_attn.append(attn)
        
        return torch.stack(all_logits, dim=1), torch.stack(all_attn, dim=1)