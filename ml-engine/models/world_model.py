"""
Main World Model Architecture
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, Dict, Tuple, List
from dataclasses import dataclass

from .encoders import GraphEncoder, HostEncoder, TrafficEncoder, FusionLayer, GraphDecoder
from .temporal import TemporalEncoder, AutoregressivePredictor
from .heads import (
    StageClassifier, 
    TargetPredictor, 
    TemporalStageClassifier, 
    TemporalTargetPredictor,
)


@dataclass
class WorldModelOutput:
    """Output container for World Model forward pass."""
    # Encoded representations
    node_embeddings: torch.Tensor          # [B, N, D] or [N, D]
    graph_embedding: torch.Tensor          # [B, D]
    host_embeddings: torch.Tensor          # [B, N, D]
    traffic_embedding: torch.Tensor        # [B, D]
    fused_embedding: torch.Tensor          # [B, D]
    temporal_context: torch.Tensor         # [B, D]
    
    # Predictions
    predicted_states: torch.Tensor         # [B, H, state_dim]
    stage_logits: torch.Tensor             # [B, H, num_stages]
    stage_probs: torch.Tensor              # [B, H, num_stages]
    target_logits: torch.Tensor            # [B, H, N]
    target_probs: torch.Tensor             # [B, H, N]
    
    # Reconstruction
    recon_node_features: Optional[torch.Tensor] = None
    recon_edge_features: Optional[torch.Tensor] = None
    recon_edge_logits: Optional[torch.Tensor] = None
    
    # Attention weights for explainability
    attention_weights: Optional[Dict[str, torch.Tensor]] = None


class WorldModel(nn.Module):
    """
    World Model for Network State Prediction.
    
    Learns the dynamics of network state evolution:
    S_t -> S_{t+1} -> S_{t+2} -> ... -> S_{t+H}
    
    Architecture:
    1. State Encoder (per timestep):
       - Graph Encoder (GAT) for topology
       - Host Encoder (MLP) for host features
       - Traffic Encoder (TCN + Attention) for traffic stats
       - Fusion Layer (Cross-Attention)
    2. Temporal Encoder (Transformer) for sequence modeling
    3. Prediction Heads:
       - State Decoder (Graph Decoder)
       - Stage Classifier (MLP)
       - Target Predictor (Attention)
    """
    
    def __init__(
        self,
        # Graph encoder
        node_input_dim: int = 64,
        edge_input_dim: int = 16,
        # Host encoder
        host_input_dim: int = 100,
        # Traffic encoder
        traffic_input_dim: int = 50,
        # Shared dimensions
        hidden_dim: int = 256,
        num_heads: int = 8,
        dropout: float = 0.1,
        # Temporal
        context_window: int = 10,
        horizon: int = 4,
        # Heads
        num_stages: int = 14,
        max_assets: int = 1000,
    ):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.horizon = horizon
        self.context_window = context_window
        self.num_stages = num_stages
        
        # ============ STATE ENCODERS (per timestep) ============
        
        # Graph Encoder
        self.graph_encoder = GraphEncoder(
            node_input_dim=node_input_dim,
            edge_input_dim=edge_input_dim,
            hidden_dim=hidden_dim,
            num_layers=3,
            num_heads=num_heads,
            dropout=dropout,
        )
        
        # Host Encoder
        self.host_encoder = HostEncoder(
            input_dim=host_input_dim,
            hidden_dims=[hidden_dim, hidden_dim],
            output_dim=hidden_dim,
            dropout=dropout,
        )
        
        # Traffic Encoder
        self.traffic_encoder = TrafficEncoder(
            input_dim=traffic_input_dim,
            hidden_dim=hidden_dim,
            num_layers=3,
            kernel_sizes=[3, 5, 7],
            num_heads=num_heads // 2,
            dropout=dropout,
        )
        
        # Fusion Layer
        self.fusion = FusionLayer(
            query_dim=hidden_dim,
            key_dim=hidden_dim,
            value_dim=hidden_dim,
            num_heads=num_heads,
            dropout=dropout,
        )
        
        # ============ TEMPORAL ENCODER ============
        self.temporal_encoder = TemporalEncoder(
            d_model=hidden_dim,
            nhead=num_heads,
            num_layers=4,
            dim_feedforward=hidden_dim * 4,
            dropout=dropout,
            activation="gelu",
            max_seq_len=context_window + horizon,
            positional_encoding="learned",
        )
        
        # ============ PREDICTION HEADS ============
        
        # State Decoder (for reconstruction)
        self.state_decoder = GraphDecoder(
            latent_dim=hidden_dim,
            hidden_dim=hidden_dim,
            output_node_dim=node_input_dim,
            output_edge_dim=edge_input_dim,
            num_layers=3,
            dropout=dropout,
        )
        
        # Autoregressive State Predictor
        self.state_predictor = AutoregressivePredictor(
            d_model=hidden_dim,
            state_dim=hidden_dim,
            horizon=horizon,
            num_layers=2,
            dropout=dropout,
        )
        
        # Stage Classifier (per horizon step)
        self.stage_classifier = TemporalStageClassifier(
            input_dim=hidden_dim,
            horizon=horizon,
            hidden_dim=hidden_dim // 2,
            num_classes=num_stages,
            dropout=dropout,
        )
        
        # Target Predictor (per horizon step)
        self.target_predictor = TemporalTargetPredictor(
            query_dim=hidden_dim,
            key_dim=hidden_dim,
            horizon=horizon,
            num_heads=num_heads,
            dropout=dropout,
        )
        
        # ============ STATE PROJECTION ============
        # Project fused embedding to state dimension
        self.state_proj = nn.Linear(hidden_dim, hidden_dim)
        self.state_norm = nn.LayerNorm(hidden_dim)
        
    def encode_state(
        self,
        # Graph data
        node_features: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor,
        batch: torch.Tensor,
        # Host data
        host_features: torch.Tensor,
        # Traffic data
        traffic_features: torch.Tensor,
        host_mask: Optional[torch.Tensor] = None,
    ) -> Tuple[
        torch.Tensor,  # node_embeddings
        torch.Tensor,  # graph_embedding
        torch.Tensor,  # host_embeddings
        torch.Tensor,  # traffic_embedding
        torch.Tensor,  # fused_embedding
    ]:
        """
        Encode a single network state.
        
        Args:
            node_features: [N, node_input_dim] or [B, N, node_input_dim]
            edge_index: [2, E] or [B, 2, E]
            edge_attr: [E, edge_input_dim] or [B, E, edge_input_dim]
            batch: [N] or [B, N]
            host_features: [N, host_input_dim] or [B, N, host_input_dim]
            host_mask: [N] or [B, N] (optional)
            traffic_features: [B, L, traffic_input_dim] or [L, traffic_input_dim]
            
        Returns:
            Tuple of embeddings
        """
        # Handle batched vs unbatched inputs
        is_batched = node_features.dim() == 3
        
        if not is_batched:
            # Add batch dimension
            node_features = node_features.unsqueeze(0)
            edge_index = edge_index.unsqueeze(0)
            edge_attr = edge_attr.unsqueeze(0)
            batch = batch.unsqueeze(0)
            host_features = host_features.unsqueeze(0)
            traffic_features = traffic_features.unsqueeze(0)
            if host_mask is not None:
                host_mask = host_mask.unsqueeze(0)
        
        batch_size = node_features.size(0)
        
        # Graph encoding
        node_emb, graph_emb = self.graph_encoder(
            node_features.view(-1, node_features.size(-1)),
            edge_index.view(2, -1),
            edge_attr.view(-1, edge_attr.size(-1)),
            batch.view(-1),
        )
        
        # Reshape node embeddings
        node_emb = node_emb.view(batch_size, -1, self.hidden_dim)
        
        # Host encoding
        host_emb = self.host_encoder(host_features)
        
        # Traffic encoding
        traffic_emb = self.traffic_encoder(traffic_features)
        
        # Fusion
        fused_emb = self.fusion(
            graph_emb=graph_emb,
            host_emb=host_emb,
            traffic_emb=traffic_emb,
            host_mask=host_mask,
        )
        
        return node_emb, graph_emb, host_emb, traffic_emb, fused_emb
    
    def forward(
        self,
        # Sequence of states (context_window + 1 for current)
        sequence: Dict[str, List[torch.Tensor]],
        # Current state (for autoregressive start)
        current_state: Dict[str, torch.Tensor],
        # Assets for target prediction
        asset_embeddings: Optional[torch.Tensor] = None,
        asset_mask: Optional[torch.Tensor] = None,
        # Teacher forcing
        teacher_forcing_states: Optional[torch.Tensor] = None,
        teacher_forcing_ratio: float = 0.0,
    ) -> WorldModelOutput:
        """
        Full forward pass: encode sequence -> predict future.
        
        Args:
            sequence: Dict with lists of tensors for each timestep:
                - node_features: List of [B, N, D]
                - edge_index: List of [B, 2, E]
                - edge_attr: List of [B, E, D]
                - batch: List of [B, N]
                - host_features: List of [B, N, D]
                - host_mask: List of [B, N]
                - traffic_features: List of [B, L, D]
            current_state: Dict with tensors for current timestep
            asset_embeddings: [B, N, D] asset embeddings
            asset_mask: [B, N] valid asset mask
            teacher_forcing_states: [B, H, D] ground truth future states
            teacher_forcing_ratio: Probability of teacher forcing
            
        Returns:
            WorldModelOutput with all predictions
        """
        batch_size = sequence["node_features"][0].size(0)
        seq_len = len(sequence["node_features"])
        
        # Encode each timestep in sequence
        fused_embeddings = []
        
        for t in range(seq_len):
            node_emb, graph_emb, host_emb, traffic_emb, fused_emb = self.encode_state(
                node_features=sequence["node_features"][t],
                edge_index=sequence["edge_index"][t],
                edge_attr=sequence["edge_attr"][t],
                batch=sequence["batch"][t],
                host_features=sequence["host_features"][t],
                host_mask=sequence.get("host_mask", [None] * seq_len)[t],
                traffic_features=sequence["traffic_features"][t],
            )
            fused_embeddings.append(fused_emb)
        
        # Stack sequence [B, L, D]
        sequence_emb = torch.stack(fused_embeddings, dim=1)
        
        # Temporal encoding
        temporal_context = self.temporal_encoder(sequence_emb)
        
        # Current state encoding
        _, _, _, _, current_fused = self.encode_state(
            node_features=current_state["node_features"],
            edge_index=current_state["edge_index"],
            edge_attr=current_state["edge_attr"],
            batch=current_state["batch"],
            host_features=current_state["host_features"],
            host_mask=current_state.get("host_mask"),
            traffic_features=current_state["traffic_features"],
        )
        
        # Project current state
        current_state_emb = self.state_proj(current_fused)
        current_state_emb = self.state_norm(current_state_emb)
        
        # Autoregressive state prediction
        predicted_states = self.state_predictor(
            context=temporal_context,
            current_state=current_state_emb,
            teacher_forcing=teacher_forcing_states,
            teacher_forcing_ratio=teacher_forcing_ratio,
        )  # [B, H, D]
        
        # Stage classification per horizon step
        stage_logits = self.stage_classifier(predicted_states)  # [B, H, num_stages]
        stage_probs = F.softmax(stage_logits, dim=-1)
        
        # Target prediction per horizon step
        if asset_embeddings is not None:
            target_logits, target_attn = self.target_predictor(
                queries=predicted_states,
                asset_embeddings=asset_embeddings,
                asset_mask=asset_mask,
            )  # [B, H, N]
            target_probs = F.softmax(target_logits, dim=-1)
        else:
            target_logits = None
            target_probs = None
            target_attn = None
        
# Reconstruction (for current state)
        # Use batched edge_index from sequence
        curr_edge_index = current_state["edge_index"]
        if curr_edge_index.dim() == 3:
            # Convert [B, 2, E] to [2, B*E] format
            b, _, e = curr_edge_index.shape
            curr_edge_index = curr_edge_index.permute(1, 0, 2).reshape(2, b * e)
        
        # Use node embeddings for decoder (shape: [B, N, D] or [N, D])
        node_latent = node_emb[0] if node_emb.dim() == 3 else node_emb
        
        recon_node, recon_edge, recon_edge_logits = self.state_decoder(
            node_latent=node_latent,
            edge_index=curr_edge_index,
        )
        
        return WorldModelOutput(
            node_embeddings=node_emb,
            graph_embedding=graph_emb,
            host_embeddings=host_emb,
            traffic_embedding=traffic_emb,
            fused_embedding=current_fused,
            temporal_context=temporal_context,
            predicted_states=predicted_states,
            stage_logits=stage_logits,
            stage_probs=stage_probs,
            target_logits=target_logits,
            target_probs=target_probs,
            recon_node_features=recon_node,
            recon_edge_features=recon_edge,
            recon_edge_logits=recon_edge_logits,
            attention_weights={
                "target_attention": target_attn,
            } if target_attn is not None else None,
        )
    
    def predict(
        self,
        current_state: Dict[str, torch.Tensor],
        asset_embeddings: Optional[torch.Tensor] = None,
        asset_mask: Optional[torch.Tensor] = None,
    ) -> WorldModelOutput:
        """
        Inference: predict future from single current state (with context buffer).
        
        For streaming inference, maintain a buffer of past fused embeddings.
        """
        # Encode current state
        node_emb, graph_emb, host_emb, traffic_emb, fused_emb = self.encode_state(
            node_features=current_state["node_features"],
            edge_index=current_state["edge_index"],
            edge_attr=current_state["edge_attr"],
            batch=current_state["batch"],
            host_features=current_state["host_features"],
            host_mask=current_state.get("host_mask"),
            traffic_features=current_state["traffic_features"],
        )
        
        # For single-state inference, we need historical context
        # This would typically come from a buffer maintained externally
        # For now, use current fused embedding as context (placeholder)
        temporal_context = self.temporal_encoder(fused_emb.unsqueeze(1)).squeeze(1)
        
        # Project current state
        current_state_emb = self.state_proj(fused_emb)
        current_state_emb = self.state_norm(current_state_emb)
        
        # Predict
        predicted_states = self.state_predictor(
            context=temporal_context,
            current_state=current_state_emb,
        )
        
        # Stage classification
        stage_logits = self.stage_classifier(predicted_states)
        stage_probs = F.softmax(stage_logits, dim=-1)
        
        # Target prediction
        if asset_embeddings is not None:
            target_logits, target_attn = self.target_predictor(
                queries=predicted_states,
                asset_embeddings=asset_embeddings,
                asset_mask=asset_mask,
            )
            target_probs = F.softmax(target_logits, dim=-1)
        else:
            target_logits = None
            target_probs = None
            target_attn = None
        
        return WorldModelOutput(
            node_embeddings=node_emb,
            graph_embedding=graph_emb,
            host_embeddings=host_emb,
            traffic_embedding=traffic_emb,
            fused_embedding=fused_emb,
            temporal_context=temporal_context,
            predicted_states=predicted_states,
            stage_logits=stage_logits,
            stage_probs=stage_probs,
            target_logits=target_logits,
            target_probs=target_probs,
            attention_weights={"target_attention": target_attn} if target_attn is not None else None,
        )
    
    def get_attention_weights(self) -> Dict[str, torch.Tensor]:
        """Extract attention weights for explainability."""
        weights = {}
        
        # Graph attention (from GAT)
        # Would need to modify GraphEncoder to return attention
        
        # Fusion attention
        # Would need to modify FusionLayer to return attention
        
        # Temporal attention
        # Would need to modify TemporalEncoder to return attention
        
        return weights


# ============ FACTORY FUNCTION ============

def create_world_model(config: Dict) -> WorldModel:
    """Create World Model from configuration dictionary."""
    return WorldModel(
        node_input_dim=config.get("node_input_dim", 64),
        edge_input_dim=config.get("edge_input_dim", 16),
        host_input_dim=config.get("host_input_dim", 100),
        traffic_input_dim=config.get("traffic_input_dim", 50),
        hidden_dim=config.get("hidden_dim", 256),
        num_heads=config.get("num_heads", 8),
        dropout=config.get("dropout", 0.1),
        context_window=config.get("context_window", 10),
        horizon=config.get("horizon", 4),
        num_stages=config.get("num_stages", 14),
        max_assets=config.get("max_assets", 1000),
    )