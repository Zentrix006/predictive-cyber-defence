"""
All Encoders for World Model:
- GraphEncoder (GAT) for network topology
- GraphDecoder for state reconstruction
- HostEncoder (MLP) for host features
- TrafficEncoder (TCN + Attention) for traffic stats
- FusionLayer (Cross-Attention) for multi-modal fusion
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, LayerNorm
from torch_geometric.data import Data, Batch
from typing import Optional, List, Tuple


# ============================================================================
# GRAPH ENCODER / DECODER
# ============================================================================

class GraphEncoder(nn.Module):
    """
    Graph Attention Network encoder for network topology.
    
    Encodes network graph structure with node and edge features into
    node embeddings and a global graph embedding.
    """
    
    def __init__(
        self,
        node_input_dim: int,
        edge_input_dim: int,
        hidden_dim: int = 256,
        num_layers: int = 3,
        num_heads: int = 8,
        dropout: float = 0.1,
        residual: bool = True,
        layer_norm: bool = True,
    ):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.residual = residual
        
        # Input projections
        self.node_proj = nn.Linear(node_input_dim, hidden_dim)
        self.edge_proj = nn.Linear(edge_input_dim, hidden_dim)
        
        # GAT layers
        self.gat_layers = nn.ModuleList()
        self.layer_norms = nn.ModuleList() if layer_norm else None
        
        for i in range(num_layers):
            gat = GATConv(
                in_channels=hidden_dim,
                out_channels=hidden_dim // num_heads,
                heads=num_heads,
                dropout=dropout,
                edge_dim=hidden_dim,
                add_self_loops=True,
                fill_value="mean",
            )
            self.gat_layers.append(gat)
            
            if layer_norm:
                self.layer_norms.append(LayerNorm(hidden_dim))
        
        # Output projection
        self.output_proj = nn.Linear(hidden_dim, hidden_dim)
        self.dropout = nn.Dropout(dropout)
        
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor,
        batch: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            x: Node features [num_nodes, node_input_dim]
            edge_index: Edge indices [2, num_edges]
            edge_attr: Edge features [num_edges, edge_input_dim]
            batch: Batch vector [num_nodes]
            
        Returns:
            node_embeddings: [num_nodes, hidden_dim]
            graph_embedding: [batch_size, hidden_dim]
        """
        # Project inputs
        h = self.node_proj(x)
        edge_attr = self.edge_proj(edge_attr)
        
        # GAT layers
        for i, gat in enumerate(self.gat_layers):
            h_residual = h if self.residual else None
            
            h = gat(h, edge_index, edge_attr)
            h = self.dropout(h)
            
            if self.residual and h_residual is not None:
                h = h + h_residual
            
            if self.layer_norms is not None:
                h = self.layer_norms[i](h, batch)
            
            h = F.elu(h)
        
        # Output projection
        node_embeddings = self.output_proj(h)
        
        # Global graph embedding (mean pooling)
        graph_embedding = self._global_mean_pool(node_embeddings, batch)
        
        return node_embeddings, graph_embedding
    
    def _global_mean_pool(self, x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
        """Global mean pooling over nodes per graph."""
        return torch.scatter_reduce(
            torch.zeros(batch.max().item() + 1, x.size(1), device=x.device),
            0,
            batch.unsqueeze(-1).expand_as(x),
            x,
            reduce="mean",
        )


class GraphDecoder(nn.Module):
    """
    Graph decoder for reconstructing network state from latent representation.
    """
    
    def __init__(
        self,
        latent_dim: int,
        hidden_dim: int,
        output_node_dim: int,
        output_edge_dim: int,
        num_layers: int = 3,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.latent_dim = latent_dim
        
        # Node decoder
        self.node_decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, output_node_dim),
        )
        
        # Edge decoder (predict edge existence and features)
        self.edge_decoder = nn.Sequential(
            nn.Linear(latent_dim * 2, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, output_edge_dim + 1),  # +1 for edge existence
        )
        
    def forward(
        self,
        node_latent: torch.Tensor,
        edge_index: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Decode node and edge features from latent representations.
        
        Args:
            node_latent: [num_nodes, latent_dim]
            edge_index: [2, num_edges]
            
        Returns:
            node_features: [num_nodes, output_node_dim]
            edge_features: [num_edges, output_edge_dim]
            edge_logits: [num_edges] (existence probability)
        """
        # Decode node features
        node_features = self.node_decoder(node_latent)
        
        # Decode edge features
        src, dst = edge_index
        edge_latent = torch.cat([node_latent[src], node_latent[dst]], dim=-1)
        edge_output = self.edge_decoder(edge_latent)
        
        edge_logits = edge_output[:, 0]      # Existence logit
        edge_features = edge_output[:, 1:]   # Edge features
        
        return node_features, edge_features, edge_logits


# ============================================================================
# HOST ENCODER
# ============================================================================

class HostEncoder(nn.Module):
    """
    MLP encoder for per-host feature vectors.
    Encodes host-level statistics into latent embeddings.
    """
    
    def __init__(
        self,
        input_dim: int,
        hidden_dims: List[int] = [256, 256],
        output_dim: int = 256,
        dropout: float = 0.1,
        activation: str = "relu",
        layer_norm: bool = True,
    ):
        super().__init__()
        
        self.input_dim = input_dim
        self.output_dim = output_dim
        
        # Activation function
        act_fn = self._get_activation(activation)
        
        # Build layers
        layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_dims:
            layers.append(nn.Linear(prev_dim, hidden_dim))
            if layer_norm:
                layers.append(nn.LayerNorm(hidden_dim))
            layers.append(act_fn)
            layers.append(nn.Dropout(dropout))
            prev_dim = hidden_dim
        
        # Output layer
        layers.append(nn.Linear(prev_dim, output_dim))
        if layer_norm:
            layers.append(nn.LayerNorm(output_dim))
        
        self.encoder = nn.Sequential(*layers)
        
    def _get_activation(self, name: str) -> nn.Module:
        activations = {
            "relu": nn.ReLU(),
            "gelu": nn.GELU(),
            "elu": nn.ELU(),
            "leaky_relu": nn.LeakyReLU(0.1),
            "silu": nn.SiLU(),
        }
        return activations.get(name.lower(), nn.ReLU())
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Host features [batch_size, num_hosts, input_dim] or [num_hosts, input_dim]
            
        Returns:
            Host embeddings [batch_size, num_hosts, output_dim] or [num_hosts, output_dim]
        """
        return self.encoder(x)


# ============================================================================
# TRAFFIC ENCODER
# ============================================================================

class TrafficEncoder(nn.Module):
    """
    Temporal Convolutional Network with Attention for traffic time series.
    Encodes aggregated traffic statistics over time windows.
    """
    
    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 256,
        num_layers: int = 3,
        kernel_sizes: List[int] = [3, 5, 7],
        num_heads: int = 4,
        dropout: float = 0.1,
        max_seq_len: int = 50,
    ):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        
        # Input projection
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        
        # Temporal convolutions with different kernel sizes
        self.temporal_convs = nn.ModuleList()
        for ks in kernel_sizes:
            padding = ks // 2
            conv = nn.Sequential(
                nn.Conv1d(hidden_dim, hidden_dim, kernel_size=ks, padding=padding, groups=hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.GELU(),
                nn.Dropout(dropout),
            )
            self.temporal_convs.append(conv)
        
        # Fusion of multi-scale convolutions
        self.fusion = nn.Sequential(
            nn.Linear(hidden_dim * len(kernel_sizes), hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        
        # Self-attention for temporal dependencies
        self.attention = nn.MultiheadAttention(
            embed_dim=hidden_dim,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True,
        )
        
        # Positional encoding
        self.pos_encoding = nn.Parameter(torch.randn(1, max_seq_len, hidden_dim) * 0.02)
        
        # Output projection
        self.output_proj = nn.Linear(hidden_dim, hidden_dim)
        self.layer_norm = nn.LayerNorm(hidden_dim)
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Traffic features [batch_size, seq_len, input_dim]
            
        Returns:
            Traffic embedding [batch_size, hidden_dim]
        """
        batch_size, seq_len, _ = x.shape
        
        # Input projection
        h = self.input_proj(x)  # [B, L, H]
        
        # Temporal convolutions (need to transpose for Conv1d)
        h_conv = h.transpose(1, 2)  # [B, H, L]
        conv_outputs = []
        for conv in self.temporal_convs:
            conv_out = conv(h_conv)  # [B, H, L]
            conv_outputs.append(conv_out.transpose(1, 2))  # [B, L, H]
        
        # Fuse multi-scale features
        h_fused = torch.cat(conv_outputs, dim=-1)  # [B, L, H * num_scales]
        h_fused = self.fusion(h_fused)  # [B, L, H]
        
        # Add positional encoding
        h_fused = h_fused + self.pos_encoding[:, :seq_len, :]
        
        # Self-attention
        h_attn, _ = self.attention(h_fused, h_fused, h_fused)
        h_attn = h_attn + h_fused  # Residual
        
        # Global pooling over sequence (attention-weighted)
        # Use mean pooling for now, can be enhanced with learnable pooling
        h_pooled = h_attn.mean(dim=1)  # [B, H]
        
        # Output projection
        output = self.output_proj(h_pooled)
        output = self.layer_norm(output)
        
        return output


# ============================================================================
# FUSION LAYER
# ============================================================================

class FusionLayer(nn.Module):
    """
    Cross-attention fusion layer for combining graph, host, and traffic embeddings.
    """
    
    def __init__(
        self,
        query_dim: int,
        key_dim: int,
        value_dim: int,
        num_heads: int = 8,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.num_heads = num_heads
        self.head_dim = query_dim // num_heads
        assert query_dim % num_heads == 0, "query_dim must be divisible by num_heads"
        
        # Projections
        self.q_proj = nn.Linear(query_dim, query_dim)
        self.k_proj = nn.Linear(key_dim, query_dim)
        self.v_proj = nn.Linear(value_dim, query_dim)
        self.out_proj = nn.Linear(query_dim, query_dim)
        
        self.dropout = nn.Dropout(dropout)
        self.layer_norm = nn.LayerNorm(query_dim)
        
        # Modality-specific projections for host and traffic
        self.host_proj = nn.Linear(key_dim, query_dim)
        self.traffic_proj = nn.Linear(value_dim, query_dim)
        
    def forward(
        self,
        graph_emb: torch.Tensor,      # [B, H] - query
        host_emb: torch.Tensor,       # [B, N, H] - key/value
        traffic_emb: torch.Tensor,    # [B, H] - key/value
        host_mask: Optional[torch.Tensor] = None,  # [B, N]
    ) -> torch.Tensor:
        """
        Cross-attention fusion.
        
        Args:
            graph_emb: Graph embedding [B, H]
            host_emb: Host embeddings [B, N, H]
            traffic_emb: Traffic embedding [B, H]
            host_mask: Mask for valid hosts [B, N]
            
        Returns:
            Fused embedding [B, H]
        """
        batch_size = graph_emb.size(0)
        
        # Project graph as query
        q = self.q_proj(graph_emb).unsqueeze(1)  # [B, 1, H]
        
        # Project hosts and traffic as keys/values
        k_host = self.host_proj(host_emb)  # [B, N, H]
        v_host = host_emb  # [B, N, H]
        
        k_traffic = self.traffic_proj(traffic_emb).unsqueeze(1)  # [B, 1, H]
        v_traffic = traffic_emb.unsqueeze(1)  # [B, 1, H]
        
        # Combine keys and values
        k = torch.cat([k_host, k_traffic], dim=1)  # [B, N+1, H]
        v = torch.cat([v_host, v_traffic], dim=1)  # [B, N+1, H]
        
        # Attention mask
        if host_mask is not None:
            # Add True for traffic (always valid)
            traffic_mask = torch.ones(batch_size, 1, device=host_mask.device, dtype=torch.bool)
            mask = torch.cat([host_mask, traffic_mask], dim=1)  # [B, N+1]
            mask = mask.unsqueeze(1).unsqueeze(1)  # [B, 1, 1, N+1]
        else:
            mask = None
        
        # Multi-head attention
        q = q.view(batch_size, 1, self.num_heads, self.head_dim).transpose(1, 2)
        k = k.view(batch_size, -1, self.num_heads, self.head_dim).transpose(1, 2)
        v = v.view(batch_size, -1, self.num_heads, self.head_dim).transpose(1, 2)
        
        # Scaled dot-product attention
        attn_weights = torch.matmul(q, k.transpose(-2, -1)) / (self.head_dim ** 0.5)
        
        if mask is not None:
            attn_weights = attn_weights.masked_fill(~mask, float('-inf'))
        
        attn_weights = F.softmax(attn_weights, dim=-1)
        attn_weights = self.dropout(attn_weights)
        
        attn_output = torch.matmul(attn_weights, v)
        attn_output = attn_output.transpose(1, 2).contiguous().view(batch_size, 1, -1)
        
        # Output projection
        output = self.out_proj(attn_output).squeeze(1)  # [B, H]
        
        # Residual + LayerNorm
        output = self.layer_norm(output + graph_emb)
        
        return output