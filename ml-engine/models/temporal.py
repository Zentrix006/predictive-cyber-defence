"""
Temporal Encoder using Transformer for sequence modeling.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, Tuple


class TemporalEncoder(nn.Module):
    """
    Transformer-based temporal encoder for learning network state dynamics.
    Processes sequences of fused state embeddings to predict future states.
    """
    
    def __init__(
        self,
        d_model: int = 256,
        nhead: int = 8,
        num_layers: int = 4,
        dim_feedforward: int = 1024,
        dropout: float = 0.1,
        activation: str = "gelu",
        max_seq_len: int = 20,
        positional_encoding: str = "learned",
    ):
        super().__init__()
        self.d_model = d_model
        self.max_seq_len = max_seq_len
        
        # Positional encoding
        if positional_encoding == "learned":
            self.pos_encoder = nn.Parameter(
                torch.randn(1, max_seq_len, d_model) * 0.02
            )
        elif positional_encoding == "sinusoidal":
            self.register_buffer(
                "pos_encoder",
                self._create_sinusoidal_encoding(max_seq_len, d_model)
            )
        else:
            self.pos_encoder = None
        
        # Transformer encoder layers
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            activation=activation,
            batch_first=True,
            norm_first=True,  # Pre-norm for better training
        )
        self.transformer = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers,
            norm=nn.LayerNorm(d_model),
        )
        
        # Output projection
        self.output_proj = nn.Linear(d_model, d_model)
        self.layer_norm = nn.LayerNorm(d_model)
        
    def _create_sinusoidal_encoding(self, max_len: int, d_model: int) -> torch.Tensor:
        """Create sinusoidal positional encodings."""
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2).float() * (-torch.log(torch.tensor(10000.0)) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        return pe.unsqueeze(0)  # [1, max_len, d_model]
    
    def forward(
        self,
        x: torch.Tensor,
        src_key_padding_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Sequence of state embeddings [batch_size, seq_len, d_model]
            src_key_padding_mask: Mask for padding [batch_size, seq_len]
            
        Returns:
            Context vector for last timestep [batch_size, d_model]
            (or full sequence if needed)
        """
        batch_size, seq_len, _ = x.shape
        
        # Add positional encoding
        if self.pos_encoder is not None:
            x = x + self.pos_encoder[:, :seq_len, :]
        
        # Transformer encoding
        # src_key_padding_mask: True = ignore (padding), False = attend
        encoded = self.transformer(
            x,
            src_key_padding_mask=src_key_padding_mask,
        )  # [B, L, D]
        
        # Return last timestep (current state context)
        context = encoded[:, -1, :]  # [B, D]
        
        # Output projection
        context = self.output_proj(context)
        context = self.layer_norm(context)
        
        return context
    
    def forward_full(
        self,
        x: torch.Tensor,
        src_key_padding_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """Return full encoded sequence."""
        batch_size, seq_len, _ = x.shape
        
        if self.pos_encoder is not None:
            x = x + self.pos_encoder[:, :seq_len, :]
        
        encoded = self.transformer(
            x,
            src_key_padding_mask=src_key_padding_mask,
        )
        
        encoded = self.output_proj(encoded)
        encoded = self.layer_norm(encoded)
        
        return encoded


class AutoregressivePredictor(nn.Module):
    """
    Autoregressive predictor for rolling out future states.
    Uses the temporal encoder context to predict next states step by step.
    """
    
    def __init__(
        self,
        d_model: int = 256,
        state_dim: int = 256,
        horizon: int = 4,
        num_layers: int = 2,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.horizon = horizon
        self.state_dim = state_dim
        
        # State transition predictor
        self.transition = nn.Sequential(
            nn.Linear(d_model + state_dim, d_model),
            nn.LayerNorm(d_model),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        
        # Stack of transition layers
        self.transition_layers = nn.ModuleList()
        for _ in range(num_layers - 1):
            self.transition_layers.append(nn.Sequential(
                nn.Linear(d_model, d_model),
                nn.LayerNorm(d_model),
                nn.GELU(),
                nn.Dropout(dropout),
            ))
        
        # Output projection to state space
        self.state_proj = nn.Linear(d_model, state_dim)
        
    def forward(
        self,
        context: torch.Tensor,
        current_state: torch.Tensor,
        teacher_forcing: Optional[torch.Tensor] = None,
        teacher_forcing_ratio: float = 0.0,
    ) -> torch.Tensor:
        """
        Autoregressive rollout.
        
        Args:
            context: Temporal context [B, D]
            current_state: Current state embedding [B, state_dim]
            teacher_forcing: Ground truth future states [B, horizon, state_dim] (for training)
            teacher_forcing_ratio: Probability of using teacher forcing
            
        Returns:
            Predicted states [B, horizon, state_dim]
        """
        batch_size = context.size(0)
        device = context.device
        
        predictions = []
        state = current_state
        
        for t in range(self.horizon):
            # Concatenate context and current state
            x = torch.cat([context, state], dim=-1)  # [B, D + state_dim]
            
            # Predict next state
            h = self.transition(x)
            for layer in self.transition_layers:
                h = layer(h) + h  # Residual
            
            next_state = self.state_proj(h)  # [B, state_dim]
            predictions.append(next_state)
            
            # Teacher forcing for training
            if teacher_forcing is not None and torch.rand(1).item() < teacher_forcing_ratio:
                state = teacher_forcing[:, t]
            else:
                state = next_state
        
        return torch.stack(predictions, dim=1)  # [B, horizon, state_dim]