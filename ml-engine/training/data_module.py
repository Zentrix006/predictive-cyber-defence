"""
Data Module for World Model Training.
"""
import os
import torch
from torch.utils.data import Dataset, DataLoader
from typing import Dict, List, Optional, Tuple
import pytorch_lightning as pl
from datasets import load_dataset
import numpy as np
from sklearn.preprocessing import RobustScaler, StandardScaler, MinMaxScaler
import pickle


class NetworkSequenceDataset(Dataset):
    """
    Dataset for network state sequences.
    Each sample is a sequence of network states with labels for attack stages/targets.
    """
    
    def __init__(
        self,
        sequences: List[Dict],
        context_window: int = 10,
        horizon: int = 4,
        stage_labels: Optional[List] = None,
        target_labels: Optional[List] = None,
        asset_features: Optional[torch.Tensor] = None,
    ):
        self.sequences = sequences
        self.context_window = context_window
        self.horizon = horizon
        self.stage_labels = stage_labels
        self.target_labels = target_labels
        self.asset_features = asset_features
        
    def __len__(self) -> int:
        return len(self.sequences)
    
    def __getitem__(self, idx: int) -> Dict:
        seq = self.sequences[idx]
        
        # Build sequence dict
        sequence = {
            "node_features": seq["node_features"][:self.context_window],
            "edge_index": seq["edge_index"][:self.context_window],
            "edge_attr": seq["edge_attr"][:self.context_window],
            "batch": seq["batch"][:self.context_window],
            "host_features": seq["host_features"][:self.context_window],
            "host_mask": seq["host_mask"][:self.context_window],
            "traffic_features": seq["traffic_features"][:self.context_window],
        }
        
        current_state = {
            "node_features": seq["node_features"][self.context_window],
            "edge_index": seq["edge_index"][self.context_window],
            "edge_attr": seq["edge_attr"][self.context_window],
            "batch": seq["batch"][self.context_window],
            "host_features": seq["host_features"][self.context_window],
            "host_mask": seq["host_mask"][self.context_window],
            "traffic_features": seq["traffic_features"][self.context_window],
        }
        
        item = {
            "sequence": sequence,
            "current_state": current_state,
        }
        
        if self.stage_labels is not None:
            item["stage_labels"] = self.stage_labels[idx]
        
        if self.target_labels is not None:
            item["target_labels"] = self.target_labels[idx]
            
        if self.asset_features is not None:
            item["asset_features"] = self.asset_features
        
        return item


class CESNETTimeSeriesDataset(Dataset):
    """
    Dataset for CESNET-TimeSeries24 time series data.
    Converts per-IP time series to network state sequences.
    """
    
    def __init__(
        self,
        data_path: str,
        context_window: int = 10,
        horizon: int = 4,
        aggregation: str = "10min",
        max_ips: int = 1000,
        normalize: bool = True,
        scaler_type: str = "robust",
        fill_missing: str = "forward",
    ):
        self.data_path = data_path
        self.context_window = context_window
        self.horizon = horizon
        self.aggregation = aggregation
        self.max_ips = max_ips
        self.normalize = normalize
        self.scaler_type = scaler_type
        self.fill_missing = fill_missing
        
        self.scaler = None
        self.time_series = None
        self.timestamps = None
        self.ip_ids = None
        
        self._load_data()
        self._create_sequences()
    
    def _load_data(self):
        """Load CESNET time series data."""
        # This would load from the actual dataset
        # For now, create synthetic data for testing
        print(f"Loading CESNET data from {self.data_path}")
        
        # In production, this would load from parquet/csv files
        # Example structure:
        # ip_addresses_sample.tar.gz -> CSVs per IP
        # Each CSV has columns: id_time, n_flows, n_packets, n_bytes, ...
        
        # Create synthetic data for testing
        n_ips = min(self.max_ips, 100)
        n_timesteps = 1000
        n_features = 12  # n_flows, n_packets, n_bytes, n_dest_ip, n_dest_asn, n_dest_port, ...
        
        self.time_series = np.random.randn(n_ips, n_timesteps, n_features).astype(np.float32)
        self.timestamps = np.arange(n_timesteps)
        self.ip_ids = np.arange(n_ips)
        
        # Apply normalization
        if self.normalize:
            self._normalize()
    
    def _normalize(self):
        """Normalize time series data."""
        if self.scaler_type == "robust":
            self.scaler = RobustScaler()
        elif self.scaler_type == "standard":
            self.scaler = StandardScaler()
        elif self.scaler_type == "minmax":
            self.scaler = MinMaxScaler()
        else:
            self.scaler = RobustScaler()
        
        # Fit on all data
        n_ips, n_timesteps, n_features = self.time_series.shape
        flat = self.time_series.reshape(-1, n_features)
        self.scaler.fit(flat)
        self.time_series = self.scaler.transform(flat).reshape(n_ips, n_timesteps, n_features)
    
    def _create_sequences(self):
        """Create sliding window sequences from time series."""
        self.sequences = []
        
        n_ips, n_timesteps, n_features = self.time_series.shape
        window_size = self.context_window + self.horizon
        
        for ip_idx in range(n_ips):
            ts = self.time_series[ip_idx]
            
            for t in range(n_timesteps - window_size + 1):
                window = ts[t:t + window_size]
                
                # Create network state representation
                # This is a simplified version - in production, you'd construct
                # proper graph/host/traffic features from the time series
                seq = self._window_to_sequence(window)
                self.sequences.append(seq)
    
    def _window_to_sequence(self, window: np.ndarray) -> Dict:
        """Convert time window to network state sequence."""
        seq_len = window.shape[0]
        n_nodes = 10  # Simplified: 10 nodes per sequence
        
        sequence = {
            "node_features": [],
            "edge_index": [],
            "edge_attr": [],
            "batch": [],
            "host_features": [],
            "host_mask": [],
            "traffic_features": [],
        }
        
        for t in range(seq_len):
            # Node features (use time series features + positional)
            node_feat = np.tile(window[t], (n_nodes, 1))
            # Pad/truncate to expected dimension
            if node_feat.shape[1] < 64:
                padding = np.zeros((n_nodes, 64 - node_feat.shape[1]))
                node_feat = np.concatenate([node_feat, padding], axis=1)
            elif node_feat.shape[1] > 64:
                node_feat = node_feat[:, :64]
            
            sequence["node_features"].append(torch.from_numpy(node_feat).float())
            
            # Edge index (simple ring topology for testing)
            edges = []
            for i in range(n_nodes):
                edges.append([i, (i + 1) % n_nodes])
            edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
            sequence["edge_index"].append(edge_index)
            
            # Edge attributes
            edge_attr = torch.randn(edge_index.shape[1], 16)
            sequence["edge_attr"].append(edge_attr)
            
            # Batch
            batch = torch.zeros(n_nodes, dtype=torch.long)
            sequence["batch"].append(batch)
            
            # Host features
            host_feat = np.tile(window[t], (n_nodes, 1))
            if host_feat.shape[1] < 100:
                padding = np.zeros((n_nodes, 100 - host_feat.shape[1]))
                host_feat = np.concatenate([host_feat, padding], axis=1)
            elif host_feat.shape[1] > 100:
                host_feat = host_feat[:, :100]
            sequence["host_features"].append(torch.from_numpy(host_feat).float())
            
            # Host mask
            host_mask = torch.ones(n_nodes, dtype=torch.bool)
            sequence["host_mask"].append(host_mask)
            
            # Traffic features (sequence of traffic stats)
            traffic_seq = np.tile(window[max(0, t-5):t+1], (1, 1)).reshape(1, -1)
            if traffic_seq.shape[1] < 50 * 20:
                traffic_seq = np.pad(traffic_seq, ((0, 0), (0, 50 * 20 - traffic_seq.shape[1])))
            traffic_seq = traffic_seq.reshape(20, 50)
            sequence["traffic_features"].append(torch.from_numpy(traffic_seq).float())
        
        return sequence
    
    def __len__(self) -> int:
        return len(self.sequences)
    
    def __getitem__(self, idx: int) -> Dict:
        seq = self.sequences[idx]
        
        # Split into context and target
        context_len = self.context_window
        total_len = context_len + self.horizon
        
        sequence = {}
        for key in seq:
            sequence[key] = seq[key][:context_len]
        
        current_state = {}
        for key in seq:
            current_state[key] = seq[key][context_len]
        
        return {
            "sequence": sequence,
            "current_state": current_state,
        }


class NetworkDataModule(pl.LightningDataModule):
    """
    PyTorch Lightning DataModule for network traffic data.
    """
    
    def __init__(self, config: Dict):
        super().__init__()
        self.config = config
        self.batch_size = config.dataloader.batch_size
        self.num_workers = config.dataloader.num_workers
        self.pin_memory = config.dataloader.pin_memory
        self.persistent_workers = config.dataloader.persistent_workers
        self.prefetch_factor = config.dataloader.prefetch_factor
        
        self.train_dataset = None
        self.val_dataset = None
        self.test_dataset = None
    
    def setup(self, stage: Optional[str] = None):
        """Setup datasets for each stage."""
        
        # CESNET-TimeSeries24
        if "cesnet_timeseries24" in self.config:
            ds_config = self.config.cesnet_timeseries24
            
            full_dataset = CESNETTimeSeriesDataset(
                data_path=ds_config.dataset_name,
                context_window=self.config.model.context_window,
                horizon=self.config.model.horizon,
                aggregation=ds_config.aggregation,
                max_ips=ds_config.max_ips,
                normalize=ds_config.normalize,
                scaler_type=ds_config.normalization_method,
                fill_missing=ds_config.fill_missing,
            )
            
            # Split
            total_len = len(full_dataset)
            train_len = int(total_len * ds_config.train_split)
            val_len = int(total_len * ds_config.val_split)
            test_len = total_len - train_len - val_len
            
            self.train_dataset, self.val_dataset, self.test_dataset = \
                torch.utils.data.random_split(
                    full_dataset, [train_len, val_len, test_len],
                    generator=torch.Generator().manual_seed(42)
                )
        
        # UNSW-NB15
        if "unsw_nb15" in self.config:
            # Load from Hugging Face datasets
            # Implementation would go here
            pass
        
        # CICIDS2017
        if "cicids2017" in self.config:
            # Load from Hugging Face datasets
            # Implementation would go here
            pass
    
    def train_dataloader(self) -> DataLoader:
        return DataLoader(
            self.train_dataset,
            batch_size=self.batch_size,
            shuffle=True,
            num_workers=self.num_workers,
            pin_memory=self.pin_memory,
            persistent_workers=self.persistent_workers,
            prefetch_factor=self.prefetch_factor,
            collate_fn=self._collate_fn,
        )
    
    def val_dataloader(self) -> DataLoader:
        return DataLoader(
            self.val_dataset,
            batch_size=self.batch_size,
            shuffle=False,
            num_workers=self.num_workers,
            pin_memory=self.pin_memory,
            persistent_workers=self.persistent_workers,
            prefetch_factor=self.prefetch_factor,
            collate_fn=self._collate_fn,
        )
    
    def test_dataloader(self) -> DataLoader:
        return DataLoader(
            self.test_dataset,
            batch_size=self.batch_size,
            shuffle=False,
            num_workers=self.num_workers,
            pin_memory=self.pin_memory,
            persistent_workers=self.persistent_workers,
            prefetch_factor=self.prefetch_factor,
            collate_fn=self._collate_fn,
        )
    
    def _collate_fn(self, batch: List[Dict]) -> Dict:
        """Custom collate function for batching network sequences."""
        # This handles the nested dictionary structure
        # For now, return as list (batch size 1)
        # In production, implement proper batching
        return batch[0] if len(batch) == 1 else batch


def create_synthetic_dataloader(
    batch_size: int = 32,
    context_window: int = 10,
    horizon: int = 4,
    num_samples: int = 1000,
) -> DataLoader:
    """Create synthetic dataloader for testing."""
    
    dataset = NetworkSequenceDataset(
        sequences=[{
            "node_features": torch.randn(context_window + horizon, 20, 64),
            "edge_index": torch.randint(0, 20, (context_window + horizon, 2, 50)),
            "edge_attr": torch.randn(context_window + horizon, 50, 16),
            "batch": torch.zeros(context_window + horizon, 20, dtype=torch.long),
            "host_features": torch.randn(context_window + horizon, 20, 100),
            "host_mask": torch.ones(context_window + horizon, 20, dtype=torch.bool),
            "traffic_features": torch.randn(context_window + horizon, 20, 50),
        } for _ in range(num_samples)],
        context_window=context_window,
        horizon=horizon,
    )
    
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0,
    )


if __name__ == "__main__":
    # Test synthetic dataloader
    loader = create_synthetic_dataloader(batch_size=4, num_samples=100)
    batch = next(iter(loader))
    print("Batch keys:", batch.keys())
    print("Sequence keys:", batch["sequence"].keys())
    print("Current state keys:", batch["current_state"].keys())
    print("Node features shape:", batch["sequence"]["node_features"][0].shape)