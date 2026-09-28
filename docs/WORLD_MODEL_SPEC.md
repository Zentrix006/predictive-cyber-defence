# World Model Specification

## Overview

The World Model is the core ML component that learns the dynamics of network state evolution and predicts future states. Unlike traditional IDS/IPS that classify individual packets/flows as benign/malicious, the World Model learns:

```
S_t → S_{t+1} → S_{t+2} → ... → S_{t+H}
```

Where `S_t` is the complete network state at time `t`, and `H` is the prediction horizon.

## Problem Formulation

### Input: Network State Representation

Each network state `S_t` captures the complete observable state of the enterprise network at time `t`:

```
S_t = {
    topology: G_t = (V, E_t),           # Network graph
    hosts: {h_i: features_i}_t,          # Per-host feature vectors
    traffic: {flow_j: stats_j}_t,        # Aggregated flow statistics
    temporal: {Δ_t, Δ_{t-1}, ...}        # Temporal context
}
```

### Output: Future State Distribution

The model predicts a distribution over future states:

```
P(S_{t+1}, S_{t+2}, ..., S_{t+H} | S_t, S_{t-1}, ..., S_{t-K})
```

### Attack Stage Mapping

Predicted states are mapped to MITRE ATT&CK stages via a classifier head:

```
Stage_t = f_stage(encode(S_t))
```

## Model Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         WORLD MODEL ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  INPUT SEQUENCE                                                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐           ┌─────────┐               │
│  │ S_{t-2} │  │ S_{t-1} │  │  S_t    │    ...    │ S_{t-K} │               │
│  └────┬────┘  └────┬────┘  └────┬────┘           └────┬────┘               │
│       │            │            │                    │                      │
│       ▼            ▼            ▼                    ▼                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    STATE ENCODER (per timestep)                      │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │   │
│  │  │  Graph      │ │  Host       │ │  Traffic    │ │  Temporal   │   │   │
│  │  │  Encoder    │ │  Encoder    │ │  Encoder    │ │  Encoder    │   │   │
│  │  │  (GNN)      │ │  (MLP)      │ │  (CNN/Trans)│ │  (Positional)│   │   │
│  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘   │   │
│  │         │               │               │               │            │   │
│  │         └───────────────┼───────────────┼───────────────┘            │   │
│  │                         ▼               ▼                            │   │
│  │              ┌─────────────────────────────────┐                    │   │
│  │              │      FUSION LAYER (Attention)   │                    │   │
│  │              └──────────────────┬──────────────┘                    │   │
│  │                                 │                                    │   │
│  │                                 ▼                                    │   │
│  │              ┌─────────────────────────────────┐                    │   │
│  │              │     LATENT STATE z_t ∈ R^d      │                    │   │
│  │              └─────────────────────────────────┘                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │            │            │                    │                      │
│       ▼            ▼            ▼                    ▼                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    TEMPORAL ENCODER (Sequence Model)                 │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  Transformer / Temporal Conv / LSTM                         │   │   │
│  │  │  Input: [z_{t-K}, ..., z_{t-1}, z_t]                       │   │   │
│  │  │  Output: Context vector c_t                                 │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                 │                                          │
│                                 ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    PREDICTION HEADS                                  │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                │   │
│  │  │ State        │ │ Stage        │ │ Target       │                │   │
│  │  │ Decoder      │ │ Classifier   │ │ Predictor    │                │   │
│  │  │ (GNN + MLP)  │ │ (MLP)        │ │ (Attention)  │                │   │
│  │  └──────────────┘ └──────────────┘ └──────────────┘                │   │
│  │       │                │                │                            │   │
│  │       ▼                ▼                ▼                            │   │
│  │  Ŝ_{t+1}          P(stage)         P(target)                        │   │
│  │  Ŝ_{t+2}          (H steps)        (H steps)                        │   │
│  │  ...                                                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1. State Encoder (Per-Timestep)

#### Graph Encoder (Network Topology)
- **Input**: Network graph `G_t = (V, E)` with node features `X_v` and edge features `E_e`
- **Architecture**: Graph Attention Network (GAT) with 3 layers
- **Node Features**: 
  - Asset type (one-hot)
  - Zone (one-hot)
  - Criticality (ordinal)
  - Current status (one-hot)
  - Aggregated traffic stats (degree, weighted degree, clustering)
- **Edge Features**:
  - Protocol (one-hot)
  - Port category (well-known, registered, ephemeral)
  - Traffic volume (log-scaled)
  - Connection state
- **Output**: Node embeddings `H_v ∈ R^d`, Graph embedding `h_G = MEAN(H_v)`

#### Host Encoder
- **Input**: Per-host feature vector (50-100 dimensions)
- **Features**:
  - Connection counts (in/out, successful/failed)
  - Port entropy (src/dst)
  - Protocol distribution
  - Authentication events (success/failure rates)
  - Process/service counts
  - Resource utilization (CPU, memory, disk, network)
  - File system events
  - Threat intelligence matches
- **Architecture**: 3-layer MLP with LayerNorm, ReLU, Dropout
- **Output**: Host embedding `h_host ∈ R^d`

#### Traffic Encoder
- **Input**: Aggregated flow statistics per time window
- **Features** (per window):
  - Flow count, byte/packet totals
  - Protocol/port distributions (histograms)
  - Temporal patterns (inter-arrival times, burstiness)
  - Spatial patterns (source/destination entropy)
  - TCP flag distributions
  - Packet size statistics
- **Architecture**: 1D Temporal Convolution + Attention pooling
- **Output**: Traffic embedding `h_traffic ∈ R^d`

#### Fusion Layer
- **Mechanism**: Cross-attention between graph, host, and traffic embeddings
- **Query**: Graph embedding `h_G`
- **Keys/Values**: Host embeddings `{h_host_i}`, Traffic embedding `h_traffic`
- **Output**: Fused state embedding `z_t ∈ R^d`

### 2. Temporal Encoder (Sequence Model)

- **Architecture**: Transformer encoder (4 layers, 8 heads, d_model=256)
- **Input**: Sequence `[z_{t-K}, ..., z_{t-1}, z_t]` where K=10 (100 seconds at 10s windows)
- **Positional Encoding**: Learned temporal embeddings + sinusoidal
- **Output**: Context vector `c_t` representing temporal dynamics

### 3. Prediction Heads

#### State Decoder (Future State Reconstruction)
- **Architecture**: Graph decoder (reverse GNN) + MLP decoders for host/traffic
- **Input**: Context vector `c_t` + previous state `z_t`
- **Autoregressive**: Predict `S_{t+1}`, then condition on it for `S_{t+2}`, etc.
- **Loss**: MSE on feature vectors + Graph structure loss (edge prediction)

#### Stage Classifier
- **Architecture**: MLP (256 → 128 → 64 → 14 stages)
- **Input**: Context vector `c_t` (or each predicted state embedding)
- **Output**: Probability distribution over 14 MITRE stages per horizon step
- **Loss**: Cross-entropy with label smoothing

#### Target Predictor
- **Architecture**: Attention over asset embeddings
- **Query**: Predicted state embedding
- **Keys/Values**: Asset embeddings from current topology
- **Output**: Probability distribution over assets for each horizon step
- **Loss**: Cross-entropy with focal loss for imbalance

## Training Strategy

### Data Pipeline

```
RAW TELEMETRY (PCAP, NetFlow, Logs, EDR)
         │
         ▼
   ZEEK / PARSERS
         │
         ▼
   TIME WINDOWS (10s default)
         │
         ▼
   STATE CONSTRUCTION
         │
         ▼
   SEQUENCE CREATION
   [S_{t-K}, ..., S_t] → S_{t+1}
         │
         ▼
   LABELING
   - Attack stage per window (MITRE)
   - Target asset (if known)
   - Ground truth from red team / incidents
         │
         ▼
   TRAIN/VAL/TEST SPLIT (temporal!)
```

### Loss Function

```
L_total = λ_state * L_state + λ_stage * L_stage + λ_target * L_target + λ_consistency * L_consistency
```

Where:
- `L_state`: MSE between predicted and actual feature vectors + BCE for graph edges
- `L_stage`: Cross-entropy for stage classification at each horizon
- `L_target`: Cross-entropy for target prediction at each horizon
- `L_consistency`: KL divergence between predicted stage distribution and stage derived from predicted state

### Training Phases

1. **Phase 1 - State Reconstruction** (Self-supervised)
   - Mask random nodes/edges/features, reconstruct
   - Learn meaningful latent representations

2. **Phase 2 - Dynamics Prediction** (Supervised)
   - Predict next state given history
   - Teacher forcing during training

3. **Phase 3 - Attack Forecasting** (Supervised)
   - Add stage/target heads
   - Train on labeled incident data

4. **Phase 4 - Fine-tuning** (RL / Preference)
   - Optimize for decision-making utility
   - Human feedback on prediction quality

## Inference Pipeline

```
LIVE TELEMETRY STREAM
         │
         ▼
   SLIDING WINDOW (10s)
         │
         ▼
   STATE CONSTRUCTION (incremental)
         │
         ▼
   STATE ENCODER → z_t
         │
         ▼
   TEMPORAL BUFFER [z_{t-K}, ..., z_t]
         │
         ▼
   TEMPORAL ENCODER → c_t
         │
         ▼
   PREDICTION HEADS
         │
         ├── State Decoder → Ŝ_{t+1..t+H}
         ├── Stage Classifier → P(stage_{t+1..t+H})
         └── Target Predictor → P(target_{t+1..t+H})
         │
         ▼
   POST-PROCESSING
   - Calibrate probabilities (temperature scaling)
   - Filter low-confidence predictions
   - Map to attack forecast format
         │
         ▼
   DECISION ENGINE
```

## Explainability

### Attention Visualization
- **Graph Attention**: Which nodes/edges the model attends to
- **Temporal Attention**: Which historical windows matter most
- **Cross-Modal Attention**: Graph ↔ Host ↔ Traffic interactions

### Feature Importance
- **SHAP Values**: Per-feature contribution to stage/target predictions
- **Integrated Gradients**: For continuous features
- **Counterfactual**: "What if this connection didn't exist?"

### Natural Language Explanation
Template-based generation:
```
"Lateral Movement predicted (78%) because:
  1. 3.2x increase in SMB connections from SERVER-03 (42%)
  2. Repeated authentication failures to DB-01 (36%)
  3. New east-west traffic to database subnet (21%)"
```

## Model Serving

### Requirements
- **Latency**: <100ms per inference (P99)
- **Throughput**: 10 inferences/second
- **GPU**: 1x A10G / T4 (8GB VRAM)
- **Batch Size**: 1 (real-time) or 32 (batch)

### Optimization
- ONNX export + ONNX Runtime
- FP16 quantization
- Graph optimization (constant folding, operator fusion)
- TensorRT for NVIDIA GPUs

### API Interface

```python
class WorldModelInference:
    def __init__(self, model_path: str, device: str = "cuda"):
        self.session = ort.InferenceSession(model_path, providers=['CUDAExecutionProvider'])
        
    def predict(
        self, 
        state_sequence: list[NetworkState],  # Length K+1
        horizon: int = 4
    ) -> WorldModelOutput:
        """
        Input: List of NetworkState objects (historical + current)
        Output: Predicted states, stage probs, target probs, attention weights
        """
        
    def explain(
        self, 
        state_sequence: list[NetworkState],
        prediction: WorldModelOutput
    ) -> Explanation:
        """Generate SHAP/attention explanations"""
```

## Evaluation Metrics

### State Prediction
- **MSE/MAE** on feature vectors
- **Graph Edit Distance** for topology
- **Node/Edge F1** for structure prediction

### Stage Forecasting
- **Top-1 Accuracy** at each horizon
- **Top-3 Accuracy** at each horizon
- **Brier Score** (calibration)
- **AUC-ROC** per stage

### Target Prediction
- **Hit@1, Hit@3, Hit@5**
- **Mean Reciprocal Rank (MRR)**

### Operational
- **Time-to-Detection** improvement vs baseline
- **False Positive Rate** at decision thresholds
- **Mean Time to Respond** reduction

## Dataset Requirements

### Training Data
- **Normal Traffic**: 30+ days of enterprise traffic
- **Attack Scenarios**: 100+ simulated incidents (red team)
- **Diversity**: Multiple network topologies, asset types, attack vectors
- **Labels**: MITRE stage per window, ground truth targets

### Simulation Environment
- **Network Simulator**: Custom or existing (Mininet, GNS3, Eve-NG)
- **Attack Framework**: Caldera, Atomic Red Team, custom
- **Traffic Generator**: Realistic background traffic + attack injection
- **Telemetry Collection**: Zeek, Suricata, Sysmon, NetFlow

## Versioning & Monitoring

### Model Registry
- **MLflow** for experiment tracking
- **Model versioning** with semantic versioning
- **A/B testing** framework for gradual rollout

### Production Monitoring
- **Prediction drift**: Statistical distance from training distribution
- **Performance drift**: Accuracy on labeled incidents
- **Latency/Error rates**: SLA monitoring
- **Feature importance drift**: Concept drift detection

## Future Extensions

1. **Multi-Agent World Model**: Separate models per zone/segment
2. **Counterfactual Reasoning**: "What if we isolate X?"
3. **Causal Discovery**: Learn causal graph of network dynamics
4. **Federated Learning**: Train across organizations without sharing data
5. **Continuous Learning**: Online adaptation to new attack patterns