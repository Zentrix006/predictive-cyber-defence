# Backend Specification (FastAPI)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        FASTAPI APPLICATION                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │   API    │  │   WS     │  │  Auth    │  │ Health   │        │
│  │ Routes   │  │ Handler  │  │          │  │ Checks   │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │             │             │             │               │
│       └─────────────┼─────────────┼─────────────┘               │
│                     ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    CORE SERVICES                           │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │  │
│  │  │ Network  │ │  World   │ │ Decision │ │Containment│     │  │
│  │  │  State   │ │  Model   │ │  Engine  │ │  Engine   │     │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘     │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │  │
│  │  │Deception │ │Forensics │ │ Config   │ │ Evidence │     │  │
│  │  │ Engine   │ │ Engine   │ │Snapshot  │ │  Engine  │     │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                     │                                           │
│       ┌─────────────┼─────────────┐                             │
│       ▼             ▼             ▼                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐                          │
│  │PostgreSQL│  │  Redis  │  │ ML Engine│                         │
│  └─────────┘  └─────────┘  └─────────┘                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Module Structure

```
backend/app/
├── __init__.py
├── main.py                 # FastAPI app factory
├── core/
│   ├── __init__.py
│   ├── config.py           # Settings management (pydantic-settings)
│   ├── database.py         # SQLAlchemy async engine/session
│   ├── redis.py            # Redis connection pool
│   ├── security.py         # JWT, API keys, RBAC
│   ├── logging.py          # Structured logging config
│   └── exceptions.py       # Custom exceptions
├── api/
│   ├── __init__.py
│   ├── deps.py             # Dependency injection
│   ├── v1/
│   │   ├── __init__.py
│   │   ├── router.py       # API v1 router
│   │   ├── endpoints/
│   │   │   ├── __init__.py
│   │   │   ├── assets.py
│   │   │   ├── incidents.py
│   │   │   ├── predictions.py
│   │   │   ├── topology.py
│   │   │   ├── deception.py
│   │   │   ├── forensics.py
│   │   │   ├── config.py
│   │   │   └── evidence.py
│   │   └── schemas/        # Request/Response models
├── ws/
│   ├── __init__.py
│   ├── manager.py          # WebSocket connection manager
│   ├── handlers/
│   │   ├── __init__.py
│   │   ├── topology.py
│   │   ├── predictions.py
│   │   ├── incidents.py
│   │   └── deception.py
│   └── events.py           # Event definitions
├── models/
│   ├── __init__.py
│   ├── base.py             # SQLAlchemy base
│   ├── asset.py
│   ├── incident.py
│   ├── prediction.py
│   ├── topology.py
│   ├── deception.py
│   ├── forensics.py
│   ├── config_snapshot.py
│   └── evidence.py
├── schemas/
│   ├── __init__.py
│   ├── asset.py
│   ├── incident.py
│   ├── prediction.py
│   ├── topology.py
│   ├── deception.py
│   ├── forensics.py
│   ├── config.py
│   └── websocket.py
├── services/
│   ├── __init__.py
│   ├── network_state.py    # Network state construction
│   ├── world_model.py      # World Model inference
│   ├── prediction.py       # Attack forecasting
│   ├── decision.py         # Decision engine
│   ├── containment.py      # Network containment
│   ├── deception.py        # Honeynet management
│   ├── forensics.py        # Evidence collection
│   ├── config_snapshot.py  # Configuration snapshots
│   ├── evidence.py         # Evidence correlation
│   ├── telemetry.py        # Data ingestion
│   └── ml_inference.py     # ML model serving
├── db/
│   ├── __init__.py
│   ├── session.py
│   ├── init_db.py
│   └── repositories/
│       ├── __init__.py
│       ├── asset.py
│       ├── incident.py
│       ├── prediction.py
│       └── ...
└── scripts/
    ├── init_db.py
    ├── seed_data.py
    ├── train_model.py
    └── migrate.py
```

## Core Services Specification

### 1. Network State Service (`services/network_state.py`)

**Responsibility**: Construct network state representations from telemetry

```python
class NetworkStateService:
    """Builds network state vectors from raw telemetry"""
    
    async def construct_state(
        self, 
        window_start: datetime, 
        window_end: datetime
    ) -> NetworkState:
        """Construct network state for a time window"""
        
    async def get_host_features(self, host_id: str, window: TimeWindow) -> HostFeatures:
        """Extract features for a specific host"""
        
    async def get_connection_graph(self, window: TimeWindow) -> nx.Graph:
        """Build network connection graph"""
        
    async def extract_traffic_features(self, flows: list[Flow]) -> TrafficFeatures:
        """Extract statistical features from flow data"""
```

**State Representation**:
```python
@dataclass
class NetworkState:
    timestamp: datetime
    window_size: timedelta
    hosts: dict[str, HostState]
    connections: list[ConnectionState]
    traffic_stats: TrafficStatistics
    graph: nx.Graph  # Network topology graph
    feature_vector: np.ndarray  # Flattened for ML model
```

### 2. World Model Service (`services/world_model.py`)

**Responsibility**: Core ML inference for state transition prediction

```python
class WorldModelService:
    """World Model for network state transition prediction"""
    
    def __init__(self, model_path: str, device: str = "cuda"):
        self.model = self._load_model(model_path)
        self.device = device
        
    def predict_next_state(
        self, 
        current_state: NetworkState,
        horizon: int = 3
    ) -> list[PredictedState]:
        """Roll out future states"""
        
    def predict_transition(
        self, 
        state_t: NetworkState, 
        state_t1: NetworkState
    ) -> TransitionPrediction:
        """Predict next state given current and previous"""
        
    def get_attention_weights(self, state: NetworkState) -> AttentionWeights:
        """Extract explainability features"""
        
    def encode_state(self, state: NetworkState) -> torch.Tensor:
        """Encode network state to latent representation"""
```

**Model Architecture**:
- **Graph Neural Network** (GAT/GraphSAGE) for topology encoding
- **Temporal Convolution** / **Transformer** for sequence modeling
- **Output**: Next state distribution + attack stage probabilities

### 3. Prediction Service (`services/prediction.py`)

**Responsibility**: Translate model outputs to attack forecasts

```python
class PredictionService:
    """Attack stage forecasting and explainability"""
    
    def __init__(
        self, 
        world_model: WorldModelService,
        stage_classifier: StageClassifier
    ):
        self.world_model = world_model
        self.stage_classifier = stage_classifier
        
    async def forecast_attack(
        self, 
        incident_id: str,
        current_state: NetworkState,
        horizon: int = 4
    ) -> AttackForecast:
        """Generate complete attack forecast"""
        
    async def get_stage_probabilities(
        self, 
        predicted_states: list[PredictedState]
    ) -> dict[AttackStage, float]:
        """Map predicted states to MITRE stages"""
        
    async def identify_targets(
        self, 
        forecast: AttackForecast
    ) -> list[PredictedTarget]:
        """Identify likely target assets"""
        
    def explain_prediction(
        self, 
        forecast: AttackForecast
    ) -> Explanation:
        """Generate human-readable explanation"""
```

**Forecast Output**:
```python
@dataclass
class AttackForecast:
    incident_id: str
    current_stage: AttackStage
    current_confidence: float
    timeline: list[ForecastWindow]
    predicted_targets: list[PredictedTarget]
    explanation: Explanation
    generated_at: datetime

@dataclass
class ForecastWindow:
    window_offset: int  # 1, 2, 3, 4
    stage: AttackStage
    probability: float
    target_asset: str | None
    eta_seconds: float
```

### 4. Decision Engine (`services/decision.py`)

**Responsibility**: Evaluate predictions and determine response actions

```python
class DecisionEngine:
    """Policy-based response decision making"""
    
    def __init__(self, policy: ResponsePolicy):
        self.policy = policy
        
    async def evaluate(
        self, 
        forecast: AttackForecast,
        asset_criticality: dict[str, CriticalityLevel],
        current_incident: Incident | None
    ) -> Decision:
        """Evaluate forecast against policy"""
        
    def calculate_risk_score(
        self, 
        forecast: AttackForecast,
        asset_criticality: CriticalityLevel
    ) -> float:
        """Compute composite risk score"""
        
    def select_actions(
        self, 
        risk_score: float,
        forecast: AttackForecast
    ) -> list[ResponseAction]:
        """Select appropriate response actions"""
```

**Decision Output**:
```python
@dataclass
class Decision:
    incident_id: str
    risk_score: float
    actions: list[ResponseAction]
    reasoning: str
    requires_approval: bool
    created_at: datetime

@dataclass
class ResponseAction:
    action_type: ActionType  # CONTAIN, DECEIVE, MONITOR, BLOCK, ALERT
    target_asset: str
    parameters: dict
    priority: int
```

### 5. Containment Engine (`services/containment.py`)

**Responsibility**: Execute network isolation actions

```python
class ContainmentEngine:
    """Network containment and isolation"""
    
    async def isolate_host(
        self, 
        asset_id: str, 
        isolation_level: IsolationLevel
    ) -> ContainmentResult:
        """Move host to quarantine VLAN"""
        
    async def block_traffic(
        self, 
        src: str, 
        dst: str, 
        protocol: str, 
        port: int
    ) -> BlockResult:
        """Apply ACL/firewall rule"""
        
    async def restore_host(self, asset_id: str) -> RestoreResult:
        """Restore host to normal VLAN"""
        
    async def get_containment_status(self, asset_id: str) -> ContainmentStatus:
        """Check current isolation status"""
```

### 6. Deception Engine (`services/deception.py`)

**Responsibility**: Manage adaptive honeynet deployment

```python
class DeceptionEngine:
    """Adaptive honeynet deployment and management"""
    
    def __init__(self, docker_client: DockerClient):
        self.docker = docker_client
        self.honeypot_templates = self._load_templates()
        
    async def deploy_honeynet(
        self, 
        incident_id: str,
        predicted_targets: list[PredictedTarget],
        attack_stage: AttackStage
    ) -> DeceptionDeployment:
        """Deploy honeypots based on prediction"""
        
    async def select_honeypot_types(
        self, 
        predicted_targets: list[PredictedTarget],
        attack_stage: AttackStage
    ) -> list[HoneypotType]:
        """Choose appropriate honeypot types"""
        
    async def connect_to_topology(
        self, 
        deployment: DeceptionDeployment,
        network_topology: NetworkTopology
    ) -> TopologyUpdate:
        """Integrate honeynet into network topology"""
        
    async def capture_interactions(
        self, 
        honeypot_id: str
    ) -> list[HoneypotInteraction]:
        """Collect attacker interactions"""
        
    async def teardown_honeynet(self, deployment_id: str) -> TeardownResult:
        """Clean up honeynet deployment"""
```

**Honeypot Types**:
- **Web** - HTTP/HTTPS services with vulnerable apps
- **SSH** - SSH servers with credential logging
- **Database** - MySQL/PostgreSQL/MongoDB with decoy data
- **SMB** - File shares with decoy documents
- **IoT** - Simulated IoT devices
- **Custom** - Tailored to predicted target

### 7. Forensics Engine (`services/forensics.py`)

**Responsibility**: Evidence collection and correlation

```python
class ForensicsEngine:
    """Incident forensics and evidence management"""
    
    async def create_incident_timeline(
        self, 
        incident_id: str
    ) -> IncidentTimeline:
        """Build chronological event timeline"""
        
    async def collect_pcap(
        self, 
        incident_id: str,
        assets: list[str],
        time_range: TimeRange
    ) -> PCAPCollection:
        """Gather packet captures"""
        
    async def collect_logs(
        self, 
        incident_id: str,
        sources: list[LogSource],
        time_range: TimeRange
    ) -> LogCollection:
        """Aggregate logs from multiple sources"""
        
    async def track_file_events(
        self, 
        incident_id: str,
        host_id: str
    ) -> FileEventTimeline:
        """Track file-level activity"""
        
    async def hash_evidence(self, evidence: Evidence) -> EvidenceHash:
        """Generate cryptographic hashes for integrity"""
```

### 8. Config Snapshot Engine (`services/config_snapshot.py`)

**Responsibility**: Network configuration versioning

```python
class ConfigSnapshotEngine:
    """Network configuration snapshots and rollback"""
    
    async def create_snapshot(
        self, 
        incident_id: str,
        label: str,
        description: str
    ) -> ConfigSnapshot:
        """Capture current network configuration"""
        
    async def apply_snapshot(self, snapshot_id: str) -> ApplyResult:
        """Rollback to previous configuration"""
        
    async def diff_snapshots(
        self, 
        from_id: str, 
        to_id: str
    ) -> ConfigDiff:
        """Compare two configurations"""
        
    async def get_snapshot_history(
        self, 
        incident_id: str
    ) -> list[ConfigSnapshot]:
        """Get all snapshots for an incident"""
```

---

## WebSocket Event System

### Event Types

```python
class EventType(str, Enum):
    # Topology events
    ASSET_STATUS_CHANGED = "asset_status_changed"
    CONNECTION_ADDED = "connection_added"
    CONNECTION_REMOVED = "connection_removed"
    TOPOLOGY_UPDATED = "topology_updated"
    
    # Prediction events
    PREDICTION_GENERATED = "prediction_generated"
    FORECAST_UPDATED = "forecast_updated"
    STAGE_TRANSITION = "stage_transition"
    
    # Incident events
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_CLOSED = "incident_closed"
    
    # Deception events
    HONEYPOT_DEPLOYED = "honeypot_deployed"
    HONEYPOT_INTERACTION = "honeypot_interaction"
    HONEYPOT_REMOVED = "honeypot_removed"
    
    # Containment events
    HOST_ISOLATED = "host_isolated"
    HOST_RESTORED = "host_restored"
    TRAFFIC_BLOCKED = "traffic_blocked"
    
    # Config events
    SNAPSHOT_CREATED = "snapshot_created"
    CONFIG_APPLIED = "config_applied"
    
    # Forensics events
    EVIDENCE_COLLECTED = "evidence_collected"
    TIMELINE_UPDATED = "timeline_updated"
```

### WebSocket Message Format

```json
{
  "event": "asset_status_changed",
  "timestamp": "2026-01-15T14:20:13.123Z",
  "incident_id": "INC-0042",
  "payload": {
    "asset_id": "SERVER-03",
    "old_status": "suspicious",
    "new_status": "compromised",
    "threat_score": 0.87
  }
}
```

---

## API Endpoints

### Assets
- `GET /api/v1/assets` - List all assets
- `GET /api/v1/assets/{asset_id}` - Get asset details
- `GET /api/v1/assets/{asset_id}/status` - Real-time status
- `POST /api/v1/assets/{asset_id}/contain` - Initiate containment
- `POST /api/v1/assets/{asset_id}/restore` - Restore from containment

### Incidents
- `GET /api/v1/incidents` - List incidents (with filters)
- `POST /api/v1/incidents` - Create incident
- `GET /api/v1/incidents/{incident_id}` - Get incident details
- `GET /api/v1/incidents/{incident_id}/timeline` - Attack timeline
- `PATCH /api/v1/incidents/{incident_id}` - Update incident
- `POST /api/v1/incidents/{incident_id}/close` - Close incident

### Predictions
- `GET /api/v1/predictions/{incident_id}` - Get latest forecast
- `GET /api/v1/predictions/{incident_id}/history` - Prediction history
- `GET /api/v1/predictions/{incident_id}/explanation` - Explainability
- `POST /api/v1/predictions/generate` - Trigger new prediction

### Topology
- `GET /api/v1/topology` - Full network topology
- `GET /api/v1/topology/live` - Live topology (WebSocket)
- `GET /api/v1/topology/{asset_id}/neighbors` - Asset neighbors

### Deception
- `POST /api/v1/deception/deploy` - Deploy honeynet
- `GET /api/v1/deception/deployments` - List deployments
- `GET /api/v1/deception/deployments/{deployment_id}` - Deployment details
- `GET /api/v1/deception/deployments/{deployment_id}/interactions` - Attacker interactions
- `POST /api/v1/deception/deployments/{deployment_id}/teardown` - Remove honeynet

### Forensics
- `GET /api/v1/forensics/incidents/{incident_id}/evidence` - Evidence index
- `GET /api/v1/forensics/incidents/{incident_id}/pcap` - PCAP files
- `GET /api/v1/forensics/incidents/{incident_id}/logs` - Log files
- `GET /api/v1/forensics/incidents/{incident_id}/files` - File events
- `GET /api/v1/forensics/incidents/{incident_id}/timeline` - Full timeline

### Configuration
- `POST /api/v1/config/snapshots` - Create snapshot
- `GET /api/v1/config/snapshots` - List snapshots
- `GET /api/v1/config/snapshots/{snapshot_id}` - Get snapshot
- `POST /api/v1/config/snapshots/{snapshot_id}/apply` - Apply snapshot
- `GET /api/v1/config/snapshots/diff` - Compare snapshots