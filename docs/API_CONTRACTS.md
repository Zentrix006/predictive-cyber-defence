# API Contracts Specification

## Base URL
- Development: `http://localhost:8000/api/v1`
- Production: `https://api.cyber-defence.example.com/api/v1`

## Authentication

### JWT Bearer Token
```
Authorization: Bearer <access_token>
```

### Token Endpoints
- `POST /auth/login` - Username/password → access + refresh tokens
- `POST /auth/refresh` - Refresh token → new access token
- `POST /auth/logout` - Invalidate refresh token

### API Key (Service-to-Service)
```
X-API-Key: <api_key>
```

## Error Responses

### Standard Error Format
```json
{
  "success": false,
  "error": "VALIDATION_ERROR",
  "detail": "Invalid input data",
  "code": "VALIDATION_ERROR",
  "fields": {
    "field_name": ["error message"]
  }
}
```

### HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request (validation error)
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `422` - Unprocessable Entity
- `429` - Too Many Requests
- `500` - Internal Server Error
- `503` - Service Unavailable

## Rate Limiting
- **Authenticated**: 1000 req/min
- **WebSocket**: 50 connections/user
- **Prediction Generation**: 10 req/min

---

## ASSETS API

### List Assets
```
GET /assets
```

**Query Parameters**
| Parameter | Type | Description |
|-----------|------|-------------|
| page | int | Page number (default: 1) |
| page_size | int | Items per page (default: 20, max: 100) |
| status | string[] | Filter by status (comma-separated) |
| asset_type | string[] | Filter by type |
| zone | string[] | Filter by zone |
| criticality | string[] | Filter by criticality |
| search | string | Search hostname/IP |
| incident_id | uuid | Filter by incident |

**Response** (200)
```json
{
  "items": [
    {
      "id": "uuid",
      "hostname": "SERVER-03",
      "ip_address": "10.10.20.15",
      "asset_type": "server",
      "zone": "server_zone",
      "criticality": "high",
      "os": "Linux",
      "os_version": "Ubuntu 22.04",
      "status": "compromised",
      "threat_score": 0.87,
      "last_seen": "2026-01-15T14:20:13Z",
      "incident_id": "uuid",
      "containment_level": "quarantine_vlan",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-15T14:20:13Z"
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 20,
  "total_pages": 8
}
```

### Get Asset Details
```
GET /assets/{asset_id}
```

**Response** (200)
```json
{
  "id": "uuid",
  "hostname": "SERVER-03",
  "ip_address": "10.10.20.15",
  "asset_type": "server",
  "zone": "server_zone",
  "criticality": "high",
  "os": "Linux",
  "os_version": "Ubuntu 22.04",
  "interfaces": [
    {"name": "eth0", "ip_addresses": ["10.10.20.15"], "mac_address": "aa:bb:cc:dd:ee:ff", "vlan": 20, "speed_mbps": 1000}
  ],
  "status": "compromised",
  "threat_score": 0.87,
  "last_seen": "2026-01-15T14:20:13Z",
  "incident_id": "uuid",
  "containment_level": "quarantine_vlan",
  "deception_deployment_id": "uuid",
  "tags": ["database", "production"],
  "metadata": {},
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-15T14:20:13Z"
}
```

### Get Asset Status (Real-time)
```
GET /assets/{asset_id}/status
```

**Response** (200)
```json
{
  "asset_id": "uuid",
  "status": "compromised",
  "threat_score": 0.87,
  "active_connections": 24,
  "suspicious_flows": 8,
  "blocked_flows": 4,
  "auth_failures_5min": 12,
  "cpu_usage": 0.45,
  "memory_usage": 0.62,
  "updated_at": "2026-01-15T14:20:13Z"
}
```

### Contain Asset
```
POST /assets/{asset_id}/contain
```

**Request Body**
```json
{
  "isolation_level": "quarantine_vlan",
  "reason": "Predicted lateral movement to DB-01 (71%)",
  "approved_by": "uuid"
}
```

**Response** (200)
```json
{
  "asset_id": "uuid",
  "action": "contain",
  "success": true,
  "previous_status": "compromised",
  "new_status": "contained",
  "isolation_level": "quarantine_vlan",
  "applied_rules": ["ACL-DENY-10.10.20.15", "VLAN-MOVE-QUARANTINE"],
  "executed_at": "2026-01-15T14:20:13Z"
}
```

### Restore Asset
```
POST /assets/{asset_id}/restore
```

**Request Body**
```json
{
  "reason": "Incident resolved, forensics complete"
}
```

---

## INCIDENTS API

### List Incidents
```
GET /incidents
```

**Query Parameters**
| Parameter | Type | Description |
|-----------|------|-------------|
| page | int | Page number |
| page_size | int | Items per page |
| status | string[] | Filter by status |
| severity | string[] | Filter by severity |
| date_from | datetime | Filter from date |
| date_to | datetime | Filter to date |
| assigned_to | uuid | Filter by assignee |
| search | string | Search title/description |

**Response** (200) - Paginated list of Incident objects

### Create Incident
```
POST /incidents
```

**Request Body**
```json
{
  "title": "Suspicious lateral movement from SERVER-03",
  "description": "World Model predicted lateral movement to DB-01 with 71% probability",
  "severity": "high",
  "source": "auto",
  "source_reference": "WM-PRED-20260115-142007",
  "detected_at": "2026-01-15T14:20:07Z",
  "assets_involved": ["uuid-server-03", "uuid-db-01"],
  "tags": ["lateral-movement", "prediction"]
}
```

**Response** (201) - Incident object

### Get Incident
```
GET /incidents/{incident_id}
```

**Response** (200) - Full Incident object with relationships

### Update Incident
```
PATCH /incidents/{incident_id}
```

**Request Body** - Partial IncidentUpdate

### Close Incident
```
POST /incidents/{incident_id}/close
```

**Request Body**
```json
{
  "reason": "Threat contained, systems restored, forensics complete"
}
```

### Get Incident Timeline
```
GET /incidents/{incident_id}/timeline
```

**Query Parameters**
| Parameter | Type | Description |
|-----------|------|-------------|
| event_types | string[] | Filter event types |
| severity | string[] | Filter by severity |

**Response** (200)
```json
{
  "incident_id": "uuid",
  "events": [
    {
      "id": "uuid",
      "timestamp": "2026-01-15T14:20:01Z",
      "event_type": "network_anomaly_detected",
      "title": "Network anomaly detected",
      "description": "Unusual SMB traffic from SERVER-03",
      "severity": "medium",
      "source": "world_model",
      "asset_ids": ["uuid-server-03"],
      "metadata": {"flow_count": 847, "bytes": 12400000},
      "prediction_id": null
    }
  ]
}
```

---

## PREDICTIONS API

### Get Latest Forecast
```
GET /predictions/{incincident_id}
```

**Response** (200)
```json
{
  "incident_id": "uuid",
  "current_stage": "initial_access",
  "current_confidence": 0.92,
  "timeline": [
    {
      "window_offset": 1,
      "stage": "lateral_movement",
      "probability": 0.78,
      "target_asset_id": "uuid-db-01",
      "target_asset_name": "DB-01",
      "eta_seconds": 30,
      "confidence": 0.78
    },
    {
      "window_offset": 2,
      "stage": "collection",
      "probability": 0.71,
      "target_asset_id": "uuid-db-01",
      "target_asset_name": "DB-01",
      "eta_seconds": 60,
      "confidence": 0.71
    }
  ],
  "predicted_targets": [
    {
      "asset_id": "uuid-db-01",
      "asset_name": "DB-01",
      "asset_type": "database",
      "probability": 0.71,
      "reasoning": ["Database subnet access", "SMB enumeration", "Credential reuse"]
    }
  ],
  "explanation": {
    "feature_importance": {
      "smb_connection_rate": 0.42,
      "auth_failure_rate": 0.36,
      "east_west_traffic": 0.21,
      "tcp_flag_anomaly": 0.09
    },
    "top_factors": [
      {"factor": "smb_connection_rate", "contribution": 0.42, "description": "3.2x increase in SMB connections from SERVER-03"},
      {"factor": "auth_failure_rate", "contribution": 0.36, "description": "Repeated authentication failures to DB-01"}
    ],
    "natural_language": "Lateral Movement predicted (78%) because: 1. 3.2x increase in SMB connections from SERVER-03 (42%) 2. Repeated authentication failures to DB-01 (36%) 3. New east-west traffic to database subnet (21%)"
  },
  "generated_at": "2026-01-15T14:20:09Z",
  "model_version": "wm-v2.1.0"
}
```

### Get Prediction History
```
GET /predictions/{incident_id}/history
```

**Response** (200) - Array of AttackForecast objects

### Generate New Prediction
```
POST /predictions/generate
```

**Request Body**
```json
{
  "incident_id": "uuid",
  "horizon": 4
}
```

**Response** (200) - AttackForecast object

### Get Explanation
```
GET /predictions/{incident_id}/explanation
```

**Response** (200) - Explanation object

---

## TOPOLOGY API

### Get Full Topology
```
GET /topology
```

**Query Parameters**
| Parameter | Type | Description |
|-----------|------|-------------|
| incident_id | uuid | Filter to incident topology |
| include_predictions | bool | Include prediction edges |

**Response** (200)
```json
{
  "nodes": [
    {
      "id": "uuid-server-03",
      "label": "SERVER-03",
      "asset_id": "uuid-server-03",
      "asset_type": "server",
      "zone": "server_zone",
      "status": "compromised",
      "threat_score": 0.87,
      "criticality": "high",
      "position": {"x": 400, "y": 300},
      "metadata": {}
    }
  ],
  "edges": [
    {
      "id": "edge-1",
      "source": "uuid-pc-17",
      "target": "uuid-server-03",
      "protocol": "TCP",
      "port": 445,
      "bytes_transferred": 12400000,
      "packet_count": 847,
      "is_predicted": false,
      "first_seen": "2026-01-15T14:15:00Z",
      "last_seen": "2026-01-15T14:20:10Z"
    }
  ],
  "prediction_edges": [
    {
      "id": "pred-edge-1",
      "source": "uuid-server-03",
      "target": "uuid-db-01",
      "probability": 0.71,
      "predicted_stage": "lateral_movement",
      "eta_seconds": 30,
      "created_at": "2026-01-15T14:20:09Z"
    }
  ],
  "timestamp": "2026-01-15T14:20:13Z",
  "incident_id": "uuid"
}
```

### Get Live Topology (WebSocket)
```
WS /topology/live?incident_id={incident_id}
```

---

## DECEPTION API

### Deploy Honeynet
```
POST /deception/deploy
```

**Request Body**
```json
{
  "incident_id": "uuid",
  "name": "DB-Web Deception for INC-0042",
  "honeypot_types": ["database", "web"],
  "target_assets": ["uuid-db-01"],
  "predicted_stage": "lateral_movement"
}
```

**Response** (201)
```json
{
  "id": "uuid",
  "incident_id": "uuid",
  "name": "DB-Web Deception for INC-0042",
  "honeypot_types": ["database", "web"],
  "target_assets": ["uuid-db-01"],
  "predicted_stage": "lateral_movement",
  "status": "deploying",
  "container_ids": [],
  "network_config": {},
  "deployed_at": null,
  "interactions_count": 0
}
```

### List Deployments
```
GET /deception/deployments
```

**Query Parameters**: incident_id, status

### Get Deployment Details
```
GET /deception/deployments/{deployment_id}
```

**Response** (200) - DeceptionDeployment with honeypot details

### Get Interactions
```
GET /deception/deployments/{deployment_id}/interactions
```

**Response** (200)
```json
{
  "deployment_id": "uuid",
  "interactions": [
    {
      "id": "uuid",
      "deployment_id": "uuid",
      "honeypot_type": "database",
      "container_id": "container-uuid",
      "timestamp": "2026-01-15T14:22:34Z",
      "source_ip": "10.10.20.15",
      "source_port": 54321,
      "destination_port": 3306,
      "protocol": "TCP",
      "action": "auth_attempt",
      "details": {"username": "admin", "password": "password123", "success": false},
      "severity": "medium",
      "mitre_techniques": ["T1110.001"]
    }
  ]
}
```

### Teardown Deployment
```
POST /deception/deployments/{deployment_id}/teardown
```

---

## FORENSICS API

### Get Evidence Index
```
GET /forensics/incidents/{incident_id}/evidence
```

**Response** (200)
```json
{
  "incident_id": "uuid",
  "evidence": [
    {
      "id": "uuid",
      "evidence_type": "pcap",
      "name": "SERVER-03-20260115-142000.pcap",
      "size_bytes": 124000000,
      "sha256_hash": "abc123...",
      "collected_at": "2026-01-15T14:20:15Z"
    }
  ],
  "counts": {
    "pcap": 12,
    "log": 4821,
    "file_event": 1294,
    "honeypot_session": 31,
    "config_snapshot": 4
  }
}
```

### Get PCAP Files
```
GET /forensics/incidents/{incident_id}/pcap
```

**Query Parameters**: asset_id, time_range

### Get Logs
```
GET /forensics/incidents/{incident_id}/logs
```

**Query Parameters**: source, time_range, severity

### Get File Events
```
GET /forensics/incidents/{incident_id}/files
```

**Response** (200) - Array of FileEvent objects

### Get Full Timeline
```
GET /forensics/incidents/{incident_id}/timeline
```

**Response** (200) - Correlated timeline across all sources

---

## CONFIGURATION API

### Create Snapshot
```
POST /config/snapshots
```

**Request Body**
```json
{
  "incident_id": "uuid",
  "label": "Pre-Containment",
  "description": "Network state before isolating SERVER-03",
  "snapshot_type": "containment"
}
```

**Response** (201) - ConfigSnapshot object

### List Snapshots
```
GET /config/snapshots
```

**Query Parameters**: incident_id

### Get Snapshot
```
GET /config/snapshots/{snapshot_id}
```

### Apply Snapshot (Rollback)
```
POST /config/snapshots/{snapshot_id}/apply
```

### Compare Snapshots
```
GET /config/snapshots/diff?from={snapshot_id}&to={snapshot_id}
```

**Response** (200) - ConfigDiff object

---

## WEBSOCKET EVENTS

### Connection
```
WS /ws?token={jwt_token}&incident_id={incident_id}
```

### Subscribe Message (Client → Server)
```json
{
  "type": "subscribe",
  "events": [
    "asset_status_changed",
    "prediction_generated",
    "incident_updated",
    "honeypot_interaction",
    "host_isolated"
  ]
}
```

### Event Message (Server → Client)
```json
{
  "event": "asset_status_changed",
  "timestamp": "2026-01-15T14:20:13.123Z",
  "incident_id": "uuid",
  "payload": {
    "asset_id": "uuid",
    "asset_name": "SERVER-03",
    "old_status": "suspicious",
    "new_status": "compromised",
    "threat_score": 0.87
  }
}
```

### Event Types & Payloads

| Event | Payload Schema |
|-------|----------------|
| `asset_status_changed` | `AssetStatusChangedPayload` |
| `connection_added` | `{source, target, protocol, port, ...}` |
| `connection_removed` | `{edge_id}` |
| `topology_updated` | `{nodes[], edges[]}` |
| `prediction_generated` | `PredictionGeneratedPayload` |
| `forecast_updated` | `{incident_id, forecast: AttackForecast}` |
| `stage_transition` | `{incident_id, from_stage, to_stage, confidence}` |
| `incident_created` | `{incident: Incident}` |
| `incident_updated` | `{incident_id, updates}` |
| `incident_closed` | `{incident_id, reason}` |
| `honeypot_deployed` | `{deployment_id, honeypot_types, target_assets}` |
| `honeypot_interaction` | `HoneypotInteractionPayload` |
| `honeypot_removed` | `{deployment_id}` |
| `host_isolated` | `HostIsolatedPayload` |
| `host_restored` | `{asset_id, previous_status}` |
| `traffic_blocked` | `{rule_id, src, dst, protocol, port}` |
| `snapshot_created` | `{snapshot_id, label, type}` |
| `config_applied` | `{snapshot_id, success}` |
| `evidence_collected` | `{evidence_id, type, name}` |
| `timeline_updated` | `{incident_id, event: TimelineEvent}` |

### Heartbeat
- **Client → Server**: `{"type": "ping"}` every 30s
- **Server → Client**: `{"type": "pong"}` response

---

## HEALTH CHECKS

### Liveness
```
GET /health/live
```
**Response** (200): `{"status": "alive"}`

### Readiness
```
GET /health/ready
```
**Response** (200): `{"status": "ready", "checks": {"database": "ok", "redis": "ok", "ml_engine": "ok"}}`

### Metrics (Prometheus)
```
GET /metrics
```

---

## VERSIONING

- **URL Versioning**: `/api/v1/`
- **Header**: `Accept: application/vnd.cyber-defence.v1+json`
- **Deprecation**: 6-month notice, `Sunset` header

---

## SDK / Client Libraries

### Python
```python
from cyber_defence import CyberDefenceClient

client = CyberDefenceClient(base_url="https://api.example.com", token="jwt")

# Assets
assets = client.assets.list(status=["compromised", "suspicious"])
asset = client.assets.get(asset_id)
client.assets.contain(asset_id, isolation_level="quarantine_vlan")

# Incidents
incident = client.incidents.create(title="...", severity="high")
forecast = client.predictions.get_latest(incident_id)

# WebSocket
async for event in client.ws.subscribe(incident_id, ["asset_status_changed", "prediction_generated"]):
    print(event)
```

### TypeScript
```typescript
import { CyberDefenceClient } from '@cyber-defence/client';

const client = new CyberDefenceClient({ baseUrl: 'https://api.example.com', token: 'jwt' });

// Assets
const assets = await client.assets.list({ status: ['compromised', 'suspicious'] });
await client.assets.contain(assetId, { isolationLevel: 'quarantine_vlan' });

// Incidents
const incident = await client.incidents.create({ title: '...', severity: 'high' });
const forecast = await client.predictions.getLatest(incident.id);

// WebSocket
for await (const event of client.ws.subscribe(incidentId, ['asset_status_changed', 'prediction_generated'])) {
  console.log(event);
}
```