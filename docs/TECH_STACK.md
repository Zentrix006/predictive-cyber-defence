# Tech Stack Specification

## Backend (FastAPI)

### Core Framework
- **FastAPI** 0.110+ - Modern, fast web framework with automatic OpenAPI docs
- **Uvicorn** - ASGI server for production
- **Pydantic** v2 - Data validation and serialization
- **SQLAlchemy** 2.0 + **Alembic** - ORM and migrations
- **PostgreSQL** 15+ - Primary database
- **Redis** 7+ - Caching, pub/sub, session management
- **Celery** + **Redis** - Background task processing

### ML/World Model
- **PyTorch** 2.2+ - Deep learning framework
- **PyTorch Geometric** - Graph neural networks for network topology
- **scikit-learn** - Preprocessing, traditional ML baselines
- **NumPy/Pandas** - Data manipulation
- **ONNX Runtime** - Model inference optimization

### Network & Telemetry
- **Scapy** - Packet manipulation
- **Zeek** (via subprocess) - Network traffic analysis
- **pcapng** - PCAP file handling
- **netflow** - Flow data parsing

### Deception/Honeynet
- **Docker SDK** - Container orchestration for honeypots
- **Kubernetes client** (optional) - K8s deployment
- **Paramiko** - SSH honeypot interactions

### Observability
- **Prometheus Client** - Metrics
- **structlog** - Structured logging
- **Sentry SDK** - Error tracking

---

## Frontend (Next.js 14+)

### Core Framework
- **Next.js 14** (App Router) - React framework with SSR/SSG
- **React 18** - UI library
- **TypeScript** 5+ - Type safety

### Visualization
- **React Flow** / **Cytoscape.js** - Network topology graph
- **D3.js** - Custom visualizations (attack timeline, prediction graphs)
- **Recharts** / **Chart.js** - Metrics dashboards
- **Canvas/WebGL** - High-performance topology rendering

### State Management
- **Zustand** - Lightweight global state
- **TanStack Query (React Query)** - Server state, caching, WebSocket integration
- **React Hook Form** + **Zod** - Form validation

### UI Components
- **Radix UI** / **Headless UI** - Accessible primitives
- **Tailwind CSS** - Utility-first styling
- **Lucide React** - Icons

### Real-time
- **Socket.io Client** / **Native WebSocket** - Real-time updates
- **EventSource** - SSE fallback

---

## Shared

### Communication
- **WebSocket** - Real-time topology/prediction updates
- **REST API** - CRUD, configuration, forensics
- **Server-Sent Events** - Lightweight streaming

### Data Formats
- **JSON** - API payloads
- **Protocol Buffers** (optional) - High-performance internal communication
- **PCAP/PCAPNG** - Packet captures
- **CSV/Parquet** - Training data export

---

## Infrastructure

### Development
- **Docker Compose** - Local stack
- **Makefile** / **Taskfile** - Build automation
- **Pre-commit** - Code quality hooks

### CI/CD
- **GitHub Actions** - Build, test, deploy
- **Docker** - Containerization
- **Kubernetes** (optional) - Production orchestration

### Monitoring
- **Prometheus + Grafana** - Metrics dashboards
- **Loki** - Log aggregation
- **Jaeger** - Distributed tracing