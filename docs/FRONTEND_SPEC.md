# Frontend Specification (Next.js 14)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      NEXT.JS APPLICATION                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                      APP ROUTER                            │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐         │   │
│  │  │Command  │ │ Network │ │ Attack  │ │Deception│         │   │
│  │  │ Center  │ │  View   │ │  View   │ │  View   │         │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘         │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐         │   │
│  │  │Forensics│ │ World   │ │ Settings│ │  Auth   │         │   │
│  │  │  View   │ │ Model   │ │         │ │         │         │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘         │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   SHARED LAYER                             │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │   │
│  │  │ Components│ │  Hooks   │ │ Services │ │  Store   │     │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘     │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │   │
│  │  │  Types   │ │  Utils   │ │ Styles   │ │  WS      │     │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Page Structure (App Router)

```
frontend/src/app/
├── layout.tsx                 # Root layout with providers
├── page.tsx                   # Redirect to /command-center
├── globals.css                # Global styles + Tailwind
├── providers.tsx              # Context providers (Query, WS, Auth)
├── command-center/
│   ├── page.tsx              # Main dashboard
│   └── components/
├── network/
│   ├── page.tsx              # Network topology view
│   └── components/
├── attack/
│   ├── page.tsx              # Attack progression view
│   └── components/
├── deception/
│   ├── page.tsx              # Honeynet management
│   └── components/
├── forensics/
│   ├── page.tsx              # Evidence & timeline
│   └── components/
├── world-model/
│   ├── page.tsx              # Model internals view
│   └── components/
├── incidents/
│   ├── page.tsx              # Incident list
│   ├── [id]/
│   │   ├── page.tsx          # Incident detail
│   │   ├── timeline/
│   │   ├── evidence/
│   │   └── predictions/
├── settings/
│   ├── page.tsx
│   └── components/
└── api/                      # API route handlers (if needed)
```

## Component Architecture

### Core Components

```
src/components/
├── ui/                       # Base UI components (Radix wrappers)
│   ├── button.tsx
│   ├── card.tsx
│   ├── badge.tsx
│   ├── tabs.tsx
│   ├── dialog.tsx
│   ├── dropdown-menu.tsx
│   ├── tooltip.tsx
│   ├── select.tsx
│   ├── slider.tsx
│   ├── switch.tsx
│   ├── progress.tsx
│   ├── separator.tsx
│   ├── scroll-area.tsx
│   ├── collapsible.tsx
│   └── input.tsx
│
├── topology/                 # Network topology visualization
│   ├── TopologyCanvas.tsx    # Main canvas (React Flow / Cytoscape)
│   ├── Node.tsx              # Asset node component
│   ├── Edge.tsx              # Connection edge component
│   ├── NodePanel.tsx         # Side panel on node click
│   ├── Legend.tsx            # Color/status legend
│   ├── MiniMap.tsx           # Overview minimap
│   ├── Controls.tsx          # Zoom, fit, layout controls
│   ├── PredictionOverlay.tsx # Dotted prediction lines
│   └── HoneypotNodes.tsx     # Purple deception nodes
│
├── prediction/               # Attack forecasting
│   ├── ForecastPanel.tsx     # Main prediction panel
│   ├── StageGraph.tsx        # MITRE stage progression graph
│   ├── TimelineForecast.tsx  # Horizontal timeline view
│   ├── TargetPrediction.tsx  # Predicted targets list
│   ├── ConfidenceMeter.tsx   # Confidence visualization
│   ├── ExplanationPanel.tsx  # Feature importance breakdown
│   └── ProbabilityBars.tsx   # Horizontal probability bars
│
├── timeline/                 # Attack timeline
│   ├── Timeline.tsx          # Main timeline component
│   ├── TimelineEvent.tsx     # Individual event
│   ├── EventFilter.tsx       # Filter by type/severity
│   └── EventDetail.tsx       # Expanded event view
│
├── deception/                # Honeynet management
│   ├── HoneypotPool.tsx      # Available honeypot types
│   ├── ActiveHoneypots.tsx   # Deployed honeypots
│   ├── InteractionFeed.tsx   # Real-time attacker activity
│   ├── DeploymentWizard.tsx  # Guided deployment
│   └── HoneypotNode.tsx      # Topology honeypot node
│
├── forensics/                # Evidence & analysis
│   ├── EvidenceIndex.tsx     # Evidence dashboard
│   ├── PCAPViewer.tsx        # Packet capture viewer
│   ├── LogViewer.tsx         # Log file viewer
│   ├── FileEventTimeline.tsx # File activity timeline
│   ├── ConfigDiff.tsx        # Configuration comparison
│   └── HashVerifier.tsx      # Integrity verification
│
├── incidents/                # Incident management
│   ├── IncidentList.tsx      # Incident table
│   ├── IncidentCard.tsx      # Incident summary card
│   ├── IncidentDetail.tsx    # Full incident view
│   ├── StatusBadge.tsx       # Status indicator
│   └── SeverityIndicator.tsx # Severity display
│
├── world-model/              # Model transparency
│   ├── StateVisualization.tsx # Current state representation
│   ├── TransitionGraph.tsx   # State transitions
│   ├── FeatureImportance.tsx # SHAP/attention weights
│   ├── ModelConfidence.tsx   # Confidence calibration
│   └── LatentSpace.tsx       # Latent space projection
│
├── layout/                   # Layout components
│   ├── Header.tsx            # Top navigation
│   ├── Sidebar.tsx           # Navigation sidebar
│   ├── Footer.tsx            # Status bar
│   ├── Panel.tsx             # Resizable panel
│   └── SplitView.tsx         # Split pane layout
│
└── common/                   # Shared components
    ├── LoadingSkeleton.tsx
    ├── ErrorBoundary.tsx
    ├── EmptyState.tsx
    ├── ConfirmDialog.tsx
    ├── Toaster.tsx
    └── WebSocketStatus.tsx
```

## State Management (Zustand)

### Stores

```typescript
// store/topologyStore.ts
interface TopologyState {
  nodes: Map<string, TopologyNode>;
  edges: Map<string, TopologyEdge>;
  selectedNode: string | null;
  viewMode: 'live' | 'historical';
  layout: LayoutAlgorithm;
  
  // Actions
  setNodes: (nodes: TopologyNode[]) => void;
  updateNode: (id: string, updates: Partial<TopologyNode>) => void;
  setSelectedNode: (id: string | null) => void;
  addPredictionEdge: (edge: PredictionEdge) => void;
  removePredictionEdge: (id: string) => void;
}

// store/incidentStore.ts
interface IncidentState {
  incidents: Incident[];
  activeIncident: Incident | null;
  filters: IncidentFilters;
  
  setIncidents: (incidents: Incident[]) => void;
  setActiveIncident: (incident: Incident | null) => void;
  updateIncident: (id: string, updates: Partial<Incident>) => void;
  setFilters: (filters: IncidentFilters) => void;
}

// store/predictionStore.ts
interface PredictionState {
  currentForecast: AttackForecast | null;
  forecastHistory: AttackForecast[];
  explanation: Explanation | null;
  
  setForecast: (forecast: AttackForecast) => void;
  addToHistory: (forecast: AttackForecast) => void;
  setExplanation: (explanation: Explanation) => void;
}

// store/deceptionStore.ts
interface DeceptionState {
  pool: HoneypotTemplate[];
  deployments: DeceptionDeployment[];
  interactions: Map<string, HoneypotInteraction[]>;
  
  addDeployment: (deployment: DeceptionDeployment) => void;
  updateDeployment: (id: string, updates: Partial<DeceptionDeployment>) => void;
  addInteraction: (deploymentId: string, interaction: HoneypotInteraction) => void;
}

// store/uiStore.ts
interface UIState {
  theme: 'light' | 'dark';
  sidebarOpen: boolean;
  activeView: ViewType;
  notifications: Notification[];
  
  toggleTheme: () => void;
  toggleSidebar: () => void;
  setActiveView: (view: ViewType) => void;
  addNotification: (notification: Notification) => void;
}
```

## WebSocket Integration

### Connection Manager

```typescript
// services/websocket.ts
class WebSocketManager {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 1000;
  
  connect(incidentId?: string): Promise<void>;
  disconnect(): void;
  subscribe(eventTypes: EventType[], handler: EventHandler): () => void;
  send(message: WSMessage): void;
  
  // Event handlers
  onTopologyUpdate: (payload: TopologyUpdate) => void;
  onPredictionUpdate: (payload: PredictionUpdate) => void;
  onIncidentUpdate: (payload: IncidentUpdate) => void;
  onDeceptionEvent: (payload: DeceptionEvent) => void;
  onContainmentEvent: (payload: ContainmentEvent) => void;
}
```

### React Query Integration

```typescript
// hooks/useWebSocket.ts
export function useWebSocket(incidentId?: string) {
  const queryClient = useQueryClient();
  const { addNotification } = useUIStore();
  
  useEffect(() => {
    const ws = new WebSocketManager();
    
    ws.connect(incidentId).then(() => {
      // Subscribe to events
      ws.subscribe(['asset_status_changed'], (payload) => {
        queryClient.setQueryData(['topology'], (old) => 
          updateTopologyNode(old, payload.asset_id, payload.new_status)
        );
      });
      
      ws.subscribe(['prediction_generated'], (payload) => {
        queryClient.setQueryData(['forecast', incidentId], payload.forecast);
        addNotification({ type: 'info', message: 'New prediction available' });
      });
      
      // ... other subscriptions
    });
    
    return () => ws.disconnect();
  }, [incidentId]);
}
```

## Key Views Specification

### 1. Command Center (`/command-center`)

```
┌─────────────────────────────────────────────────────────────────┐
│  PREDICTIVE CYBER DEFENCE                    [Theme] [User] ▼   │
├──────────────────┬────────────────────────────────┬─────────────┤
│                  │                                │             │
│   INCIDENTS      │      LIVE NETWORK TOPOLOGY     │  PREDICTION │
│                  │                                │             │
│  🔴 INC-0042     │    INTERNET                    │  NEXT STAGE │
│  🟡 INC-0041     │         │                      │             │
│                  │    CORE SWITCH                 │ Lateral     │
│  [New Incident]  │    /    │    \                 │ Movement    │
│                  │  🟢   🔴    🟢                 │   78%       │
│                  │        │                       │             │
│                  │        🔵                      │ TARGET      │
│                  │        │                       │ DB-01       │
│                  │        🟣                      │   71%       │
│                  │      / │ \                     │             │
│                  │    🟣 🟣 🟣                    │ ETA         │
│                  │                                │ 30 sec      │
│                  │                                │             │
│                  │  [Zoom] [Fit] [Layout] [Live]  │  [Explain]  │
├──────────────────┴────────────────────────────────┴─────────────┤
│                        ATTACK TIMELINE                            │
│  Detect → Predict → Snapshot → Isolate → Deceive → Observe       │
├──────────────────────────────────────────────────────────────────┤
│ EVIDENCE  |  PCAP  |  HOST EVENTS  |  FILES  |  HONEYNET  | CFG  │
└──────────────────────────────────────────────────────────────────┘
```

### 2. Network View (`/network`)

- Full-screen topology with advanced filtering
- Zone-based grouping (DMZ, Server, User, IoT, Quarantine, Honeynet)
- Traffic flow visualization (animated edges)
- Protocol/port filtering
- Historical playback slider

### 3. Attack View (`/attack`)

- MITRE ATT&CK matrix with current stage highlighted
- Stage progression probability tree
- Target asset ranking
- Kill chain visualization
- Adversary emulation mapping

### 4. Deception View (`/deception`)

- Honeypot pool with resource status
- Deployment wizard (target-driven)
- Real-time interaction feed
- Deception effectiveness metrics
- Attacker TTP extraction

### 5. Forensics View (`/forensics`)

- Evidence dashboard with counts
- PCAP viewer with packet inspection
- Log aggregation with search
- File event timeline (discovered/read/modified/copied/exfiltrated)
- Configuration diff viewer
- Timeline correlation across sources

### 6. World Model View (`/world-model`)

- Current network state tensor visualization
- State transition graph
- Attention heatmap on topology
- Feature importance (SHAP values)
- Latent space projection (t-SNE/UMAP)
- Model confidence calibration curves

## Real-time Updates

### Topology Updates
```typescript
// On WebSocket event: asset_status_changed
queryClient.setQueryData(['topology'], (old: TopologyData) => ({
  ...old,
  nodes: old.nodes.map(node => 
    node.id === payload.asset_id 
      ? { ...node, status: payload.new_status, threatScore: payload.threat_score }
      : node
  )
}));

// Trigger re-render of TopologyCanvas
```

### Prediction Updates
```typescript
// On WebSocket event: prediction_generated
queryClient.setQueryData(['forecast', incidentId], payload.forecast);
// ForecastPanel automatically re-renders with new data
```

### Deception Events
```typescript
// On WebSocket event: honeypot_interaction
queryClient.setQueryData(['deception', deploymentId], (old) => ({
  ...old,
  interactions: [...old.interactions, payload.interaction]
}));
// InteractionFeed updates in real-time
```

## Styling System

### Tailwind Configuration

```javascript
// tailwind.config.ts
export default {
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Status colors
        'status-normal': '#10B981',      // Green
        'status-suspicious': '#F59E0B',  // Yellow
        'status-compromised': '#EF4444', // Red
        'status-contained': '#3B82F6',   // Blue
        'status-deception': '#8B5CF6',   // Purple
        'status-offline': '#6B7280',     // Gray
        
        // Semantic
        'bg-primary': 'var(--bg-primary)',
        'bg-secondary': 'var(--bg-secondary)',
        'text-primary': 'var(--text-primary)',
        'border-primary': 'var(--border-primary)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'flow': 'flow 2s linear infinite',
        'blink': 'blink 1s step-end infinite',
      },
      keyframes: {
        flow: {
          '0%': { strokeDashoffset: '0' },
          '100%': { strokeDashoffset: '100' },
        },
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
      },
    },
  },
};
```

### CSS Variables (globals.css)

```css
:root {
  --bg-primary: #0F172A;
  --bg-secondary: #1E293B;
  --bg-tertiary: #334155;
  --text-primary: #F8FAFC;
  --text-secondary: #94A3B8;
  --border-primary: #334155;
  --accent-blue: #3B82F6;
  --accent-green: #10B981;
  --accent-red: #EF4444;
  --accent-yellow: #F59E0B;
  --accent-purple: #8B5CF6;
}

.light {
  --bg-primary: #FFFFFF;
  --bg-secondary: #F1F5F9;
  --bg-tertiary: #E2E8F0;
  --text-primary: #0F172A;
  --text-secondary: #475569;
  --border-primary: #E2E8F0;
}
```

## Responsive Breakpoints

- **Desktop** (≥1440px): Full multi-panel layout
- **Laptop** (1024-1439px): Collapsible sidebar, stacked panels
- **Tablet** (768-1023px): Tab-based navigation, single panel focus
- **Mobile** (<768px): Simplified views, critical alerts only

## Performance Considerations

### Topology Rendering
- Use **Canvas/WebGL** for >500 nodes (Cytoscape.js with canvas renderer)
- Virtualize off-screen nodes
- Debounce WebSocket updates (50ms)
- Web Workers for layout computation

### Data Fetching
- React Query with stale-while-revalidate
- Prefetch adjacent views
- Pagination for large lists (incidents, evidence)
- WebSocket for real-time, REST for initial load

### Bundle Optimization
- Dynamic imports for heavy views (forensics, world-model)
- Code splitting by route
- Tree-shaking for Radix UI components

## Accessibility

- WCAG 2.1 AA compliance
- Keyboard navigation for all interactive elements
- Screen reader support (ARIA labels, live regions)
- Color-blind safe palette (status colors tested)
- Focus management for modals/panels
- Reduced motion support