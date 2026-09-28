import { create } from 'zustand';
import { TopologyNode, TopologyEdge, PredictionEdge } from '@/types';

interface TopologyState {
  nodes: Map<string, TopologyNode>;
  edges: Map<string, TopologyEdge>;
  predictionEdges: Map<string, PredictionEdge>;
  selectedNode: TopologyNode | null;
  viewMode: 'live' | 'historical';
  layout: string;
  
  // Actions
  setNodes: (nodes: TopologyNode[]) => void;
  addNode: (node: TopologyNode) => void;
  updateNode: (id: string, updates: Record<string, any>) => void;
  setEdges: (edges: TopologyEdge[]) => void;
  setPredictionEdges: (edges: PredictionEdge[]) => void;
  addPredictionEdge: (edge: PredictionEdge) => void;
  removePredictionEdge: (id: string) => void;
  setSelectedNode: (node: TopologyNode | null) => void;
  setViewMode: (mode: 'live' | 'historical') => void;
  setLayout: (layout: string) => void;
  clearSelection: () => void;
}

export const useTopologyStore = create<TopologyState>((set) => ({
  nodes: new Map(),
  edges: new Map(),
  predictionEdges: new Map(),
  selectedNode: null,
  viewMode: 'live',
  layout: 'cose-bilkent',
  
  setNodes: (nodes) => set({ nodes: new Map((Array.isArray(nodes) ? nodes : []).map(n => [n.id, n])) }),
  addNode: (node) => set((state) => {
    const newNodes = new Map(state.nodes);
    newNodes.set(node.id, node);
    return { nodes: newNodes };
  }),
  updateNode: (id, updates) => set((state) => {
    const newNodes = new Map(state.nodes);
    const node = newNodes.get(id);
    if (node) newNodes.set(id, { ...node, ...updates });
    return { nodes: newNodes };
  }),
  setEdges: (edges) => set({ edges: new Map((Array.isArray(edges) ? edges : []).map(e => [e.id, e])) }),
  setPredictionEdges: (edges) => set({ predictionEdges: new Map((Array.isArray(edges) ? edges : []).map(e => [e.id, e])) }),
  addPredictionEdge: (edge) => set((state) => {
    const newEdges = new Map(state.predictionEdges);
    newEdges.set(edge.id, edge);
    return { predictionEdges: newEdges };
  }),
  removePredictionEdge: (id) => set((state) => {
    const newEdges = new Map(state.predictionEdges);
    newEdges.delete(id);
    return { predictionEdges: newEdges };
  }),
  setSelectedNode: (node) => set({ selectedNode: node }),
  setViewMode: (mode) => set({ viewMode: mode }),
  setLayout: (layout) => set({ layout }),
  clearSelection: () => set({ selectedNode: null }),
}));