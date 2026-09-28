import React, { useMemo } from 'react';
import ReactFlow, { Background, Controls, Node, Edge, MarkerType } from 'reactflow';
import 'reactflow/dist/style.css';

const initialNodes: Node[] = [
  { id: '1', position: { x: 250, y: 50 }, data: { label: 'Gateway Router' }, style: { backgroundColor: '#1e293b', color: '#94a3b8', borderColor: '#334155' } },
  { id: '2', position: { x: 100, y: 150 }, data: { label: 'Switch A' }, style: { backgroundColor: '#1e293b', color: '#94a3b8', borderColor: '#334155' } },
  { id: '3', position: { x: 400, y: 150 }, data: { label: 'Switch B' }, style: { backgroundColor: '#1e293b', color: '#94a3b8', borderColor: '#334155' } },
  { id: '4', position: { x: 100, y: 250 }, data: { label: 'Compromised Node (G-FLOWWM Predicted)' }, style: { backgroundColor: '#4c0519', color: '#fca5a5', borderColor: '#9f1239' } },
];

const initialEdges: Edge[] = [
  { id: 'e1-2', source: '1', target: '2', animated: true, style: { stroke: '#475569' } },
  { id: 'e1-3', source: '1', target: '3', style: { stroke: '#475569' } },
  { id: 'e2-4', source: '2', target: '4', animated: true, style: { stroke: '#e11d48', strokeWidth: 2 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#e11d48' } },
];

export function NetworkGraphViewer() {
  return (
    <div className="w-full h-full bg-slate-950 rounded-xl overflow-hidden border border-slate-800 shadow-2xl relative">
      <div className="absolute top-4 left-4 z-10 bg-slate-900/80 backdrop-blur-md p-3 rounded-lg border border-slate-700">
        <h3 className="text-cyan-400 font-bold mb-1">G-FLOWWM Predictive State</h3>
        <div className="flex items-center gap-2 text-xs text-slate-300">
          <div className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></div>
          Predicted Lateral Movement Path
        </div>
      </div>
      <ReactFlow nodes={initialNodes} edges={initialEdges} fitView className="bg-slate-950">
        <Background color="#334155" gap={16} size={1} />
        <Controls className="bg-slate-800 fill-slate-300 border-slate-700" />
      </ReactFlow>
    </div>
  );
}
