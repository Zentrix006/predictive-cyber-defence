"use client";

import { useState } from 'react';
import { X, AlertTriangle, AlertCircle, CheckCircle, ExternalLink, Copy } from 'lucide-react';
import { cn } from '@/utils/classnames';
import { TopologyNode } from '@/types';
import { authHeaders } from '@/lib/api';

const API = process.env.NEXT_PUBLIC_API_URL || '/api/v1';

interface NodePanelProps {
  node: TopologyNode;
  onClose: () => void;
  readOnly?: boolean;
}

export function NodePanel({ node, onClose, readOnly = false }: NodePanelProps) {
  const [busy, setBusy] = useState(false);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [status, setStatus] = useState<string>(node.status);

  const statusColors = {
    normal: 'bg-[var(--status-normal)]',
    suspicious: 'bg-[var(--status-suspicious)]',
    compromised: 'bg-[var(--status-compromised)]',
    contained: 'bg-[var(--status-contained)]',
    deception: 'bg-[var(--status-deception)]',
    offline: 'bg-[var(--status-offline)]',
  };

  const statusLabels = {
    normal: 'Normal',
    suspicious: 'Suspicious',
    compromised: 'Compromised',
    contained: 'Contained',
    deception: 'Deception',
    offline: 'Offline',
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'normal': return <CheckCircle className="w-4 h-4" />;
      case 'suspicious': return <AlertTriangle className="w-4 h-4" />;
      case 'compromised': return <AlertCircle className="w-4 h-4" />;
      case 'contained': return <CheckCircle className="w-4 h-4" />;
      case 'deception': return <span className="w-4 h-4">🟣</span>;
      default: return <span className="w-4 h-4">⚫</span>;
    }
  };

  return (
    <div aria-label="Node details" className="absolute right-0 top-0 bottom-0 w-full max-w-sm bg-[var(--bg-secondary)] border-l border-[var(--border-primary)] z-40 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-[var(--border-primary)]">
        <div className="flex items-center gap-3">
          <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center", "bg-[var(--bg-tertiary)]")}>
            {getStatusIcon(node.status)}
          </div>
          <div>
            <h3 className="font-semibold text-[var(--text-primary)]">{node.label}</h3>
            <p className="text-xs text-[var(--text-secondary)]">{node.asset_id}</p>
          </div>
        </div>
        <button type="button" aria-label="Close node details" onClick={onClose} className="p-2 hover:bg-[var(--bg-tertiary)] rounded-lg transition-colors">
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Status Badge */}
        <div className={cn(
          "px-3 py-2 rounded-lg text-center font-medium text-white",
          statusColors[status as keyof typeof statusColors]
        )}>
          {statusLabels[status as keyof typeof statusLabels] || status}
        </div>

        {/* Basic Info */}
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <InfoItem label="IP Address" value={node.metadata.ip || 'N/A'} />
            <InfoItem label="Asset Type" value={node.asset_type} />
            <InfoItem label="Zone" value={readOnly ? 'Not inferred' : node.zone} />
            <InfoItem label="Criticality" value={readOnly ? 'Not assessed' : node.criticality} />
            <InfoItem label="Threat Score" value={readOnly ? 'Not assessed' : `${(node.threatScore * 100).toFixed(0)}%`} />
            <InfoItem label="OS" value={node.metadata.os || 'Unknown'} />
          </div>
        </div>

        {/* Threat Details */}
        {node.threatScore > 0.3 && (
          <div className="bg-[var(--accent-red)]/10 border border-[var(--accent-red)]/20 rounded-lg p-3">
            <h4 className="font-medium text-[var(--accent-red)] mb-2">Threat Details</h4>
            <div className="space-y-1 text-sm">
              <p>Active Connections: {node.metadata.activeConnections || 'N/A'}</p>
              <p>Suspicious Flows: {node.metadata.suspiciousFlows || 'N/A'}</p>
              <p>Blocked Flows: {node.metadata.blockedFlows || 'N/A'}</p>
            </div>
          </div>
        )}

        {/* Network Connections */}
        <div>
          <h4 className="font-medium mb-2">Network Connections</h4>
          <p className="text-sm text-[var(--text-secondary)]">
            This asset has active connections to {node.metadata.connectionCount || 0} other assets.
          </p>
        </div>

        {/* Actions */}
        <div className="pt-4 border-t border-[var(--border-primary)] space-y-2">
          {actionMsg && (
            <p className="text-[11px] text-[var(--text-secondary)] bg-[var(--bg-tertiary)] rounded-md px-2 py-1">{actionMsg}</p>
          )}
          <button
            onClick={onClose}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-[var(--accent-blue)] text-white rounded-lg hover:bg-[var(--accent-blue)]/90 transition-colors"
          >
            <ExternalLink className="w-4 h-4" />
            View in Topology
          </button>
          <button
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(node.asset_id);
                setActionMsg('Asset ID copied to clipboard');
              } catch {
                setActionMsg('Copy failed — select the ID manually');
              }
            }}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded-lg hover:bg-[var(--border-primary)] transition-colors"
          >
            <Copy className="w-4 h-4" />
            Copy Asset ID
          </button>
          {readOnly && <p className="text-xs text-[var(--text-secondary)]">Captured host: live containment is unavailable in offline replay. Status colors do not represent a threat assessment.</p>}
          <button
            disabled={readOnly || busy || status === 'contained' || status === 'offline'}
            onClick={async () => {
              setBusy(true);
              setActionMsg(null);
              try {
                const res = await fetch(`${API}/assets/${node.asset_id}/contain?isolation_level=quarantine_vlan`, { method: 'POST', headers: authHeaders() });
                if (!res.ok) { const body = await res.json(); throw new Error(body.detail || 'Containment request failed'); }
                setStatus('contained');
                setActionMsg('Asset queued for quarantine isolation');
              } catch (e: any) {
                setActionMsg(e.message || 'Containment failed');
              } finally {
                setBusy(false);
              }
            }}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-[var(--accent-red)]/10 text-[var(--accent-red)] rounded-lg hover:bg-[var(--accent-red)]/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <AlertTriangle className="w-4 h-4" />
            {busy ? 'Isolating…' : 'Isolate Asset'}
          </button>
        </div>
      </div>
    </div>
  );
}

function InfoItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[var(--bg-tertiary)] rounded-lg p-3">
      <p className="text-xs text-[var(--text-secondary)]">{label}</p>
      <p className="font-medium text-[var(--text-primary)] truncate">{value}</p>
    </div>
  );
}
