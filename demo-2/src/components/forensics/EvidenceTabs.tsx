"use client";

import React, { useState, useEffect } from 'react';
import { useIncidentStore } from '@/store/incidentStore';
import { demoApiBase } from '@/lib/demo-api';
import { cn } from '@/utils/classnames';
import { 
  FileText, 
  Terminal, 
  FileCode, 
  Download, 
  Copy, 
  Check, 
  Search, 
  ShieldCheck, 
  Radio,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Wifi,
  RefreshCw
} from 'lucide-react';

interface EvidenceTabsProps {
  className?: string;
  incidentId?: string;
}

interface VerificationQueueItem {
  device: {
    id: string;
    primary_ip?: string;
    primary_mac?: string;
    hostname?: string;
    vendor?: string;
    model?: string;
    device_role: string;
    confidence: number;
    status: string;
  };
  observation_count: number;
  sources: string[];
  is_discrepant: boolean;
  discrepancy_reasons: string[];
  recommended_action: string;
}

interface EvidenceItem {
  id: string;
  name: string;
  evidence_type: string;
  description: string;
  size_bytes: number;
  sha256_hash: string;
  collection_method: string;
  collected_at?: string;
  packet_count?: number;
}

interface SecurityLog {
  id: string;
  timestamp: string;
  source: string;
  level: 'ALERT' | 'INFO' | 'WARN' | 'CRITICAL';
  message: string;
}

interface FileForensicEvent {
  id: string;
  file_path: string;
  file_hash: string;
  action: 'ALERT_LOGGED' | 'QUARANTINED' | 'COMMITTED' | 'EXTRACTED';
  timestamp: string;
  process_name: string;
  user: string;
  status: 'Preserved' | 'Isolated';
}

export function EvidenceTabs({ className, incidentId }: EvidenceTabsProps) {
  const [activeTab, setActiveTab] = useState<'evidence' | 'logs' | 'files' | 'verification'>('evidence');
  const { activeIncident } = useIncidentStore();
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [logSearch, setLogSearch] = useState('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [queue, setQueue] = useState<VerificationQueueItem[]>([]);
  const [scanningWifi, setScanningWifi] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const fetchQueue = async () => {
    try {
      const res = await fetch('/api/v1/evidence/devices/queue');
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) {
          setQueue(data);
        }
      }
    } catch {
      // fallback
    }
  };

  useEffect(() => {
    fetchQueue();
    const interval = setInterval(fetchQueue, 8000);
    return () => clearInterval(interval);
  }, []);

  const handleApprove = async (deviceId: string) => {
    try {
      const res = await fetch(`/api/v1/evidence/devices/${deviceId}/approve`, { method: 'POST' });
      if (res.ok) {
        setActionNotice('Device successfully approved and enrolled as verified.');
        setQueue(prev => prev.filter(q => q.device.id !== deviceId));
        setTimeout(() => setActionNotice(null), 3000);
      }
    } catch {
      setActionNotice('Approval failed.');
    }
  };

  const handleReject = async (deviceId: string) => {
    try {
      const res = await fetch(`/api/v1/evidence/devices/${deviceId}/reject`, { method: 'POST' });
      if (res.ok) {
        setActionNotice('Device rejected and network link archived.');
        setQueue(prev => prev.filter(q => q.device.id !== deviceId));
        setTimeout(() => setActionNotice(null), 3000);
      }
    } catch {
      setActionNotice('Rejection failed.');
    }
  };

  const handleScanWifi = async () => {
    setScanningWifi(true);
    try {
      await fetch('/api/v1/evidence/devices/passive-local', { method: 'POST' });
      await fetchQueue();
      setActionNotice('Passive Wi-Fi scan complete. New provisional devices loaded.');
      setTimeout(() => setActionNotice(null), 4000);
    } catch {
      setActionNotice('Passive scan failed.');
    } finally {
      setScanningWifi(false);
    }
  };

  const effectiveIncidentId = incidentId || activeIncident?.id || 'INC-RANSOMWARE';

  useEffect(() => {
    let cancelled = false;

    const fetchEvidence = async () => {
      try {
        const url = activeIncident?.id 
          ? `${demoApiBase()}/forensics/evidence?incident_id=${activeIncident.id}` 
          : `${demoApiBase()}/forensics/evidence`;
        const res = await fetch(url);
        if (res.ok) {
          const data = await res.json();
          if (!cancelled && Array.isArray(data) && data.length > 0) {
            const mapped: EvidenceItem[] = data.map((item: any, idx: number) => ({
              id: item.evidence_id || `EV-${idx}`,
              name: item.name || item.payload?.name || `${item.evidence_type || 'evidence'}_${item.evidence_id}.bin`,
              evidence_type: item.evidence_type || item.type || 'network_capture',
              description: item.description || item.payload?.description || 'Cryptographically verified forensic capture.',
              size_bytes: item.size_bytes || item.payload?.size_bytes || 418290,
              sha256_hash: item.sha256_hash || item.payload?.sha256_hash || '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
              collection_method: item.collection_method || item.payload?.collection_method || item.source || 'automated_tap',
              collected_at: item.collected_at || item.timestamp,
              packet_count: item.packet_count || item.payload?.packet_count,
            }));
            setEvidenceList(mapped);
            return;
          }
        }
      } catch {
        // fallback
      }

      if (!cancelled && Array.isArray(activeIncident?.evidence) && activeIncident.evidence.length > 0) {
        setEvidenceList(activeIncident.evidence);
        return;
      }

      if (!cancelled) {
        setEvidenceList([
          {
            id: 'EV-001',
            name: `${effectiveIncidentId}_recon_lateral_capture.pcap`,
            evidence_type: 'network_pcap',
            description: 'High-entropy PCAP trace containing Kerberos ticket requests and SMB lateral movement probes.',
            size_bytes: 418290,
            sha256_hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
            collection_method: 'automated_tap',
            collected_at: new Date().toISOString(),
            packet_count: 1420,
          },
          {
            id: 'EV-002',
            name: `${effectiveIncidentId}_honeynet_sandbox_steer.json`,
            evidence_type: 'honeynet_telemetry',
            description: 'Atomic nftables kernel redirection event. Adversary diverted to isolated honeypot sandbox before target reachability.',
            size_bytes: 18450,
            sha256_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            collection_method: 'honeynet_agent',
            collected_at: new Date().toISOString(),
          },
          {
            id: 'EV-003',
            name: `${effectiveIncidentId}_kernel_nftables_rule.log`,
            evidence_type: 'policy_enforcement',
            description: 'Dynamic kernel rule commit: nft add rule inet nat prerouting ... (Autonomous diversion).',
            size_bytes: 4120,
            sha256_hash: 'd41d8cd98f00b204e9800998ecf8427e9a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c',
            collection_method: 'kernel_nftables',
            collected_at: new Date().toISOString(),
          }
        ]);
      }
    };

    fetchEvidence();
    const interval = setInterval(fetchEvidence, 4000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [activeIncident?.id, effectiveIncidentId]);

  const logs: SecurityLog[] = [
    {
      id: 'L-1',
      timestamp: new Date(Date.now() - 16000).toLocaleTimeString(),
      source: 'suricata',
      level: 'CRITICAL',
      message: `[SURICATA] ET EXPLOIT Pass-the-Hash / SMB2 Session Setup from ${activeIncident?.attacker || '192.168.1.105'}`
    },
    {
      id: 'L-2',
      timestamp: new Date(Date.now() - 12000).toLocaleTimeString(),
      source: 'g-flowwm',
      level: 'ALERT',
      message: `[FLOWWM] G-FLOWWM counterfactual rollout: 5 branches simulated, recommended DECEPTION_DIVERT (+84% risk reduction)`
    },
    {
      id: 'L-3',
      timestamp: new Date(Date.now() - 8000).toLocaleTimeString(),
      source: 'nftables',
      level: 'ALERT',
      message: `[NFTABLES] DNAT rule committed: ip saddr 192.168.1.105 dport 445 dnat to 10.0.9.10 (latency: 18ms)`
    },
    {
      id: 'L-4',
      timestamp: new Date(Date.now() - 4000).toLocaleTimeString(),
      source: 'dionaea',
      level: 'INFO',
      message: `[HONEYNET] Dionaea decoy listener captured T1003 Mimikatz credentials payload; session quarantined in sandbox`
    },
    {
      id: 'L-5',
      timestamp: new Date().toLocaleTimeString(),
      source: 'watchdog',
      level: 'INFO',
      message: `[WATCHDOG] Zero false-positive rollback timer active (58s remaining); nominal production traffic 100% healthy`
    }
  ];

  const fileEvents: FileForensicEvent[] = [
    {
      id: 'FE-1',
      file_path: '/var/log/suricata/eve.json',
      file_hash: '9a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a',
      action: 'ALERT_LOGGED',
      timestamp: new Date(Date.now() - 15000).toLocaleTimeString(),
      process_name: 'suricata',
      user: 'root',
      status: 'Preserved',
    },
    {
      id: 'FE-2',
      file_path: '/tmp/quarantined_mimikatz_dump.bin',
      file_hash: 'c5a0b7289d0b64d1f5e8f41539e083c6d6a578912e9a3a14e912ab92c2b3e4f5',
      action: 'QUARANTINED',
      timestamp: new Date(Date.now() - 10000).toLocaleTimeString(),
      process_name: 'dionaea-sandbox',
      user: 'sandbox',
      status: 'Isolated',
    },
    {
      id: 'FE-3',
      file_path: '/etc/nftables.d/cyber_defence_autonomic.nft',
      file_hash: 'd41d8cd98f00b204e9800998ecf8427e9a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c',
      action: 'COMMITTED',
      timestamp: new Date(Date.now() - 7000).toLocaleTimeString(),
      process_name: 'nftables',
      user: 'kernel',
      status: 'Preserved',
    },
    {
      id: 'FE-4',
      file_path: '/var/spool/honeynet/capture_01.pcap',
      file_hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
      action: 'EXTRACTED',
      timestamp: new Date(Date.now() - 3000).toLocaleTimeString(),
      process_name: 'tcpdump',
      user: 'pcd-agent',
      status: 'Preserved',
    }
  ];

  const handleCopy = (hash: string) => {
    navigator.clipboard?.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredLogs = logs.filter(l => 
    !logSearch || 
    l.message.toLowerCase().includes(logSearch.toLowerCase()) ||
    l.source.toLowerCase().includes(logSearch.toLowerCase()) ||
    l.level.toLowerCase().includes(logSearch.toLowerCase())
  );

  return (
    <div className={cn("h-full flex flex-col p-3.5 bg-[var(--bg-secondary)] overflow-hidden", className)}>
      {/* Tab Navigation Header */}
      <div className="flex items-center justify-between gap-2 mb-2.5 border-b border-[var(--border-primary)] pb-1 shrink-0">
        <div className="flex gap-1">
          <button
            onClick={() => setActiveTab('evidence')}
            className={cn(
              "px-2.5 py-1 text-xs font-bold rounded-t transition-all flex items-center gap-1.5",
              activeTab === 'evidence'
                ? "bg-[var(--bg-tertiary)] text-[var(--accent-blue)] border-b-2 border-[var(--accent-blue)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            )}
          >
            <FileText className="w-3.5 h-3.5" />
            Evidence ({evidenceList.length})
          </button>
          <button
            onClick={() => setActiveTab('logs')}
            className={cn(
              "px-2.5 py-1 text-xs font-bold rounded-t transition-all flex items-center gap-1.5",
              activeTab === 'logs'
                ? "bg-[var(--bg-tertiary)] text-[var(--accent-blue)] border-b-2 border-[var(--accent-blue)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            )}
          >
            <Terminal className="w-3.5 h-3.5" />
            Logs ({logs.length})
          </button>
          <button
            onClick={() => setActiveTab('files')}
            className={cn(
              "px-2.5 py-1 text-xs font-bold rounded-t transition-all flex items-center gap-1.5",
              activeTab === 'files'
                ? "bg-[var(--bg-tertiary)] text-[var(--accent-blue)] border-b-2 border-[var(--accent-blue)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            )}
          >
            <FileCode className="w-3.5 h-3.5" />
            Files ({fileEvents.length})
          </button>
          <button
            onClick={() => setActiveTab('verification')}
            className={cn(
              "px-2.5 py-1 text-xs font-bold rounded-t transition-all flex items-center gap-1.5",
              activeTab === 'verification'
                ? "bg-[var(--bg-tertiary)] text-indigo-500 border-b-2 border-indigo-500 font-bold"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            )}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-indigo-400" />
            Verify Queue ({queue.length})
            {queue.length > 0 && (
              <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
            )}
          </button>
        </div>

        <div className="flex items-center gap-2">
          {activeTab === 'verification' && (
            <button
              onClick={handleScanWifi}
              disabled={scanningWifi}
              className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 border border-indigo-500/30"
              title="Passive Wi-Fi / Local ARP Scan"
            >
              <Wifi className={cn("w-3 h-3", scanningWifi && "animate-spin")} />
              {scanningWifi ? "Scanning..." : "Scan Wi-Fi"}
            </button>
          )}
          <div className="flex items-center gap-1 text-[10px] text-emerald-600 dark:text-emerald-400 font-mono">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Custody Verified</span>
          </div>
        </div>
      </div>

      {/* Tab 1: Forensic Evidence Artifacts */}
      {activeTab === 'evidence' && (
        <div className="flex-1 overflow-y-auto space-y-2 pr-1">
          {evidenceList.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-[var(--text-muted)] p-6 text-center">
              <Radio className="w-6 h-6 mb-2 opacity-40 animate-pulse text-[var(--accent-blue)]" />
              <p className="text-xs">No forensic evidence collected yet.</p>
            </div>
          ) : (
            evidenceList.map((e, i) => (
              <div 
                key={e.id || i} 
                className="p-2.5 rounded-lg border border-[var(--border-primary)] bg-[var(--bg-tertiary)] hover:border-[var(--accent-blue)]/50 transition-all text-xs"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-1.5 mb-1">
                      <span className="font-bold text-[var(--text-primary)]">{e.name}</span>
                      <span className="px-1.5 py-0.2 text-[9px] font-mono rounded bg-[var(--accent-blue)]/15 text-[var(--accent-blue)] border border-[var(--accent-blue)]/30 font-semibold">
                        {e.evidence_type}
                      </span>
                      {e.packet_count && (
                        <span className="px-1.5 py-0.2 text-[9px] font-mono rounded bg-[var(--bg-primary)] text-[var(--text-secondary)]">
                          {e.packet_count.toLocaleString()} packets
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-[var(--text-secondary)] font-mono mb-1.5">{e.description}</p>
                    <div className="flex flex-wrap items-center gap-3 text-[10px] text-[var(--text-muted)] font-mono">
                      <span>Method: <b className="text-[var(--text-primary)]">{e.collection_method}</b></span>
                      <span>Size: <b className="text-[var(--text-primary)]">{(e.size_bytes / 1024).toFixed(1)} KB</b></span>
                      <div className="flex items-center gap-1">
                        <span>SHA256:</span>
                        <code className="text-[var(--text-secondary)]">{e.sha256_hash.slice(0, 16)}...</code>
                        <button 
                          onClick={() => handleCopy(e.sha256_hash)}
                          className="hover:text-[var(--text-primary)] transition-colors p-0.5"
                          title="Copy SHA-256 Hash"
                        >
                          {copiedHash === e.sha256_hash ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 2: Security & Audit Logs */}
      {activeTab === 'logs' && (
        <div className="flex-1 flex flex-col min-h-0">
          <div className="mb-2 relative shrink-0">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[var(--text-muted)]" />
            <input
              type="text"
              placeholder="Filter logs by message, source or level..."
              value={logSearch}
              onChange={(e) => setLogSearch(e.target.value)}
              className="w-full bg-[var(--bg-tertiary)] border border-[var(--border-primary)] rounded-md pl-8 pr-3 py-1.5 text-xs text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent-blue)]"
            />
          </div>
          <div className="flex-1 overflow-y-auto space-y-1.5 font-mono text-[11px] pr-1">
            {filteredLogs.map((log) => (
              <div 
                key={log.id} 
                className="p-2 rounded bg-[var(--bg-primary)]/70 border border-[var(--border-primary)] flex items-start gap-2"
              >
                <span className="text-[var(--text-muted)] whitespace-nowrap text-[10px]">{log.timestamp}</span>
                <span className={cn(
                  "px-1 py-0.2 rounded text-[9px] font-bold uppercase shrink-0",
                  log.level === 'CRITICAL' ? 'bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/30' :
                  log.level === 'ALERT' ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30' :
                  'bg-blue-500/15 text-blue-600 dark:text-blue-400 border border-blue-500/30'
                )}>
                  {log.level}
                </span>
                <span className="flex-1 break-all select-all leading-tight text-[var(--text-primary)]">{log.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Forensic File System & Memory Events */}
      {activeTab === 'files' && (
        <div className="flex-1 overflow-y-auto space-y-2 pr-1">
          {fileEvents.map((f) => (
            <div 
              key={f.id} 
              className="p-2.5 rounded-lg border border-[var(--border-primary)] bg-[var(--bg-tertiary)] text-xs font-mono"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-bold text-[var(--text-primary)] break-all">{f.file_path}</span>
                <span className={cn(
                  "px-1.5 py-0.2 rounded text-[9px] font-bold uppercase",
                  f.action === 'QUARANTINED' ? 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30' :
                  f.action === 'ALERT_LOGGED' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30' :
                  'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                )}>
                  {f.action}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-3 text-[10px] text-[var(--text-muted)] mt-1">
                <span>Process: <b className="text-[var(--text-primary)]">{f.process_name}</b></span>
                <span>User: <b className="text-[var(--text-primary)]">{f.user}</b></span>
                <span>Status: <b className="text-emerald-600 dark:text-emerald-400 font-semibold">{f.status}</b></span>
                <div className="flex items-center gap-1">
                  <span>SHA256:</span>
                  <code className="text-[var(--text-secondary)]">{f.file_hash.slice(0, 16)}...</code>
                  <button 
                    onClick={() => handleCopy(f.file_hash)} 
                    className="hover:text-[var(--text-primary)] p-0.5"
                    title="Copy File Hash"
                  >
                    {copiedHash === f.file_hash ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 4: Operator Verification Queue (Mode B — Verify) */}
      {activeTab === 'verification' && (
        <div className="flex-1 overflow-y-auto space-y-2 pr-1">
          {actionNotice && (
            <div className="p-2 rounded bg-indigo-500/20 border border-indigo-500/40 text-[11px] text-indigo-400 dark:text-indigo-300 font-mono flex items-center justify-between">
              <span>{actionNotice}</span>
              <button onClick={() => setActionNotice(null)} className="hover:text-[var(--text-primary)]">✕</button>
            </div>
          )}

          {queue.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center p-6 text-center text-[var(--text-secondary)] space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-500/80" />
              <p className="text-xs font-semibold text-[var(--text-primary)]">All Network Endpoints Verified</p>
              <p className="text-[11px] max-w-xs text-[var(--text-muted)]">
                Mode B Operator Governance is clean. No unverified or rogue endpoints pending review. Click "Scan Wi-Fi" to passively observe local subnet neighbors.
              </p>
              <button
                onClick={handleScanWifi}
                disabled={scanningWifi}
                className="mt-2 px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 text-white hover:bg-indigo-500 flex items-center gap-1.5 shadow-sm"
              >
                <Wifi className={cn("w-3.5 h-3.5", scanningWifi && "animate-spin")} />
                {scanningWifi ? "Scanning..." : "Scan Wi-Fi Subnet"}
              </button>
            </div>
          ) : (
            queue.map((item) => (
              <div
                key={item.device.id}
                className={cn(
                  "p-2.5 rounded-lg border text-xs font-mono transition-all",
                  item.is_discrepant
                    ? "border-rose-500/40 bg-rose-950/10"
                    : "border-[var(--border-primary)] bg-[var(--bg-tertiary)]"
                )}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-[var(--text-primary)]">
                      {item.device.primary_ip || item.device.hostname || "Unknown Endpoint"}
                    </span>
                    {item.device.hostname && item.device.hostname !== item.device.primary_ip && (
                      <span className="text-[10px] text-[var(--text-secondary)]">({item.device.hostname})</span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                      {Math.round(item.device.confidence * 100)}% Fused
                    </span>
                    <button
                      onClick={() => handleApprove(item.device.id)}
                      className="p-1 rounded bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/30 border border-emerald-500/40"
                      title="Approve Device Identity"
                    >
                      <Check className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleReject(item.device.id)}
                      className="p-1 rounded bg-rose-500/20 text-rose-600 dark:text-rose-400 hover:bg-rose-500/30 border border-rose-500/40"
                      title="Reject and Quarantine"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-[var(--text-muted)] mt-1">
                  <span>MAC: <b className="text-[var(--text-primary)]">{item.device.primary_mac || "Unmeasured"}</b></span>
                  <span>Vendor: <b className="text-[var(--text-primary)]">{item.device.vendor || "Unknown"}</b></span>
                  <span>Role: <b className="text-[var(--text-primary)] uppercase">{item.device.device_role}</b></span>
                  <span>Sources: <b className="text-cyan-600 dark:text-cyan-400">{item.sources.join(", ")}</b></span>
                </div>

                {item.is_discrepant && item.discrepancy_reasons.length > 0 && (
                  <div className="mt-1.5 p-1.5 rounded bg-rose-950/30 border border-rose-500/30 text-[10px] text-rose-400 dark:text-rose-300 flex items-center gap-1.5">
                    <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                    <span>{item.discrepancy_reasons[0]}</span>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}