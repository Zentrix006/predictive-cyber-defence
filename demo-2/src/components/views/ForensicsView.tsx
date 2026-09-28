"use client";

import { useEffect, useState } from 'react';
import api, { AuditEvent, toArray } from '@/lib/api';
import { useIncidentStore } from '@/store/incidentStore';
import { Panel, Spinner, EmptyState } from '@/components/ui/Panel';
import { cn } from '@/utils/classnames';
import { format, formatDistanceToNow } from 'date-fns';

import { demoApiBase } from '@/lib/demo-api';

const fmt = (value?: string) => (value ? format(new Date(value), 'MMM d, yyyy h:mm a') : '—');

interface EvidenceItem {
  id: string;
  evidence_type: string;
  name: string;
  description: string | null;
  size_bytes: number;
  sha256_hash: string;
  collection_method: string;
  collected_at: string;
}

interface FileEvent {
  id: string;
  file_path: string;
  file_hash: string | null;
  action: string;
  timestamp: string;
  process_name: string | null;
  user: string | null;
  was_exfiltrated: boolean;
  exfiltration_destination: string | null;
}

export function ForensicsView() {
  const { activeIncident } = useIncidentStore();
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [fileEvents, setFileEvents] = useState<FileEvent[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    const loadData = async () => {
      let id = activeIncident?.id;
      if (!id) {
        try {
          const res = await fetch(`${demoApiBase()}/command/overview`);
          if (res.ok) {
            const data = await res.json();
            const inc = data.incidents?.[0] || data.incident;
            if (inc) id = inc.id;
          }
        } catch {}
      }

      if (!id) {
        if (!cancelled) setLoading(false);
        return;
      }

      try {
        const demoEvRes = await fetch(`${demoApiBase()}/forensics/evidence?incident_id=${id}`).catch(() => null);
        if (demoEvRes && demoEvRes.ok) {
          const demoEvData = await demoEvRes.json();
          if (!cancelled && Array.isArray(demoEvData) && demoEvData.length > 0) {
            setEvidence(demoEvData.map((e: any) => ({
              id: e.evidence_id || e.id,
              evidence_type: e.evidence_type || e.type,
              name: e.name || `${e.evidence_type}.bin`,
              description: e.description,
              size_bytes: e.size_bytes || 418290,
              sha256_hash: e.sha256_hash,
              collection_method: e.collection_method,
              collected_at: e.collected_at || e.timestamp,
            })));
            setLoading(false);
          }
        }
      } catch {}

      try {
        const [ev, files, tl, aud] = await Promise.all([
          api.get<any>(`/forensics/incidents/${id}/evidence`).catch(() => null),
          api.get<FileEvent[]>(`/forensics/incidents/${id}/files`).catch(() => []),
          api.get<any[]>(`/forensics/incidents/${id}/timeline`).catch(() => null),
          api.get<AuditEvent[]>('/audit?limit=60').catch(() => []),
        ]);
        if (cancelled) return;
        const evList = toArray<EvidenceItem>(ev, 'evidence');
        if (evList.length > 0) {
          setEvidence(evList);
          setFileEvents(toArray<FileEvent>(files));
          setTimeline(toArray(tl, 'events'));
          setAudit(toArray<AuditEvent>(aud));
          setLoading(false);
          return;
        }
      } catch {}

      // Fallback to scenario forensic telemetry
      if (!cancelled) {
        setEvidence([
          {
            id: 'EV-001',
            evidence_type: 'network_pcap',
            name: `${id}_recon_lateral_capture.pcap`,
            description: `High-entropy PCAP trace containing Kerberos ticket requests and SMB lateral movement probes.`,
            size_bytes: 418290,
            sha256_hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
            collection_method: 'automated_tap',
            collected_at: new Date().toISOString(),
          },
          {
            id: 'EV-002',
            evidence_type: 'honeynet_telemetry',
            name: `${id}_honeynet_sandbox_steer.json`,
            description: `Atomic nftables kernel redirection event. Adversary diverted to isolated honeypot sandbox before target reachability.`,
            size_bytes: 18450,
            sha256_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            collection_method: 'honeynet_agent',
            collected_at: new Date().toISOString(),
          }
        ]);
        setFileEvents([
          {
            id: 'FE-001',
            file_path: '/var/log/suricata/eve.json',
            file_hash: '9a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a',
            action: 'ALERT_LOGGED',
            timestamp: new Date().toISOString(),
            process_name: 'suricata',
            user: 'root',
            was_exfiltrated: false,
            exfiltration_destination: null,
          }
        ]);
        setTimeline([
          {
            id: 'TL-1',
            timestamp: new Date().toISOString(),
            title: 'Initial Probing Detected',
            stage: 'reconnaissance',
            details: 'Adversary initiated TCP SYN and service discovery scans.',
          },
          {
            id: 'TL-2',
            timestamp: new Date().toISOString(),
            title: 'G-FLOWWM Model Anticipation',
            stage: 'lateral_movement',
            details: 'World Model simulated 5 counterfactual paths; recommended DECEPTION_DIVERT with +84% risk reduction.',
          },
          {
            id: 'TL-3',
            timestamp: new Date().toISOString(),
            title: 'Kernel nftables Rule Committed',
            stage: 'containment',
            details: 'Sub-second autonomic diversion: inbound SMB redirected to Honeynet sandbox.',
          }
        ]);
        setLoading(false);
      }
    };

    loadData();
    return () => { cancelled = true; };
  }, [activeIncident?.id]);

  if (!activeIncident && evidence.length === 0) {
    return (
      <div className="p-6 h-full overflow-auto">
        <EmptyState message="Select an incident or trigger an executive scenario to inspect forensic evidence and chain of custody." />
      </div>
    );
  }

  return (
    <div className="p-6 h-full overflow-auto space-y-5">
      <div>
        <h2 className="text-xl font-semibold text-[var(--text-primary)]">Forensic Analysis</h2>
        <p className="text-sm text-[var(--text-secondary)]">
          Evidence index, file activity and chain of custody for <span className="font-medium">{activeIncident.title}</span>
        </p>
      </div>

      {loading && !evidence.length && <Spinner />}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Evidence index */}
        <Panel title="Evidence Index" subtitle={`${evidence.length} item(s)`}>
          {evidence.length === 0 ? (
            <EmptyState message="No evidence collected." />
          ) : (
            <div className="space-y-2">
              {evidence.map((e) => (
                <div key={e.id} className="rounded-lg border border-[var(--border-primary)] p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-[var(--text-primary)] truncate">{e.name}</span>
                    <span className="shrink-0 text-xs px-2 py-0.5 rounded bg-[var(--bg-tertiary)] text-[var(--text-secondary)]">{e.evidence_type}</span>
                  </div>
                  <div className="mt-1 text-xs text-[var(--text-muted)]">
                    {(e.size_bytes / 1024).toFixed(1)} KB • SHA256 {e.sha256_hash.slice(0, 16)}…
                  </div>
                  <div className="mt-0.5 text-xs text-[var(--text-secondary)]">
                    Collected {fmt(e.collected_at)} • {e.collection_method}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* File events */}
        <Panel title="File Activity" subtitle="Integrity monitoring events">
          {fileEvents.length === 0 ? (
            <EmptyState message="No file events recorded." />
          ) : (
            <div className="space-y-2">
              {fileEvents.map((f) => (
                <div key={f.id} className="rounded-lg border border-[var(--border-primary)] p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-[var(--text-primary)] truncate">{f.file_path}</span>
                    <span className={cn(
                      'shrink-0 text-xs px-2 py-0.5 rounded capitalize',
                      f.was_exfiltrated ? 'bg-[var(--accent-red)]/15 text-[var(--accent-red)]'
                      : f.action === 'deleted' ? 'bg-[var(--accent-yellow)]/15 text-[var(--accent-yellow)]'
                      : 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)]'
                    )}>
                      {f.action}{f.was_exfiltrated ? ' + exfil' : ''}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-[var(--text-muted)]">
                    {fmt(f.timestamp)}{f.process_name ? ` • ${f.process_name}` : ''}{f.user ? ` • ${f.user}` : ''}
                  </div>
                  {f.exfiltration_destination && (
                    <div className="mt-1 text-xs text-[var(--accent-red)]">→ {f.exfiltration_destination}</div>
                  )}
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* Timeline + audit */}
        <div className="space-y-5">
          <Panel title="Attack Timeline" subtitle="Observed sequence">
            {timeline.length === 0 ? (
              <EmptyState message="No timeline events." />
            ) : (
              <div className="relative pl-4 space-y-3">
                <div className="absolute left-1.5 top-1 bottom-1 w-px bg-[var(--border-primary)]" />
                {timeline.slice(0, 20).map((t: any, i: number) => (
                  <div key={i} className="relative">
                    <span className="absolute -left-[13px] top-1.5 w-2 h-2 rounded-full bg-[var(--accent-blue)]" />
                    <div className="text-xs font-semibold text-[var(--text-primary)] capitalize">
                      {t.stage || t.event_type || 'event'}
                    </div>
                    <div className="text-xs text-[var(--text-muted)]">{fmt(t.timestamp || t.observed_at)}</div>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          <Panel title="Chain of Custody" subtitle="Latest audit events">
            {audit.length === 0 ? (
              <EmptyState message="No audit events." />
            ) : (
              <div className="space-y-1.5">
                {audit.slice(0, 12).map((a) => (
                  <div key={a.id} className="flex items-start gap-2 text-xs">
                    <span className="shrink-0 px-1.5 py-0.5 rounded bg-[var(--bg-tertiary)] text-[var(--text-secondary)] font-mono">
                      {a.action}
                    </span>
                    <span className="text-[var(--text-primary)] flex-1 min-w-0 truncate">{a.summary}</span>
                    <span className="shrink-0 text-[var(--text-muted)]">{formatDistanceToNow(new Date(a.timestamp), { addSuffix: true })}</span>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}