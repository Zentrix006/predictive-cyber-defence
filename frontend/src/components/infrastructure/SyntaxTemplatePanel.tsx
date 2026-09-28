"use client";

import { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, ExternalLink, ShieldCheck } from 'lucide-react';
import api, { getConsoleSession, toArray } from '@/lib/api';
import { Panel, EmptyState, Spinner } from '@/components/ui/Panel';
import { cn } from '@/utils/classnames';

interface SyntaxTemplate {
  id: number;
  vendor: string;
  os_version: string;
  abstract_intent: string;
  status: 'candidate' | 'verified' | 'rejected' | string;
  confidence: number;
  generated_by: string;
  source_url?: string | null;
  source_hash?: string | null;
  evidence_ref?: string | null;
  updated_at?: string;
}

export function SyntaxTemplatePanel() {
  const [templates, setTemplates] = useState<SyntaxTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sourceUrl, setSourceUrl] = useState('');
  const [sourceHash, setSourceHash] = useState('');
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const session = getConsoleSession();
  const canVerify = Boolean(session?.roles?.some((role) => ['admin', 'operator'].includes(role)));

  const load = async () => {
    try {
      setError(null);
      const payload = await api.get<unknown>('/evidence/syntax-templates');
      setTemplates(toArray<SyntaxTemplate>(payload));
    } catch (e: any) {
      setError(e?.message || 'Unable to load syntax provenance');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const verify = async () => {
    if (selected === null || !sourceUrl.trim() || !/^[a-f0-9]{64}$/i.test(sourceHash.trim())) {
      setError('Enter a source URL and a 64-character SHA-256 hash before verifying.');
      return;
    }
    try {
      setBusy(true);
      const query = `?source_url=${encodeURIComponent(sourceUrl.trim())}&source_hash=${encodeURIComponent(sourceHash.trim())}`;
      await api.post(`/evidence/syntax-templates/${selected}/verify${query}`);
      setSelected(null);
      setSourceUrl('');
      setSourceHash('');
      await load();
    } catch (e: any) {
      setError(e?.message || 'Template verification failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title="Vendor syntax readiness"
      subtitle="Research output stays non-executable until provenance is verified"
      actions={<span className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">{templates.length} templates</span>}
    >
      {error && <div className="mb-3 rounded-lg border border-[var(--accent-red)]/40 bg-[var(--accent-red)]/10 p-2 text-xs text-[var(--accent-red)]">{error}</div>}
      {loading ? <Spinner /> : templates.length === 0 ? <EmptyState message="No profiled vendor syntax yet." /> : (
        <div className="space-y-2">
          {templates.map((template) => (
            <div key={template.id} className="rounded-lg border border-[var(--border-primary)] bg-[var(--bg-primary)]/30 p-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-[var(--text-primary)]">{template.vendor}</span>
                    <span className="text-xs text-[var(--text-muted)]">{template.os_version}</span>
                    <span className={cn('rounded px-1.5 py-0.5 text-[10px] uppercase', template.status === 'verified' ? 'bg-[var(--accent-green)]/15 text-[var(--accent-green)]' : 'bg-[var(--accent-yellow)]/15 text-[var(--accent-yellow)]')}>
                      {template.status}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-[var(--text-secondary)]">{template.abstract_intent.replaceAll('_', ' ')}</div>
                  <div className="mt-1 text-[10px] text-[var(--text-muted)]">Confidence {(template.confidence * 100).toFixed(0)}% · {template.generated_by}</div>
                </div>
                {template.status === 'verified' ? <CheckCircle2 className="h-4 w-4 shrink-0 text-[var(--accent-green)]" /> : <AlertTriangle className="h-4 w-4 shrink-0 text-[var(--accent-yellow)]" />}
              </div>
              {template.status !== 'verified' && canVerify && (
                <button onClick={() => setSelected(template.id)} className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-[var(--border-primary)] px-2.5 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
                  <ShieldCheck className="h-3.5 w-3.5" /> Verify source
                </button>
              )}
              {template.source_url && <a className="ml-2 text-[10px] text-[var(--accent-blue)]" href={template.source_url} target="_blank" rel="noreferrer"><ExternalLink className="inline h-3 w-3" /> source</a>}
            </div>
          ))}
        </div>
      )}
      {selected !== null && (
        <div className="mt-4 rounded-lg border border-[var(--accent-blue)]/40 bg-[var(--accent-blue)]/5 p-3">
          <div className="mb-2 text-xs font-semibold text-[var(--text-primary)]">Verify documentation provenance</div>
          <input value={sourceUrl} onChange={(e) => setSourceUrl(e.target.value)} placeholder="https://vendor.example/docs/..." className="mb-2 w-full rounded border border-[var(--border-primary)] bg-[var(--bg-secondary)] px-2 py-1.5 text-xs text-[var(--text-primary)]" />
          <input value={sourceHash} onChange={(e) => setSourceHash(e.target.value)} placeholder="SHA-256 of captured documentation" className="mb-2 w-full rounded border border-[var(--border-primary)] bg-[var(--bg-secondary)] px-2 py-1.5 font-mono text-xs text-[var(--text-primary)]" />
          <div className="flex gap-2">
            <button disabled={busy} onClick={verify} className="rounded bg-[var(--accent-blue)] px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50">{busy ? 'Verifying…' : 'Verify template'}</button>
            <button disabled={busy} onClick={() => setSelected(null)} className="rounded border border-[var(--border-primary)] px-3 py-1.5 text-xs text-[var(--text-secondary)]">Cancel</button>
          </div>
        </div>
      )}
    </Panel>
  );
}
