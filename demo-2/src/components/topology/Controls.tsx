"use client";
import { useState } from 'react';
import { ZoomIn, ZoomOut, Maximize2, Minimize2, Scan, Fullscreen, HelpCircle } from 'lucide-react';

interface ControlsProps {
  ready: boolean;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFit: () => void;
  onMaximize: () => void;
  maximized: boolean;
  onFullscreen: () => void;
  isFullscreen: boolean;
  onLayoutChange: (layout: string) => void;
  currentLayout: string;
}
export function Controls(p: ControlsProps) {
  const [help, setHelp] = useState(false);
  const buttonClass = 'flex h-9 items-center justify-center gap-1 rounded border border-[var(--border-primary)] px-2 text-xs hover:bg-[var(--bg-tertiary)] disabled:opacity-40';
  return <>
    <div aria-label="Topology controls" className="flex shrink-0 flex-wrap items-center gap-2 border-b border-[var(--border-primary)] bg-[var(--bg-secondary)] p-2 text-[var(--text-primary)]">
      <button type="button" disabled={!p.ready} onClick={p.onZoomIn} className={buttonClass} aria-label="Zoom in topology" title="Zoom in"><ZoomIn size={17} /></button>
      <button type="button" disabled={!p.ready} onClick={p.onZoomOut} className={buttonClass} aria-label="Zoom out topology" title="Zoom out"><ZoomOut size={17} /></button>
      <button type="button" disabled={!p.ready} onClick={p.onFit} className={buttonClass} aria-label="Fit topology to screen"><Scan size={17} />Fit</button>
      <select aria-label="Topology layout" value={p.currentLayout} onChange={e => p.onLayoutChange(e.target.value)} className="h-9 min-w-0 max-w-40 rounded border border-[var(--border-primary)] bg-[var(--bg-secondary)] px-2 text-xs">
        <option value="criticality">Criticality layers</option><option value="cose-bilkent">Force directed</option><option value="dagre">Hierarchical</option><option value="grid">Grid</option><option value="circle">Circle</option>
      </select>
      <button type="button" onClick={p.onMaximize} className={buttonClass} aria-label={p.maximized ? 'Minimize topology' : 'Maximize topology'} aria-pressed={p.maximized}>
        {p.maximized ? <Minimize2 size={17} /> : <Maximize2 size={17} />}{p.maximized ? 'Minimize' : 'Maximize'}
      </button>
      <button type="button" onClick={p.onFullscreen} className={buttonClass} aria-label={p.isFullscreen ? 'Exit fullscreen' : 'Enter fullscreen'} aria-pressed={p.isFullscreen}><Fullscreen size={17} />{p.isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}</button>
      <button type="button" className={buttonClass} onClick={() => setHelp(!help)} aria-expanded={help} aria-label="Topology help"><HelpCircle size={17} /></button>
    </div>
    {help && <p className="shrink-0 border-b border-[var(--border-primary)] bg-[var(--bg-secondary)] p-2 text-xs text-[var(--text-secondary)]">Drag the background to pan, scroll to zoom, click a node for details. Maximize fills the application window; Fullscreen uses the browser display. Escape restores the view. PCAP replay visualizes captured traffic without sending packets.</p>}
  </>;
}
