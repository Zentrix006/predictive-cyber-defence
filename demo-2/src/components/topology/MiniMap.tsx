"use client";

import { useState, useEffect } from 'react';
import { cn } from '@/utils/classnames';
import { Minimize2, Maximize2 } from 'lucide-react';

interface MiniMapProps {
  cy: any;
}

export function MiniMap({ cy }: MiniMapProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [canvasEl, setCanvasEl] = useState<HTMLCanvasElement | null>(null);

  useEffect(() => {
    if (!canvasEl || !cy || !isOpen) return;

    const canvas = canvasEl;
    const context = canvas.getContext('2d');
    if (!context) return;

    canvas.width = 200;
    canvas.height = 150;

    let frameId = 0;
    let active = true;

    const draw = () => {
      if (!cy || cy.destroyed() || !context || !cy.nodes().length) return;
      
      context.clearRect(0, 0, canvas.width, canvas.height);
      
      const bounds = cy.elements().boundingBox();
      const scaleX = canvas.width / (bounds.x2 - bounds.x1 || 1);
      const scaleY = canvas.height / (bounds.y2 - bounds.y1 || 1);
      const scale = Math.min(scaleX, scaleY) * 0.9;
      
      const centerX = (bounds.x1 + bounds.x2) / 2;
      const centerY = (bounds.y1 + bounds.y2) / 2;
      
      context.save();
      context.translate(canvas.width / 2, canvas.height / 2);
      context.scale(scale, scale);
      context.translate(-centerX, -centerY);
      
      // Draw edges
      cy.edges().forEach((edge: any) => {
        const source = edge.source();
        const target = edge.target();
        const s = source.position();
        const t = target.position();
        
        context.beginPath();
        context.moveTo(s.x, s.y);
        context.lineTo(t.x, t.y);
        context.strokeStyle = edge.data('isPredicted') ? '#8B5CF6' : '#334155';
        context.lineWidth = (edge.data('isPredicted') ? 1.5 : 1) / scale;
        context.setLineDash(edge.data('isPredicted') ? [4, 4] : []);
        context.stroke();
      });
      
      // Draw nodes
      cy.nodes().forEach((node: any) => {
        const pos = node.position();
        const status = node.data('status');
        const colors: Record<string, string> = {
          normal: '#10B981',
          suspicious: '#F59E0B',
          compromised: '#EF4444',
          contained: '#3B82F6',
          deception: '#8B5CF6',
          offline: '#6B7280',
        };
        
        context.beginPath();
        context.arc(pos.x, pos.y, 3 / scale, 0, Math.PI * 2);
        context.fillStyle = colors[status] || '#6B7280';
        context.fill();
      });
      
      // Draw viewport rectangle
      const viewport = cy.extent();
      
      context.strokeStyle = '#3B82F6';
      context.lineWidth = 2 / scale;
      context.setLineDash([]);
      context.strokeRect(viewport.x1, viewport.y1, viewport.w, viewport.h);
      
      context.restore();
    };

    const animate = () => {
      if (!active) return;
      cancelAnimationFrame(frameId);
      frameId = requestAnimationFrame(draw);
    };
    
    animate();
    cy.on('pan zoom position add remove resize data', animate);

    return () => {
      active = false;
      cancelAnimationFrame(frameId);
      cy.off('pan zoom position add remove resize data', animate);
    };
  }, [cy, isOpen, canvasEl]);

  return (
    <div className="absolute bottom-3 right-3 z-30">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          "p-2 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border-primary)] shadow-lg transition-all",
          isOpen ? "bg-[var(--accent-blue)]/20 border-[var(--accent-blue)]" : ""
        )}
        aria-label={isOpen ? "Close minimap" : "Open minimap"}
        title={isOpen ? "Close minimap" : "Open minimap"}
      >
        {isOpen ? <Minimize2 className="w-5 h-5" /> : <Maximize2 className="w-5 h-5" />}
      </button>
      
      {isOpen && (
        <div className="absolute bottom-12 right-0 w-48 h-36 bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-lg shadow-lg overflow-hidden animate-fade-in">
          <canvas 
            ref={setCanvasEl} 
            className="w-full h-full"
            width={200}
            height={150}
          />
        </div>
      )}
    </div>
  );
}
