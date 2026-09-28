"use client";

import { usePredictionStore } from '@/store/predictionStore';
import { cn } from '@/utils/classnames';

export function PredictionPanel({ forecast }: { forecast?: any }) {
  if (!forecast) {
    return (
      <div className={cn("h-full flex items-center justify-center text-[var(--text-muted)]")}>
        No prediction data available
      </div>
    );
  }

  const timeline = Array.isArray(forecast.timeline) ? forecast.timeline : [];
  const predictedTargets = Array.isArray(forecast.predicted_targets) ? forecast.predicted_targets : [];

  return (
    <div className={cn("h-full flex flex-col p-4 bg-[var(--bg-secondary)] overflow-auto")}>
      <div className="mb-4">
        <h3 className="text-lg font-semibold text-[var(--text-primary)]">Attack Forecast</h3>
        <p className="text-sm text-[var(--text-secondary)]">
          Incident: {forecast.incident_id?.slice(0, 8)}...
        </p>
      </div>

      <div className="space-y-3">
        <div className="flex justify-between text-sm">
          <span className="text-[var(--text-secondary)]">Current Stage:</span>
          <span className="font-medium">{forecast.current_stage}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-[var(--text-secondary)]">Confidence:</span>
          <span className="font-medium">{(forecast.current_confidence * 100).toFixed(0)}%</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-[var(--text-secondary)]">Model:</span>
          <span className="font-medium text-xs">{forecast.model_version}</span>
        </div>
      </div>

      {timeline.length > 0 && (
        <div className="mt-4">
          <h4 className="text-sm font-medium text-[var(--text-primary)] mb-2">Timeline</h4>
          <div className="space-y-2">
            {timeline.map((window: any, i: number) => (
              <div key={i} className="text-xs p-2 bg-[var(--bg-tertiary)] rounded">
                <div className="flex justify-between">
                  <span>Window {window.window_offset}</span>
                  <span className="font-medium">{window.stage}</span>
                </div>
                <div className="flex justify-between text-[var(--text-secondary)]">
                  <span>Probability: {(window.probability * 100).toFixed(0)}%</span>
                  <span>ETA: {window.eta_seconds?.toFixed(0)}s</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {predictedTargets.length > 0 && (
        <div className="mt-4">
          <h4 className="text-sm font-medium text-[var(--text-primary)] mb-2">Predicted Targets</h4>
          <div className="space-y-1">
            {predictedTargets.slice(0, 5).map((target: any, i: number) => (
              <div key={i} className="text-xs p-2 bg-[var(--bg-tertiary)] rounded flex justify-between">
                <span>{target.asset_name} ({target.asset_type})</span>
                <span className="font-medium text-[var(--accent-red)]">{(target.probability * 100).toFixed(0)}%</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}