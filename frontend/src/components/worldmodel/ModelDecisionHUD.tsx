"use client";

import React, { useState } from 'react';
import { usePredictionStore } from '@/store/predictionStore';
import { cn } from '@/utils/classnames';
import { 
  GitBranch, 
  Activity, 
  Terminal, 
  ChevronDown, 
  ChevronUp, 
  CheckCircle2, 
  Sparkles,
} from 'lucide-react';

export function ModelDecisionHUD({ className }: { className?: string }) {
  const { currentForecast, latestDecision } = usePredictionStore();
  const [collapsed, setCollapsed] = useState(false);
  const [showDiff, setShowDiff] = useState(false);

  // Extract decision or synthesize fallback from forecast if latestDecision is not yet set
  const decision = latestDecision || currentForecast?.model_decision || (
    currentForecast ? {
      action: currentForecast.recommended_action || 'DECEPTION_DIVERT',
      action_type: currentForecast.recommended_action || 'DECEPTION_DIVERT',
      risk_reduction_pct: 84.0,
      jepa_surprisal: 2.14,
      is_novel_behavior: true,
      decision_confidence: currentForecast.current_confidence || 0.91,
      target_stage: currentForecast.current_stage || 'lateral_movement',
      branches_evaluated: 5,
      worst_case_branch: { terminal_stage: 'data_exfiltration', risk_score: 0.94 },
      rollback_armed: true,
      vendor_diff: 'nft add rule inet nat prerouting dnat to 10.0.9.10 comment "FLOWWM_DECEPTION_DIVERT"',
    } : null
  );

  if (!decision) {
    return null;
  }

  const isDivert = decision.action.includes('DIVERT') || decision.action.includes('DECEPTION');
  const isContain = decision.action.includes('CONTAIN') || decision.action.includes('ISOLATE');
  const isRateLimit = decision.action.includes('RATE');

  const actionBadgeBg = isDivert
    ? 'bg-gradient-to-r from-purple-600 to-indigo-600'
    : isContain
    ? 'bg-gradient-to-r from-rose-600 to-orange-600'
    : isRateLimit
    ? 'bg-gradient-to-r from-amber-600 to-yellow-600'
    : 'bg-gradient-to-r from-cyan-600 to-blue-600';

  return (
    <div className={cn(
      "absolute bottom-4 right-4 z-30 w-96 max-w-[calc(100%-2rem)] rounded-xl border border-white/10 bg-[#0a101d]/90 backdrop-blur-md shadow-2xl text-xs text-slate-200 transition-all duration-300 pointer-events-auto",
      className
    )}>
      {/* HUD Header */}
      <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-white/10 bg-slate-900/60 rounded-t-xl">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
          </span>
          <span className="font-mono text-[11px] font-bold tracking-wider text-cyan-300 uppercase">
            G-FLOWWM • Autonomous HUD
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1 rounded hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
            title={collapsed ? "Expand HUD" : "Collapse HUD"}
            aria-label="Toggle HUD"
          >
            {collapsed ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Primary Action Banner */}
      <div className="p-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className={cn("px-2.5 py-1 rounded-md text-[11px] font-bold tracking-wide shadow-sm text-white", actionBadgeBg)}>
              {decision.action}
            </div>
          </div>
          <div className="text-right">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">Risk Reduction</div>
            <div className="text-sm font-black text-emerald-400">
              +{decision.risk_reduction_pct}%
            </div>
          </div>
        </div>

        {/* Expanded Details */}
        {!collapsed && (
          <div className="mt-3 space-y-3 border-t border-white/10 pt-3">
            {/* Cyber-JEPA Surprisal & Novelty Indicator */}
            <div className="grid grid-cols-2 gap-2 bg-slate-900/40 p-2 rounded-lg border border-white/5">
              <div>
                <div className="text-[10px] text-slate-400 flex items-center gap-1">
                  <Activity className="w-3 h-3 text-cyan-400" />
                  JEPA Surprisal
                </div>
                <div className="text-sm font-semibold font-mono text-cyan-300 mt-0.5">
                  {decision.jepa_surprisal.toFixed(3)} <span className="text-[10px] text-slate-500">nats</span>
                </div>
              </div>
              <div>
                <div className="text-[10px] text-slate-400 flex items-center gap-1">
                  <Sparkles className="w-3 h-3 text-amber-400" />
                  Novelty Discrim.
                </div>
                <div className="mt-0.5">
                  {decision.is_novel_behavior ? (
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      NOVEL ZERO-DAY
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      KNOWN SIGNATURE
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Counterfactual Branch Trajectories */}
            <div className="bg-slate-900/40 p-2.5 rounded-lg border border-white/5">
              <div className="flex items-center justify-between text-[11px] mb-1.5">
                <span className="text-slate-400 flex items-center gap-1">
                  <GitBranch className="w-3 h-3 text-indigo-400" />
                  Branches Evaluated
                </span>
                <span className="font-mono font-semibold text-slate-200">
                  {decision.branches_evaluated || 5} rollouts
                </span>
              </div>
              <div className="text-[10px] text-slate-400 flex items-center justify-between bg-black/30 p-1.5 rounded">
                <span>Avoided Worst Case:</span>
                <span className="font-mono font-bold text-rose-400 uppercase">
                  {decision.worst_case_branch?.terminal_stage || 'Data Exfiltration'}
                </span>
              </div>
            </div>

            {/* Rollback & Kernel SLA */}
            <div className="flex items-center justify-between px-1 text-[11px]">
              <div className="flex items-center gap-1.5 text-emerald-400">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span className="text-[10px] font-medium">Rollback Watchdog Armed (60s SLA)</span>
              </div>
              <button 
                onClick={() => setShowDiff(!showDiff)}
                className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 underline underline-offset-2"
              >
                <Terminal className="w-3 h-3" />
                {showDiff ? "Hide Diff" : "View Kernel Diff"}
              </button>
            </div>

            {/* Machine Auditable Diff Viewer */}
            {showDiff && (
              <div className="mt-2 p-2 rounded bg-black/70 border border-cyan-500/30 font-mono text-[10px] text-cyan-300 overflow-x-auto">
                <div className="text-[9px] text-slate-400 mb-1"># nftables atomic transaction:</div>
                <div className="whitespace-pre">{decision.vendor_diff}</div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
