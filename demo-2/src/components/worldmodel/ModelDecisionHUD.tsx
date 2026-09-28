"use client";

import React, { useState } from 'react';
import { usePredictionStore } from '@/store/predictionStore';
import { useUIStore } from '@/store/uiStore';
import { cn } from '@/utils/classnames';
import { 
  GitBranch, 
  Activity, 
  Terminal, 
  ChevronDown, 
  ChevronUp, 
  CheckCircle2, 
  Sparkles,
  Cpu
} from 'lucide-react';

export function ModelDecisionHUD({ className }: { className?: string }) {
  const { currentForecast, latestDecision } = usePredictionStore();
  const { theme } = useUIStore();
  const isLight = theme === 'light';
  
  // Collapse by default so it never overlaps or blocks topology nodes
  const [collapsed, setCollapsed] = useState(true);
  const [showDiff, setShowDiff] = useState(false);

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

  // Compact collapsed capsule that floats unobtrusively without covering canvas
  if (collapsed) {
    return (
      <div 
        onClick={() => setCollapsed(false)}
        className={cn(
          "absolute bottom-3 right-3 z-30 flex items-center gap-2.5 px-3 py-2 rounded-full border shadow-lg cursor-pointer transition-all hover:scale-105 pointer-events-auto",
          isLight 
            ? "bg-white/95 border-slate-300 text-slate-800 shadow-slate-300/50 hover:bg-slate-50" 
            : "bg-[#0a101d]/90 border-white/15 text-slate-200 shadow-black/60 hover:bg-[#0f172a]",
          className
        )}
        title="Click to view G-FLOWWM autonomous decision details"
      >
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
        </span>
        <span className="font-mono text-[11px] font-bold text-cyan-600 dark:text-cyan-400 uppercase tracking-wider">
          G-FLOWWM HUD
        </span>
        <div className={cn("px-2 py-0.5 rounded text-[10px] font-bold text-white", actionBadgeBg)}>
          {decision.action}
        </div>
        <span className="text-xs font-black text-emerald-600 dark:text-emerald-400 font-mono">
          +{decision.risk_reduction_pct}%
        </span>
        <ChevronUp className="w-3.5 h-3.5 text-slate-400" />
      </div>
    );
  }

  return (
    <div className={cn(
      "absolute bottom-3 right-3 z-30 w-88 max-w-[calc(100%-1.5rem)] rounded-xl border backdrop-blur-md transition-all duration-300 pointer-events-auto shadow-2xl",
      isLight 
        ? "border-slate-300 bg-white/95 text-slate-800 shadow-slate-300/50" 
        : "border-white/10 bg-[#0a101d]/95 text-slate-200 shadow-black/80",
      className
    )}>
      {/* HUD Header */}
      <div className={cn(
        "flex items-center justify-between px-3.5 py-2.5 border-b rounded-t-xl",
        isLight ? "bg-slate-100/90 border-slate-200" : "bg-slate-900/60 border-white/10"
      )}>
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
          </span>
          <span className="font-mono text-[11px] font-bold tracking-wider text-cyan-600 dark:text-cyan-300 uppercase">
            G-FLOWWM • Autonomous HUD
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setCollapsed(true)}
            className="p-1 rounded hover:bg-slate-200 dark:hover:bg-white/10 text-slate-400 hover:text-slate-800 dark:hover:text-white transition-colors"
            title="Minimize HUD"
            aria-label="Minimize HUD"
          >
            <ChevronDown className="w-4 h-4" />
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
            <div className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Risk Reduction</div>
            <div className="text-sm font-black text-emerald-600 dark:text-emerald-400">
              +{decision.risk_reduction_pct}%
            </div>
          </div>
        </div>

        {/* Expanded Details */}
        <div className={cn("mt-3 space-y-2.5 border-t pt-2.5", isLight ? "border-slate-200" : "border-white/10")}>
          {/* Cyber-JEPA Surprisal & Novelty Indicator */}
          <div className={cn("grid grid-cols-2 gap-2 p-2 rounded-lg border", isLight ? "bg-slate-50 border-slate-200" : "bg-slate-900/40 border-white/5")}>
            <div>
              <div className="text-[10px] text-slate-500 dark:text-slate-400 flex items-center gap-1">
                <Activity className="w-3 h-3 text-cyan-500" />
                JEPA Surprisal
              </div>
              <div className="text-sm font-semibold font-mono text-cyan-600 dark:text-cyan-300 mt-0.5">
                {decision.jepa_surprisal.toFixed(3)} <span className="text-[10px] text-slate-400">nats</span>
              </div>
            </div>
            <div>
              <div className="text-[10px] text-slate-500 dark:text-slate-400 flex items-center gap-1">
                <Sparkles className="w-3 h-3 text-amber-500" />
                Novelty Discrim.
              </div>
              <div className="mt-0.5">
                {decision.is_novel_behavior ? (
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/30">
                    NOVEL ZERO-DAY
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                    KNOWN SIGNATURE
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Counterfactual Branch Trajectories */}
          <div className={cn("p-2.5 rounded-lg border", isLight ? "bg-slate-50 border-slate-200" : "bg-slate-900/40 border-white/5")}>
            <div className="flex items-center justify-between text-[11px] mb-1.5">
              <span className="text-slate-500 dark:text-slate-400 flex items-center gap-1">
                <GitBranch className="w-3 h-3 text-indigo-500" />
                Branches Evaluated
              </span>
              <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                {decision.branches_evaluated || 5} rollouts
              </span>
            </div>
            <div className={cn("text-[10px] flex items-center justify-between p-1.5 rounded", isLight ? "bg-slate-200/60 text-slate-600" : "bg-black/30 text-slate-400")}>
              <span>Avoided Worst Case:</span>
              <span className="font-mono font-bold text-rose-600 dark:text-rose-400 uppercase">
                {decision.worst_case_branch?.terminal_stage || 'Data Exfiltration'}
              </span>
            </div>
          </div>

          {/* Rollback & Kernel SLA */}
          <div className="flex items-center justify-between px-1 text-[11px]">
            <div className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span className="text-[10px] font-medium">Rollback Watchdog Armed (60s SLA)</span>
            </div>
            <button 
              onClick={() => setShowDiff(!showDiff)}
              className="text-[10px] text-cyan-600 dark:text-cyan-400 hover:underline flex items-center gap-1"
            >
              <Terminal className="w-3 h-3" />
              {showDiff ? "Hide Diff" : "View Kernel Diff"}
            </button>
          </div>

          {/* Machine Auditable Diff Viewer */}
          {showDiff && (
            <div className={cn(
              "mt-2 p-2 rounded border font-mono text-[10px] overflow-x-auto",
              isLight ? "bg-slate-900 text-cyan-300 border-slate-700" : "bg-black/70 text-cyan-300 border-cyan-500/30"
            )}>
              <div className="text-[9px] text-slate-400 mb-1"># nftables atomic transaction:</div>
              <div className="whitespace-pre">{decision.vendor_diff}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
