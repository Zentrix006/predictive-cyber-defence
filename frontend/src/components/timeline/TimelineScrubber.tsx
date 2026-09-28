"use client";

import React, { useState, useEffect } from "react";
import { usePredictionStore } from "@/store/predictionStore";
import { useTopologyStore } from "@/store/topologyStore";
import { cn } from "@/utils/classnames";

interface TimelineScrubberProps {
  className?: string;
  onTimeChange?: (offsetSeconds: number) => void;
}

export function TimelineScrubber({ className, onTimeChange }: TimelineScrubberProps) {
  const [timeOffset, setTimeOffset] = useState<number>(0); // -60 to +90
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const { currentForecast, latestDecision } = usePredictionStore();

  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;
    if (isPlaying) {
      interval = setInterval(() => {
        setTimeOffset((prev) => {
          if (prev >= 90) {
            setIsPlaying(false);
            return 90;
          }
          const next = prev + 5;
          onTimeChange?.(next);
          return next;
        });
      }, 500);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isPlaying, onTimeChange]);

  const handleSliderChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseInt(e.target.value, 10);
    setTimeOffset(val);
    onTimeChange?.(val);
  };

  const resetToLive = () => {
    setTimeOffset(0);
    setIsPlaying(false);
    onTimeChange?.(0);
  };

  // Determine current timeline status
  const isPast = timeOffset < 0;
  const isLive = timeOffset === 0;
  const isFuture = timeOffset > 0;

  const currentWindowIdx = isFuture ? Math.min(3, Math.floor(timeOffset / 30)) : 0;
  const predictedWindow = currentForecast?.timeline?.[currentWindowIdx];

  return (
    <div
      className={cn(
        "rounded-xl border border-cyan-500/20 bg-slate-950/85 p-3.5 backdrop-blur-md shadow-xl select-none",
        className
      )}
    >
      {/* Top Header & Mode Indicators */}
      <div className="flex items-center justify-between gap-3 mb-2.5">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5">
            <span
              className={cn(
                "h-2.5 w-2.5 rounded-full transition-all duration-300",
                isLive
                  ? "bg-emerald-400 animate-pulse shadow-[0_0_8px_#34d399]"
                  : isPast
                  ? "bg-amber-400"
                  : "bg-cyan-400 animate-pulse shadow-[0_0_8px_#38bdf8]"
              )}
            />
            <span className="text-xs font-mono font-bold tracking-wider text-slate-200 uppercase">
              {isLive ? "LIVE TELEMETRY" : isPast ? "HISTORICAL SNAPSHOT" : "IMAGINED FUTURE (G-FLOWWM)"}
            </span>
          </div>

          <span
            className={cn(
              "px-2 py-0.5 text-[10px] font-mono font-bold rounded border",
              isLive
                ? "bg-emerald-950/60 border-emerald-500/30 text-emerald-300"
                : isPast
                ? "bg-amber-950/60 border-amber-500/30 text-amber-300"
                : "bg-cyan-950/60 border-cyan-500/30 text-cyan-300"
            )}
          >
            {timeOffset === 0 ? "T = 0s" : `${timeOffset > 0 ? "+" : ""}${timeOffset}s`}
          </span>
        </div>

        {/* Future Prediction Quick Insights */}
        {isFuture && predictedWindow && (
          <div className="hidden sm:flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Forecasted Stage:</span>
            <span className="text-amber-400 font-bold uppercase tracking-wide">
              {predictedWindow.stage || "Lateral Movement"}
            </span>
            <span className="text-cyan-400/80">({Math.round((predictedWindow.confidence || 0.85) * 100)}% prob)</span>
          </div>
        )}

        {/* Controls */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="px-2.5 py-1 text-xs font-mono font-semibold rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors border border-slate-700/60"
            title={isPlaying ? "Pause timeline replay" : "Play timeline simulation"}
          >
            {isPlaying ? "❚❚ Pause" : "▶ Play"}
          </button>
          {!isLive && (
            <button
              onClick={resetToLive}
              className="px-2 py-1 text-xs font-mono font-semibold rounded bg-emerald-900/50 hover:bg-emerald-800/60 text-emerald-300 border border-emerald-500/30 transition-colors"
              title="Return to live streaming telemetry"
            >
              ● Jump to Live
            </button>
          )}
        </div>
      </div>

      {/* Scrubber Range Slider */}
      <div className="relative flex items-center px-1">
        <input
          type="range"
          min="-60"
          max="90"
          step="5"
          value={timeOffset}
          onChange={handleSliderChange}
          className="w-full h-2 rounded-lg bg-slate-800 appearance-none cursor-pointer accent-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
        />
      </div>

      {/* Axis Tick Marks & Key Milestones */}
      <div className="flex justify-between items-center text-[10px] font-mono text-slate-500 mt-2 px-1">
        <span className="hover:text-amber-300 cursor-pointer" onClick={() => setTimeOffset(-60)}>
          -60s (Ingress)
        </span>
        <span className="hover:text-amber-300 cursor-pointer" onClick={() => setTimeOffset(-30)}>
          -30s
        </span>
        <span
          className={cn(
            "font-bold cursor-pointer transition-colors",
            isLive ? "text-emerald-400 font-extrabold" : "text-slate-400 hover:text-emerald-300"
          )}
          onClick={() => setTimeOffset(0)}
        >
          NOW (0s)
        </span>
        <span className="hover:text-cyan-300 cursor-pointer" onClick={() => setTimeOffset(30)}>
          +30s (Step 1)
        </span>
        <span className="hover:text-cyan-300 cursor-pointer" onClick={() => setTimeOffset(60)}>
          +60s (Step 2)
        </span>
        <span className="hover:text-cyan-300 cursor-pointer" onClick={() => setTimeOffset(90)}>
          +90s (Horizon)
        </span>
      </div>
    </div>
  );
}
