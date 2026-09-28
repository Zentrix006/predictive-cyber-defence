"use client";

import React, { useState, useEffect, useRef } from "react";
import { cn } from "@/utils/classnames";

interface CommandItem {
  id: string;
  category: "ACTION" | "NAVIGATION" | "ASSET";
  title: string;
  subtitle: string;
  badge?: string;
  handler: () => void;
}

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateView?: (viewId: string) => void;
}

export function CommandPalette({ isOpen, onClose, onNavigateView }: CommandPaletteProps) {
  const [search, setSearch] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands: CommandItem[] = [
    // Navigation
    {
      id: "nav-cmd-center",
      category: "NAVIGATION",
      title: "SOC Command Center",
      subtitle: "Main topology, live incident queue, and decision HUD",
      badge: "View",
      handler: () => {
        onNavigateView?.("command_center");
        onClose();
      },
    },
    {
      id: "nav-ai-intel",
      category: "NAVIGATION",
      title: "AI Intelligence & Cyber-JEPA",
      subtitle: "Latent world model dynamics, surprisal, and epistemic beliefs",
      badge: "View",
      handler: () => {
        onNavigateView?.("ai_intelligence");
        onClose();
      },
    },
    {
      id: "nav-forecast",
      category: "NAVIGATION",
      title: "Attack Forecast & Kill-Chain",
      subtitle: "Multi-step MITRE projection and ETA timeline",
      badge: "View",
      handler: () => {
        onNavigateView?.("attack_forecast");
        onClose();
      },
    },
    {
      id: "nav-deception",
      category: "NAVIGATION",
      title: "Honeynet Deception Farm",
      subtitle: "Decoys, diversion rules, and trapped adversarial sessions",
      badge: "View",
      handler: () => {
        onNavigateView?.("deception");
        onClose();
      },
    },
    {
      id: "nav-model-lab",
      category: "NAVIGATION",
      title: "Model Lab & Canary Deployment",
      subtitle: "Serving vs candidate checkpoints, EWC metrics, Platt calibration",
      badge: "View",
      handler: () => {
        onNavigateView?.("model_lab");
        onClose();
      },
    },

    // Autonomous Response Actions
    {
      id: "act-deception-divert",
      category: "ACTION",
      title: "Trigger Deception Diversion",
      subtitle: "Deploy high-interaction decoy and route adversarial flows into Honeynet",
      badge: "-84% Risk",
      handler: () => {
        alert("World Model: Triggered DECEPTION_DIVERT (-84% Risk Reduction)");
        onClose();
      },
    },
    {
      id: "act-isolate-host",
      category: "ACTION",
      title: "Immediate Host Isolation (nftables)",
      subtitle: "Compile atomic firewall isolation rule with 60s rollback watchdog",
      badge: "Containment",
      handler: () => {
        alert("Atomic isolation rule committed to kernel nftables.");
        onClose();
      },
    },
    {
      id: "act-rate-limit",
      category: "ACTION",
      title: "Engage Ingress Rate Limiting",
      subtitle: "Throttle volumetric DDoS / SYN flood traffic at boundary gateway",
      badge: "-45% Risk",
      handler: () => {
        alert("Boundary ingress rate-limiting policy enforced.");
        onClose();
      },
    },

    // Enterprise Assets
    {
      id: "asset-dc",
      category: "ASSET",
      title: "DOMAIN-CONTROLLER-01",
      subtitle: "10.0.0.12 (Active Directory & Kerberos KDC) [Crown Jewel]",
      badge: "Critical",
      handler: () => {
        onNavigateView?.("command_center");
        onClose();
      },
    },
    {
      id: "asset-web",
      category: "ASSET",
      title: "WEB-CORE-PROD",
      subtitle: "10.0.0.5 (Public HTTPS Ingress Cluster) [Targeted]",
      badge: "High Risk",
      handler: () => {
        onNavigateView?.("command_center");
        onClose();
      },
    },
    {
      id: "asset-db",
      category: "ASSET",
      title: "DB-VAULT-FINANCE",
      subtitle: "10.0.1.20 (Customer & Financial Transaction Storage)",
      badge: "Protected",
      handler: () => {
        onNavigateView?.("command_center");
        onClose();
      },
    },
  ];

  const filtered = commands.filter(
    (c) =>
      c.title.toLowerCase().includes(search.toLowerCase()) ||
      c.subtitle.toLowerCase().includes(search.toLowerCase()) ||
      c.category.toLowerCase().includes(search.toLowerCase())
  );

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
      setSelectedIndex(0);
    }
  }, [isOpen]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
          e.preventDefault();
          // Toggle open
        }
        return;
      }

      if (e.key === "Escape") {
        onClose();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev + 1) % Math.max(1, filtered.length));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev - 1 + filtered.length) % Math.max(1, filtered.length));
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (filtered[selectedIndex]) {
          filtered[selectedIndex].handler();
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, filtered, selectedIndex, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 bg-black/75 backdrop-blur-sm p-4">
      <div className="w-full max-w-xl rounded-xl border border-cyan-500/30 bg-slate-950 shadow-2xl overflow-hidden flex flex-col">
        {/* Search Input Bar */}
        <div className="flex items-center px-4 py-3 border-b border-slate-800 bg-slate-900/80">
          <span className="text-cyan-400 font-mono text-sm mr-2.5">⌘</span>
          <input
            ref={inputRef}
            type="text"
            placeholder="Type a command, search asset, or jump to view..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setSelectedIndex(0);
            }}
            className="flex-1 bg-transparent text-sm font-mono text-slate-100 placeholder-slate-500 focus:outline-none"
          />
          <span className="text-[10px] font-mono text-slate-500 border border-slate-700/60 px-1.5 py-0.5 rounded">
            ESC to close
          </span>
        </div>

        {/* Results List */}
        <div className="max-h-80 overflow-y-auto p-2 divide-y divide-slate-800/30 font-mono">
          {filtered.length === 0 ? (
            <div className="p-6 text-center text-sm text-slate-500 font-mono">
              No matching commands or assets found.
            </div>
          ) : (
            filtered.map((item, idx) => {
              const isSelected = idx === selectedIndex;
              return (
                <div
                  key={item.id}
                  onClick={item.handler}
                  className={cn(
                    "flex items-center justify-between p-2.5 rounded-lg cursor-pointer transition-colors text-xs",
                    isSelected ? "bg-cyan-950/60 text-cyan-200 border border-cyan-500/30" : "text-slate-300 hover:bg-slate-900"
                  )}
                >
                  <div className="flex flex-col gap-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-bold">{item.title}</span>
                      <span
                        className={cn(
                          "px-1.5 py-0.2 rounded text-[9px] font-bold uppercase",
                          item.category === "ACTION"
                            ? "bg-amber-950/80 text-amber-300 border border-amber-500/30"
                            : item.category === "NAVIGATION"
                            ? "bg-blue-950/80 text-blue-300 border border-blue-500/30"
                            : "bg-emerald-950/80 text-emerald-300 border border-emerald-500/30"
                        )}
                      >
                        {item.category}
                      </span>
                    </div>
                    <span className="text-[11px] text-slate-400">{item.subtitle}</span>
                  </div>

                  {item.badge && (
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {item.badge}
                    </span>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="flex items-center justify-between px-3 py-2 bg-slate-900/60 border-t border-slate-800 text-[10px] font-mono text-slate-400">
          <span>Navigate: ↑ ↓</span>
          <span>Select: ↵ Enter</span>
          <span>Quick Open: ⌘K</span>
        </div>
      </div>
    </div>
  );
}
