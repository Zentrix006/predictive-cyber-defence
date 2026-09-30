import React, { useState, useEffect } from 'react';
import { Network, Save, Server, Shield } from 'lucide-react';
import { cn } from '@/utils/classnames';
import api from '@/lib/api';

export function NetworkSettingsPanel() {
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [hostVisibility, setHostVisibility] = useState(false);
  const [config, setConfig] = useState({
    mgmt_iface: '',
    capture_iface: '',
    mgmt_subnet: '',
    mgmt_vlan: 40,
    mgmt_cidr: '',
    mgmt_gateway: '',
    capture_mode: 'span_tap',
    flow_export_enabled: false,
    live_telemetry_enabled: false,
  });
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    const refreshInterfaces = () => {
      api.get<{ interfaces?: string[]; host_visibility?: boolean }>('/system/network-interfaces').then(res => {
        if (res.interfaces) setInterfaces(res.interfaces);
        setHostVisibility(Boolean(res.host_visibility));
      }).catch(console.error);
    };
    // Refresh so a WLAN, VLAN, TAP, or USB NIC added after page load appears
    // without requiring a full dashboard reload.
    refreshInterfaces();
    const interfaceTimer = window.setInterval(refreshInterfaces, 10000);
    
    // Fetch current config
    api.get<{ config?: Record<string, string> }>('/system/network-config').then(res => {
      if (res.config) {
        setConfig({
          mgmt_iface: res.config.MGMT_IFACE || '',
          capture_iface: res.config.CAPTURE_IFACE || '',
          mgmt_subnet: res.config.MGMT_SUBNET || '',
          mgmt_vlan: Number(res.config.TELEMETRY_MGMT_VLAN || 40),
          mgmt_cidr: res.config.TELEMETRY_MGMT_CIDR || res.config.MGMT_SUBNET || '',
          mgmt_gateway: res.config.TELEMETRY_MGMT_GATEWAY || '',
          capture_mode: res.config.TELEMETRY_CAPTURE_MODE || 'span_tap',
          flow_export_enabled: String(res.config.FLOW_EXPORT_ENABLED).toLowerCase() === 'true',
          live_telemetry_enabled: String(res.config.LIVE_TELEMETRY_ENABLED).toLowerCase() === 'true',
        });
      }
    }).catch(console.error);

    return () => window.clearInterval(interfaceTimer);
  }, []);

  const interfaceOptions = Array.from(new Set([...
    interfaces,
    config.mgmt_iface,
    config.capture_iface,
  ].filter(Boolean))).sort();

  const handleSave = async () => {
    setLoading(true);
    try {
      await api.post('/system/network-config', config);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 mb-6">
      <div className="flex items-center gap-2 mb-6 border-b border-slate-800 pb-4">
        <Network className="w-5 h-5 text-cyan-400" />
        <h2 className="text-lg font-semibold text-slate-100">Dual-Homed Network Architecture</h2>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="lg:col-span-2 flex items-center justify-between rounded-lg border border-cyan-900/60 bg-cyan-950/20 p-4">
          <div><div className="font-medium text-slate-100">Enable live telemetry collector</div><p className="mt-1 text-xs text-slate-400">Starts the supervised Zeek/NetFlow ingestion stream. The capture interface remains read-only and passive.</p></div>
          <button type="button" role="switch" aria-label="Enable live telemetry collector" aria-checked={config.live_telemetry_enabled} onClick={() => setConfig({...config, live_telemetry_enabled: !config.live_telemetry_enabled})} className={cn('relative flex h-8 w-14 shrink-0 items-center rounded-full p-1 transition-colors', config.live_telemetry_enabled ? 'bg-emerald-500' : 'bg-slate-700')}><span className={cn('block h-6 w-6 rounded-full bg-white shadow-sm transition-transform', config.live_telemetry_enabled ? 'translate-x-6' : 'translate-x-0')} /></button>
        </div>
        {/* Control Plane */}
        <div className="space-y-4">
          <div className="flex items-center gap-2 text-emerald-400 mb-2">
            <Server className="w-4 h-4" />
            <h3 className="font-medium">Management Plane (Control)</h3>
          </div>
          <p className="text-xs text-slate-400 mb-4">
            Interface used for active OSINT discovery (Nmap/SNMP) and SSH mitigations. {hostVisibility ? 'Host interfaces are available.' : 'Showing interfaces visible to the API container.'}
          </p>
          
          <div>
            <label className="block text-xs text-slate-500 mb-1">Management Interface</label>
            <select 
              value={config.mgmt_iface}
              onChange={(e) => setConfig({...config, mgmt_iface: e.target.value})}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-sm text-slate-200 focus:border-cyan-500 outline-none"
            >
              <option value="">-- Select Interface --</option>
              {interfaceOptions.map(i => <option key={i} value={i}>{i}</option>)}
            </select>
          </div>

          <div>
            <label className="block text-xs text-slate-500 mb-1">Management Subnet (CIDR)</label>
            <input 
              type="text" 
              placeholder="e.g., 172.20.20.0/24"
              value={config.mgmt_subnet}
              onChange={(e) => setConfig({...config, mgmt_subnet: e.target.value})}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-sm text-slate-200 focus:border-cyan-500 outline-none"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><label className="block text-xs text-slate-500 mb-1">Management VLAN ID</label><input type="number" min={1} max={4094} value={config.mgmt_vlan} onChange={(e) => setConfig({...config, mgmt_vlan: Number(e.target.value)})} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-sm text-slate-200 focus:border-cyan-500 outline-none" /></div>
            <div><label className="block text-xs text-slate-500 mb-1">Gateway (optional)</label><input type="text" placeholder="172.20.20.1" value={config.mgmt_gateway} onChange={(e) => setConfig({...config, mgmt_gateway: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-sm text-slate-200 focus:border-cyan-500 outline-none" /></div>
          </div>
        </div>

        {/* Data Plane */}
        <div className="space-y-4">
          <div className="flex items-center gap-2 text-rose-400 mb-2">
            <Shield className="w-4 h-4" />
            <h3 className="font-medium">Data Plane (Capture/SPAN)</h3>
          </div>
          <p className="text-xs text-slate-400 mb-4">
            Interface connected to a SPAN/Mirror port for invisible packet sniffing.
          </p>
          
          <div>
            <label className="block text-xs text-slate-500 mb-1">Capture Interface (Promiscuous)</label>
            <select 
              value={config.capture_iface}
              onChange={(e) => setConfig({...config, capture_iface: e.target.value})}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-sm text-slate-200 focus:border-rose-500 outline-none"
            >
              <option value="">-- Select Interface --</option>
              {interfaceOptions.map(i => <option key={i} value={i}>{i}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><label className="block text-xs text-slate-500 mb-1">Capture mode</label><select value={config.capture_mode} onChange={(e) => setConfig({...config, capture_mode: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-sm text-slate-200 focus:border-rose-500 outline-none"><option value="span_tap">SPAN / TAP</option><option value="zeek_file">Zeek file tail</option><option value="flow_export">Flow export</option></select></div>
            <label className="flex items-center gap-2 self-end pb-2 text-xs text-slate-400"><input type="checkbox" checked={config.flow_export_enabled} onChange={(e) => setConfig({...config, flow_export_enabled: e.target.checked})} /> Enable flow export listener</label>
          </div>
        </div>
      </div>

      <div className="mt-8 flex justify-end">
        <button 
          onClick={handleSave}
          disabled={loading}
          className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white px-6 py-2 rounded font-medium transition-colors disabled:opacity-50"
        >
          <Save className="w-4 h-4" />
          {loading ? 'Saving...' : success ? 'Saved!' : 'Save Configuration'}
        </button>
      </div>
    </div>
  );
}
