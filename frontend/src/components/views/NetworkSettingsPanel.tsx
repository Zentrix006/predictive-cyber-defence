import React, { useState, useEffect } from 'react';
import { Network, Save, Server, Shield } from 'lucide-react';
import { cn } from '@/utils/classnames';
import api from '@/lib/api';

export function NetworkSettingsPanel() {
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [config, setConfig] = useState({
    mgmt_iface: '',
    capture_iface: '',
    mgmt_subnet: '',
  });
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    // Fetch available interfaces
    api.get('/system/network-interfaces').then(res => {
      if (res.data?.interfaces) setInterfaces(res.data.interfaces);
    }).catch(console.error);
    
    // Fetch current config
    api.get('/system/network-config').then(res => {
      if (res.data?.config) {
        setConfig({
          mgmt_iface: res.data.config.MGMT_IFACE || '',
          capture_iface: res.data.config.CAPTURE_IFACE || '',
          mgmt_subnet: res.data.config.MGMT_SUBNET || '',
        });
      }
    }).catch(console.error);
  }, []);

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
        {/* Control Plane */}
        <div className="space-y-4">
          <div className="flex items-center gap-2 text-emerald-400 mb-2">
            <Server className="w-4 h-4" />
            <h3 className="font-medium">Management Plane (Control)</h3>
          </div>
          <p className="text-xs text-slate-400 mb-4">
            Interface used for active OSINT discovery (Nmap/SNMP) and SSH mitigations.
          </p>
          
          <div>
            <label className="block text-xs text-slate-500 mb-1">Management Interface</label>
            <select 
              value={config.mgmt_iface}
              onChange={(e) => setConfig({...config, mgmt_iface: e.target.value})}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-sm text-slate-200 focus:border-cyan-500 outline-none"
            >
              <option value="">-- Select Interface --</option>
              {interfaces.map(i => <option key={i} value={i}>{i}</option>)}
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
              {interfaces.map(i => <option key={i} value={i}>{i}</option>)}
            </select>
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
