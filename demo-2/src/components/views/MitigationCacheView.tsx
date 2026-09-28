import React, { useState, useEffect } from 'react';
import { Search, ShieldAlert, Cpu, Terminal, PlayCircle } from 'lucide-react';

export function MitigationCacheView() {
  const [templates, setTemplates] = useState<Array<{ id: number; vendor: string; os_version: string; intent: string; syntax: string }>>([]);
  const [loading, setLoading] = useState(true);

  // Mock fetching from the new backend OSINT cache
  useEffect(() => {
    // Simulate API call
    setTimeout(() => {
      setTemplates([
        {
          id: 1,
          vendor: 'MikroTik',
          os_version: 'RouterOS 7',
          intent: 'BLOCK_IP_INGRESS',
          syntax: 'ip firewall filter add action=drop chain=input src-address={{ target_ip }}',
        },
        {
          id: 2,
          vendor: 'Palo Alto Networks',
          os_version: 'PAN-OS 10.1',
          intent: 'ISOLATE_MAC',
          syntax: 'set network vlan {{ quarantine_vlan }} mac-forwarding drop {{ target_mac }}',
        },
        {
          id: 3,
          vendor: 'Cisco',
          os_version: 'IOS XE 16.9',
          intent: 'SHUTDOWN_INTERFACE',
          syntax: 'interface {{ interface }}\n shutdown',
        }
      ]);
      setLoading(false);
    }, 1000);
  }, []);

  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto bg-slate-950 text-slate-200">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-2">
            <Search className="w-8 h-8 text-cyan-400" />
            OSINT Syntax Profiler Cache
          </h1>
          <p className="text-slate-400 mt-2">
            Proactively discovered configuration templates for real-time incident mitigation.
          </p>
        </div>
        <button className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded-md font-medium transition-colors">
          <PlayCircle className="w-4 h-4" /> Trigger Manual Profiling
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div className="col-span-full flex justify-center py-12 text-cyan-500">
            Loading templates...
          </div>
        ) : (
          templates.map((tpl) => (
            <div key={tpl.id} className="border border-slate-800 bg-slate-900 rounded-lg p-5 flex flex-col shadow-lg shadow-black/50">
              <div className="flex items-center justify-between mb-4 pb-4 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-indigo-400" />
                  <h3 className="font-semibold text-slate-100">{tpl.vendor}</h3>
                </div>
                <span className="text-xs px-2 py-1 bg-slate-800 text-slate-300 rounded-full font-mono">
                  {tpl.os_version}
                </span>
              </div>

              <div className="flex items-center gap-2 mb-3">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span className="text-sm font-medium text-rose-100 tracking-wide">{tpl.intent}</span>
              </div>

              <div className="bg-black/50 rounded-md p-3 relative group flex-1">
                <Terminal className="w-4 h-4 text-slate-500 absolute top-3 right-3" />
                <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap overflow-x-auto">
                  {tpl.syntax}
                </pre>
              </div>

              <div className="mt-4 flex gap-2">
                <button className="flex-1 bg-slate-800 hover:bg-slate-700 text-sm py-1.5 rounded text-cyan-300 transition-colors border border-slate-700">
                  Dry Run
                </button>
                <button className="flex-1 bg-indigo-900/50 hover:bg-indigo-800/50 text-sm py-1.5 rounded text-indigo-300 transition-colors border border-indigo-500/30">
                  Edit Template
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
