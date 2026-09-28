import { create } from 'zustand';

interface Incident {
  id: string;
  title: string;
  description?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'contained' | 'closed';
  detected_at: string;
  current_stage?: string;
  threat_score: number;
}

interface IncidentState {
  incidents: any[];
  activeIncident: any | null;
  filters: {
    status?: string[];
    severity?: string[];
    dateFrom?: string;
    dateTo?: string;
  };
  
  setIncidents: (incidents: any[]) => void;
  setActiveIncident: (incident: any | null) => void;
  updateIncident: (id: string, updates: Partial<any>) => void;
  setFilters: (filters: IncidentState['filters']) => void;
  addIncident: (incident: any) => void;
}

export const useIncidentStore = create<IncidentState>((set) => ({
  incidents: [],
  activeIncident: null,
  filters: {},
  
  setIncidents: (incidents) => set({ incidents: Array.isArray(incidents) ? incidents : [] }),
  setActiveIncident: (incident) => set({ activeIncident: incident }),
  updateIncident: (id, updates) => set((state) => ({
    incidents: state.incidents.map(i => i.id === id ? { ...i, ...updates } : i),
    activeIncident: state.activeIncident?.id === id ? { ...state.activeIncident, ...updates } : state.activeIncident,
  })),
  setFilters: (filters) => set({ filters }),
  addIncident: (incident) => set((state) => ({ incidents: [incident, ...state.incidents] })),
}));