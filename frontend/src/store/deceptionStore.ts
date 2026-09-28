import { create } from 'zustand';
import { HoneypotType, DeploymentStatus } from '@/types';

interface DeceptionState {
  pool: any[];
  deployments: any[];
  interactions: Map<string, any[]>;
  
  addDeployment: (deployment: any) => void;
  updateDeployment: (id: string, updates: Partial<any>) => void;
  removeDeployment: (id: string) => void;
  addInteraction: (deploymentId: string, interaction: any) => void;
  setPool: (pool: any[]) => void;
  setDeployments: (deployments: any[]) => void;
}

export const useDeceptionStore = create<DeceptionState>((set) => ({
  pool: [],
  deployments: [],
  interactions: new Map(),
  
  addDeployment: (deployment) => set((state) => ({
    deployments: [deployment, ...state.deployments],
  })),
  updateDeployment: (id, updates) => set((state) => ({
    deployments: state.deployments.map(d => d.id === id ? { ...d, ...updates } : d),
  })),
  removeDeployment: (id) => set((state) => ({
    deployments: state.deployments.filter(d => d.id !== id),
  })),
  addInteraction: (deploymentId, interaction) => set((state) => {
    const newInteractions = new Map(state.interactions);
    const existing = newInteractions.get(deploymentId) || [];
    newInteractions.set(deploymentId, [interaction, ...existing]);
    return { interactions: newInteractions };
  }),
  setPool: (pool) => set({ pool }),
  setDeployments: (deployments) => set({ deployments }),
}));