import { create } from 'zustand';

type ViewType =
  | 'command-center'
  | 'network'
  | 'attack'
  | 'threat-actors'
  | 'deception'
  | 'forensics'
  | 'infrastructure'
  | 'model-lab'
  | 'ai-intelligence'
  | 'settings'
  | 'world-model'
  | 'graph-analysis'
  | 'passive-analysis'
  | 'presentation'
  | 'mitigation-cache';

interface UIState {
  theme: 'light' | 'dark';
  sidebarOpen: boolean;
  activeView: ViewType;
  notifications: any[];
  
  toggleTheme: () => void;
  setTheme: (theme: 'light' | 'dark') => void;
  toggleSidebar: () => void;
  setSidebarOpen: (isOpen: boolean) => void;
  setActiveView: (view: ViewType) => void;
  addNotification: (notification: any) => void;
  removeNotification: (id: string) => void;
}

export const useUIStore = create<UIState>((set) => ({
  theme: 'dark',
  sidebarOpen: true,
  activeView: 'command-center',
  notifications: [],
  
  toggleTheme: () => set((state) => ({ theme: state.theme === 'dark' ? 'light' : 'dark' })),
  setTheme: (theme) => set({ theme }),
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
  setActiveView: (view) => set({ activeView: view }),
  addNotification: (notification) => set((state) => ({
    notifications: [...state.notifications, { ...notification, id: Date.now().toString() }],
  })),
  removeNotification: (id) => set((state) => ({
    notifications: state.notifications.filter(n => n.id !== id),
  })),
}));
