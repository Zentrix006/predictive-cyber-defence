import { create } from 'zustand';
import { AttackForecast, ForecastWindow, PredictedTarget, Explanation, ModelDecision } from '@/types';

interface PredictionState {
  currentForecast: AttackForecast | null;
  forecastHistory: AttackForecast[];
  explanation: Explanation | null;
  latestDecision: ModelDecision | null;
  
  setForecast: (forecast: AttackForecast) => void;
  addToHistory: (forecast: AttackForecast) => void;
  setExplanation: (explanation: Explanation) => void;
  setLatestDecision: (decision: ModelDecision | null) => void;
  clearForecast: () => void;
}

export const usePredictionStore = create<PredictionState>((set) => ({
  currentForecast: null,
  forecastHistory: [],
  explanation: null,
  latestDecision: null,
  
  setForecast: (forecast) => set((state) => ({
    currentForecast: forecast,
    latestDecision: forecast?.model_decision || state.latestDecision,
  })),
  addToHistory: (forecast) => set((state) => ({
    forecastHistory: [forecast, ...state.forecastHistory.slice(0, 49)],
  })),
  setExplanation: (explanation) => set({ explanation }),
  setLatestDecision: (latestDecision) => set({ latestDecision }),
  clearForecast: () => set({ currentForecast: null, explanation: null, latestDecision: null }),
}));