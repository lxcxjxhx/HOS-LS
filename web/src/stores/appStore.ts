import { create } from 'zustand'
import type { Finding, StarMapNode } from '../types'

interface AppState {
  sidebarCollapsed: boolean
  rightPanelOpen: boolean
  rightPanelType: 'finding' | 'node' | 'chat' | null
  rightPanelData: Finding | StarMapNode | null
  currentProject: string | null
  
  toggleSidebar: () => void
  openRightPanel: (type: AppState['rightPanelType'], data: AppState['rightPanelData']) => void
  closeRightPanel: () => void
  setCurrentProject: (project: string | null) => void
}

export const useAppStore = create<AppState>((set) => ({
  sidebarCollapsed: false,
  rightPanelOpen: false,
  rightPanelType: null,
  rightPanelData: null,
  currentProject: null,
  
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  
  openRightPanel: (type, data) => set({
    rightPanelOpen: true,
    rightPanelType: type,
    rightPanelData: data,
  }),
  
  closeRightPanel: () => set({
    rightPanelOpen: false,
    rightPanelType: null,
    rightPanelData: null,
  }),
  
  setCurrentProject: (project) => set({ currentProject: project }),
}))
