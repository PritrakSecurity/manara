import { create } from 'zustand'

export interface UpgradeModalContent {
  featureName: string
  requiredTier: string
  description: string
}

interface UIState {
  isUpgradeModalOpen: boolean
  modalContent: UpgradeModalContent | null
  openUpgradeModal: (featureName: string, requiredTier: string, description: string) => void
  closeUpgradeModal: () => void
}

export const useUIStore = create<UIState>((set) => ({
  isUpgradeModalOpen: false,
  modalContent: null,
  openUpgradeModal: (featureName, requiredTier, description) =>
    set({
      isUpgradeModalOpen: true,
      modalContent: { featureName, requiredTier, description },
    }),
  closeUpgradeModal: () => set({ isUpgradeModalOpen: false }),
}))
