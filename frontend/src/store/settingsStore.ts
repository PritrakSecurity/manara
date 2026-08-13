import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export interface BrandingSettings {
  logoUrl: string | null
  companyName: string
  primaryColor: string
  secondaryColor: string
  fontFamily: string
}

interface SettingsState {
  branding: BrandingSettings
  setBranding: (branding: Partial<BrandingSettings>) => void
  uploadLogo: (file: File) => Promise<string>
}

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set, get) => ({
      branding: {
        logoUrl: null,
        companyName: 'PRITRAK DLP',
        primaryColor: '#2563EB',
        secondaryColor: '#1E40AF',
        fontFamily: 'Inter',
      },
      setBranding: (branding) => {
        set((state) => ({
          branding: { ...state.branding, ...branding },
        }))
      },
      uploadLogo: async (file: File) => {
        // In production, this would upload to backend
        // For now, create a data URL
        return new Promise((resolve, reject) => {
          const reader = new FileReader()
          reader.onload = (e) => {
            const logoUrl = e.target?.result as string
            get().setBranding({ logoUrl })
            resolve(logoUrl)
          }
          reader.onerror = reject
          reader.readAsDataURL(file)
        })
      },
    }),
    {
      name: 'settings-storage',
    }
  )
)
