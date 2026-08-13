import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export interface User {
  id: string
  email: string
  name: string
  role: 'admin' | 'analyst' | 'viewer'
  department?: string
}

interface AuthState {
  user: User | null
  token: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  logout: () => void
  setUser: (user: User) => void
  setToken: (token: string, refreshToken?: string) => void
  checkAuth: () => boolean
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,

      logout: () => {
        set({
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
        })
      },

      setUser: (user: User) => {
        set({ user })
      },

      setToken: (token: string, refreshToken?: string) => {
        set({ token, refreshToken: refreshToken || null })
      },

      checkAuth: () => {
        const { token, isAuthenticated } = get()
        if (!token || !isAuthenticated) return false

        // For mock tokens, just check if they exist
        if (token.startsWith('mock-')) {
          return true
        }

        // Check if token is expired (basic check for real JWT)
        try {
          const payload = JSON.parse(atob(token.split('.')[1]))
          if (payload.exp && payload.exp * 1000 < Date.now()) {
            get().logout()
            return false
          }
          return true
        } catch {
          // If token parsing fails but token exists, assume valid for dev
          return true
        }
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        refreshToken: state.refreshToken,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)
