import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type Theme = 'dark' | 'light' | 'system'

interface ThemeState {
  theme: Theme
  resolvedTheme: 'dark' | 'light'
  setTheme: (theme: Theme) => void
  toggleTheme: () => void
}

const getSystemTheme = (): 'dark' | 'light' => {
  if (typeof window === 'undefined') return 'dark'
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set, get) => {
      const resolveTheme = (theme: Theme): 'dark' | 'light' => {
        if (theme === 'system') {
          return getSystemTheme()
        }
        return theme
      }

      const initialTheme = (localStorage.getItem('theme-storage')
        ? JSON.parse(localStorage.getItem('theme-storage') || '{}')?.state?.theme
        : 'dark') as Theme || 'dark'

      return {
        theme: initialTheme,
        resolvedTheme: resolveTheme(initialTheme),
        setTheme: (theme: Theme) => {
          const resolved = resolveTheme(theme)
          set({ theme, resolvedTheme: resolved })

          // Apply theme to document
          const root = document.documentElement
          root.classList.remove('light', 'dark')
          root.classList.add(resolved)
        },
        toggleTheme: () => {
          const current = get().resolvedTheme
          const newTheme = current === 'dark' ? 'light' : 'dark'
          get().setTheme(newTheme)
        },
      }
    },
    {
      name: 'theme-storage',
    }
  )
)
