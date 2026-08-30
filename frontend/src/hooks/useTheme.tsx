import { useState } from 'react'

export type Theme = 'dark' | 'light'

export function getStoredTheme(): Theme {
  return (localStorage.getItem('harbore_theme') as Theme) || 'dark'
}

export function applyTheme(t: Theme) {
  document.documentElement.classList.toggle('light', t === 'light')
}

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(getStoredTheme())
  const setTheme = (t: Theme) => {
    localStorage.setItem('harbore_theme', t)
    applyTheme(t)
    setThemeState(t)
  }
  return { theme, setTheme, toggle: () => setTheme(theme === 'dark' ? 'light' : 'dark') }
}
