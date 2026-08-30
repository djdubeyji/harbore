/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // ── Cyber-Amber Sentinel — Deep Midnight & Electric Amber ──────────────
        surface: {
          0: '#080C14', // obsidian base (app background)
          1: '#0B1120', // raised base (sidebar)
          2: '#0F172A', // deep slate (cards)
          3: '#141E33', // elevated
          4: '#1C283F', // hover / high elevation
        },
        border: {
          DEFAULT: 'rgba(255,122,0,0.20)', // amber-tinted detail border
          bright:  'rgba(255,122,0,0.40)',
        },
        accent: {
          // `blue` is intentionally repointed to amber so every existing
          // `accent-blue` class across the app becomes the primary accent.
          blue:    '#FF7A00',
          amber:   '#FF7A00', // primary accent (electric amber)
          gold:    '#FFAA00', // secondary glow (signal gold)
          emerald: '#10B981', // passed / success
          crimson: '#F43F5E', // critical
          red:     '#F43F5E',
          orange:  '#FF7A00',
          yellow:  '#FFAA00',
          green:   '#10B981',
          purple:  '#A855F7',
          pink:    '#EC4899',
        },
        sev: {
          critical: '#F43F5E',
          high:     '#FF7A00',
          medium:   '#FFAA00',
          low:      '#38BDF8', // kept distinct (sky) for severity legibility
          info:     '#64748B',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'amber':     '0 0 0 1px rgba(255,122,0,0.25), 0 0 22px -4px rgba(255,122,0,0.45)',
        'amber-sm':  '0 0 12px -2px rgba(255,122,0,0.40)',
        'glow-gold': '0 0 24px -6px rgba(255,170,0,0.50)',
      },
      animation: {
        'pulse-slow':  'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
        'fade-in':     'fadeIn 0.2s ease-out',
        'slide-up':    'slideUp 0.2s ease-out',
        'amber-pulse': 'amberPulse 2.4s ease-in-out infinite',
      },
      keyframes: {
        fadeIn:  { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        slideUp: { '0%': { opacity: '0', transform: 'translateY(8px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        amberPulse: {
          '0%,100%': { boxShadow: '0 0 0 0 rgba(255,122,0,0.45)' },
          '50%':     { boxShadow: '0 0 0 4px rgba(255,122,0,0)' },
        },
      },
    },
  },
  plugins: [],
}
