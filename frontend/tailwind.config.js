/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#070B14',
          900: '#0B1120',
          850: '#0E172A',
          800: '#111C33',
          750: '#182542',
          700: '#1E2D4A',
          600: '#2A3F66',
        },
        shield: {
          cyan: '#06B6D4',
          cyanGlow: 'rgba(6, 182, 212, 0.25)',
          indigo: '#6366F1',
          indigoGlow: 'rgba(99, 102, 241, 0.25)',
          safe: '#10B981',
          safeGlow: 'rgba(16, 185, 129, 0.25)',
          warn: '#F59E0B',
          warnGlow: 'rgba(245, 158, 11, 0.25)',
          danger: '#EF4444',
          dangerGlow: 'rgba(239, 68, 68, 0.25)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        display: ['Outfit', 'Inter', 'sans-serif'],
      },
      animation: {
        'radar-sweep': 'radar 3s linear infinite',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-bar': 'scanBar 2s ease-in-out infinite',
      },
      keyframes: {
        radar: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        scanBar: {
          '0%, 100%': { transform: 'translateY(0%)', opacity: '0.4' },
          '50%': { transform: 'translateY(100%)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
};
