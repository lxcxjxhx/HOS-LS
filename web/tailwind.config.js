/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        celestial: {
          bg: '#0D0D1A',
          surface: '#1A1A2E',
          surfaceLight: '#222240',
          border: '#2A2A4A',
          primary: '#6A0DAD',
          primaryLight: '#8B3FCF',
          accent: '#00FF9C',
          accentDim: '#00CC7D',
          alert: '#8B0000',
          alertLight: '#CC3333',
          text: '#E0E0E0',
          textDim: '#9999AA',
          star: {
            high: '#FF4444',
            medium: '#FF8C00',
            low: '#4488FF',
            safe: '#44FF88',
          }
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      animation: {
        'pulse-star': 'pulse-star 2s ease-in-out infinite',
        'glow': 'glow 3s ease-in-out infinite',
        'supernova': 'supernova 1.5s ease-out',
        'blackhole': 'blackhole 4s linear infinite',
      },
      keyframes: {
        'pulse-star': {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.7', transform: 'scale(1.2)' },
        },
        'glow': {
          '0%, 100%': { filter: 'brightness(1)' },
          '50%': { filter: 'brightness(1.3)' },
        },
        'supernova': {
          '0%': { transform: 'scale(0)', opacity: '1' },
          '50%': { transform: 'scale(2)', opacity: '0.8' },
          '100%': { transform: 'scale(0)', opacity: '0' },
        },
        'blackhole': {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
      },
    },
  },
  plugins: [],
}
