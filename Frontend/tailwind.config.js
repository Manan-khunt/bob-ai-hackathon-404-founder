/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        'hacker-black': '#080C08',
        'hacker-panel': '#0C110C',
        'hacker-border': '#1A2E1A',
        'hacker-green': '#00FF41',
        'hacker-green-dim': '#00C032',
        'hacker-green-dark': '#004D18',
        'hacker-amber': '#FFB300',
        'hacker-red': '#FF2D2D',
        'hacker-blue': '#00B4D8',
        'hacker-white': '#C8FAD6',
        'hacker-muted': '#3D6B3D',
        'hacker-purple': '#7C3AED',
      },
      fontFamily: {
        mono: ['"Share Tech Mono"', 'monospace'],
        orbitron: ['Orbitron', 'sans-serif'],
        body: ['Inter', 'sans-serif'],
      },
      borderRadius: {
        hard: '4px',
      },
      keyframes: {
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
        pulseRed: {
          '0%, 100%': { borderColor: '#FF2D2D', boxShadow: '0 0 6px rgba(255,45,45,0.45)' },
          '50%': { borderColor: '#7a0000', boxShadow: '0 0 2px rgba(255,45,45,0.15)' },
        },
        dashFlow: {
          to: { strokeDashoffset: '-20' },
        },
        flashGreen: {
          '0%': { backgroundColor: 'rgba(0,255,65,0.35)' },
          '100%': { backgroundColor: 'transparent' },
        },
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
      },
      animation: {
        blink: 'blink 1s step-end infinite',
        'pulse-red': 'pulseRed 1.4s ease-in-out infinite',
        'dash-flow': 'dashFlow 1.2s linear infinite',
        'flash-green': 'flashGreen 0.5s ease-out',
        'fade-in': 'fadeIn 0.4s ease-out',
      },
    },
  },
  plugins: [],
}