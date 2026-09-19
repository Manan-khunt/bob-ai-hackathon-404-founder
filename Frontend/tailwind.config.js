/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        defence: {
          darkest: '#070B14',
          base: '#0B1120',
          surface: '#0F172A',
          card: '#131D31',
          cardHover: '#18243D',
          border: '#1E293B',
          borderLight: '#334155',
          accent: '#0EA5E9',
          accentGlow: '#38BDF8',
          blue: '#2563EB',
          critical: '#EF4444',
          warning: '#F59E0B',
          success: '#10B981',
          muted: '#64748B',
          text: '#F8FAFC',
          subtext: '#94A3B8',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': '0.65rem',
      },
      boxShadow: {
        'defence': '0 4px 20px -2px rgba(0, 0, 0, 0.45)',
        'defence-lg': '0 10px 30px -4px rgba(0, 0, 0, 0.6)',
        'defence-border': '0 0 0 1px rgba(30, 41, 59, 0.8)',
      },
    },
  },
  plugins: [],
}