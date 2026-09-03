/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          blue: '#246BFE',
          navy: '#0B1F3A',
          bg: '#F7F9FC',
          muted: '#68809F',
          border: '#E5E9F2',
          card: '#FFFFFF',
          success: '#10B981',
          warning: '#F59E0B',
          critical: '#EF4444',
        },
        soc: {
          navy: '#0B1F3A',
          dark: '#0B1F3A',
          slate: '#68809F',
          accent: '#246BFE',
          cyan: '#06B6D4',
          surface: '#FFFFFF',
          border: '#E5E9F2',
          success: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
        }
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      }
    },
  },
  plugins: [],
}
