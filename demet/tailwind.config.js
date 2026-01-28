/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        vault: {
          dark: '#0a0a0a',
          darker: '#050505',
          neutral: '#1a1a1a',
          border: '#2a2a2a',
          muted: '#6b6b6b',
        },
        gold: {
          DEFAULT: '#d4af37',
          light: '#f4d03f',
          dark: '#b8941f',
        },
        silver: {
          DEFAULT: '#c0c0c0',
          light: '#e8e8e8',
          dark: '#808080',
        },
        copper: {
          DEFAULT: '#b87333',
          light: '#d4a574',
          dark: '#8b5a2b',
        },
        platinum: {
          DEFAULT: '#e5e4e2',
          light: '#f5f5f5',
          dark: '#b8b8b8',
        },
        uranium: {
          DEFAULT: '#00ff41',
          light: '#4dff6e',
          dark: '#00cc33',
        },
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'SF Pro Display', 'system-ui', 'sans-serif'],
        display: ['-apple-system', 'BlinkMacSystemFont', 'SF Pro Display', 'system-ui', 'sans-serif'],
      },
      animation: {
        'shimmer': 'shimmer 3s ease-in-out infinite',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        shimmer: {
          '0%, 100%': { opacity: '0.7', transform: 'translateX(0)' },
          '50%': { opacity: '1', transform: 'translateX(10px)' },
        },
      },
    },
  },
  plugins: [],
}
