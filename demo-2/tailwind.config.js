/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Status colors
        'status-normal': '#10B981',
        'status-suspicious': '#F59E0B',
        'status-compromised': '#EF4444',
        'status-contained': '#3B82F6',
        'status-deception': '#8B5CF6',
        'status-offline': '#6B7280',
        
        // Semantic colors
        'bg-primary': 'var(--bg-primary)',
        'bg-secondary': 'var(--bg-secondary)',
        'bg-tertiary': 'var(--bg-tertiary)',
        'text-primary': 'var(--text-primary)',
        'text-secondary': 'var(--text-secondary)',
        'border-primary': 'var(--border-primary)',
        'accent-blue': '#3B82F6',
        'accent-green': '#10B981',
        'accent-red': '#EF4444',
        'accent-yellow': '#F59E0B',
        'accent-purple': '#8B5CF6',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'flow': 'flow 2s linear infinite',
        'blink': 'blink 1s step-end infinite',
      },
      keyframes: {
        flow: {
          '0%': { strokeDashoffset: '0' },
          '100%': { strokeDashoffset: '100' },
        },
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0' },
        },
      },
    },
  },
  plugins: [],
};