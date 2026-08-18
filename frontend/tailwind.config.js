/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: '#fd382f',
          hover: '#e02f26',
        },
        sidebar: {
          DEFAULT: 'rgb(var(--bg-sidebar) / <alpha-value>)',
          text: 'rgb(var(--text-sidebar-idle) / <alpha-value>)',
          active: 'rgb(var(--text-sidebar-active) / <alpha-value>)',
        },
        page: 'rgb(var(--bg-page-surface) / <alpha-value>)',
        card: 'rgb(var(--bg-card-surface) / <alpha-value>)',
        primary: 'rgb(var(--text-primary) / <alpha-value>)',
        secondary: 'rgb(var(--text-secondary) / <alpha-value>)',
        status: {
          critical: 'rgb(var(--status-critical) / <alpha-value>)',
          high: 'rgb(var(--status-high) / <alpha-value>)',
          medium: 'rgb(var(--status-medium) / <alpha-value>)',
          low: 'rgb(var(--status-low) / <alpha-value>)',
        },
        classification: {
          restricted: 'rgb(var(--class-restricted) / <alpha-value>)',
          confidential: 'rgb(var(--class-confidential) / <alpha-value>)',
          internal: 'rgb(var(--class-internal) / <alpha-value>)',
          public: 'rgb(var(--class-public) / <alpha-value>)',
        }
      },
    },
  },
  plugins: [],
}
