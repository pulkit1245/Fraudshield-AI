/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: {
          DEFAULT: "#05070B",
          surface: "#080C14",
          elevated: "#0D1320",
        },
        primary: {
          cyan: "#5EE7FF",
          blue: "#6C7BFF",
        },
        ai: {
          light: "#C4B5FD",
          DEFAULT: "#A78BFA",
        },
        status: {
          success: "#4ADE80",
          warning: "#FBBF24",
          threat: "#FF4D67",
        },
        text: {
          bright: "#F8FAFC",
          DEFAULT: "#CBD5E1",
          muted: "#64748B",
        },
        border: {
          DEFAULT: "rgba(148,163,184,0.12)",
        },
        band: {
          low: "#2a9e65",
          medium: "#c0872a",
          high: "#c0672a",
          critical: "#b91c1c",
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      transitionTimingFunction: {
        'spring': 'cubic-bezier(0.175, 0.885, 0.32, 1.275)',
      }
    },
  },
  plugins: [],
};
