/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        band: {
          low: "#2a9e65",
          medium: "#c0872a",
          high: "#c0672a",
          critical: "#b91c1c",
        },
      },
    },
  },
  plugins: [],
};
