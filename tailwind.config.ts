import type { Config } from "tailwindcss";
import forms from "@tailwindcss/forms";

export default {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#08090b",
        panel: "#101114",
        line: "#2a2d34",
        signal: "#ef4444",
        cyan: "#94a3b8",
      },
      fontFamily: { sans: ["Inter", "ui-sans-serif", "system-ui"] },
      boxShadow: { glow: "0 16px 40px rgba(0,0,0,.24)" },
    },
  },
  plugins: [forms],
} satisfies Config;
