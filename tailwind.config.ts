import type { Config } from "tailwindcss";
import forms from "@tailwindcss/forms";

export default {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#07090d",
        panel: "#10141b",
        line: "#222a36",
        signal: "#7cf8c4",
        cyan: "#5ad7ff",
      },
      fontFamily: { sans: ["Inter", "ui-sans-serif", "system-ui"] },
      boxShadow: { glow: "0 0 40px rgba(124,248,196,.08)" },
    },
  },
  plugins: [forms],
} satisfies Config;
