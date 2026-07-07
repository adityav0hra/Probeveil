import type { Config } from "tailwindcss";
import forms from "@tailwindcss/forms";

export default {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#09090b",
        panel: "#0d0d10",
        line: "#24262d",
        signal: "#dc2626",
        cyan: "#94a3b8",
      },
      fontFamily: { sans: ["Inter", "ui-sans-serif", "system-ui"] },
      boxShadow: { glow: "none" },
    },
  },
  plugins: [forms],
} satisfies Config;
