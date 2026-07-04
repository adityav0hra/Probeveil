import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Probeveil", template: "%s · Probeveil" },
  description: "Website security scan control plane",
  icons: {
    apple: "/probeveil-icon.png",
    icon: "/probeveil-icon.png",
    shortcut: "/probeveil-icon.png",
  },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
