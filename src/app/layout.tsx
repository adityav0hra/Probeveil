import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Probeveil", template: "%s · Probeveil" },
  description: "Website security scan control plane",
  icons: {
    apple: "/probeveil-icon-red.png",
    icon: "/probeveil-icon-red.png",
    shortcut: "/probeveil-icon-red.png",
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
