import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "WebGuard", template: "%s · WebGuard" },
  description: "Website security scan control plane",
  icons: {
    apple: "/webguard-icon.png",
    icon: "/webguard-icon.png",
    shortcut: "/webguard-icon.png",
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
