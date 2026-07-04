"use client";
import { useState } from "react";
import { Copy } from "lucide-react";
export function CopyButton({ value, label }: { value: string; label: string }) { const [done, setDone] = useState(false); return <button className="button-secondary" onClick={async () => { await navigator.clipboard.writeText(value); setDone(true); setTimeout(() => setDone(false), 1200); }}><Copy size={14} />{done ? "Copied" : label}</button>; }
