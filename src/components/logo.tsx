import { ShieldCheck } from "lucide-react";
export function Logo() {
  return (
    <div className="flex items-center gap-3">
      <span className="grid size-9 place-items-center rounded-lg border border-signal/25 bg-signal/10 text-signal">
        <ShieldCheck size={19} />
      </span>
      <div>
        <div className="font-semibold tracking-tight text-white">Probeveil</div>
        <div className="text-[10px] uppercase tracking-[.18em] text-slate-600">
          Scan Console
        </div>
      </div>
    </div>
  );
}
