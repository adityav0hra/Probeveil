export function ScoreRing({
  label,
  suffix = "/100",
  value,
}: {
  label: string;
  suffix?: string;
  value: number | null;
}) {
  const n = value ?? 0;
  return (
    <div className="flex items-center gap-4">
      <div
        className="relative grid size-20 place-items-center rounded-full"
        style={{
          background: `conic-gradient(#ef4444 ${n * 3.6}deg,#22252c 0)`,
        }}
      >
        <div className="grid size-[68px] place-items-center rounded-full bg-panel">
          <span className="text-xl font-semibold text-white">
            {value ?? "—"}
          </span>
        </div>
      </div>
      <div>
        <div className="eyebrow">{label}</div>
        <div className="mt-1 text-sm text-slate-400">
          {value === null ? "Pending" : `${value}${suffix}`}
        </div>
      </div>
    </div>
  );
}
