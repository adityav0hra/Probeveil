import clsx from "clsx";
export function StatusPill({ value }: { value: string }) {
  return (
    <span
      className={clsx(
        "inline-flex rounded-full border px-2 py-1 text-[10px] font-semibold uppercase tracking-wider",
        {
          "border-red-500/20 bg-red-500/10 text-red-200": [
            "COMPLETED",
            "CONFIRMED",
            "RUNNING",
            "READY",
            "RESPONDED",
            "SENT",
          ].includes(value),
          "border-amber-500/20 bg-amber-500/10 text-amber-300": [
            "QUEUED",
            "PENDING",
            "POTENTIAL",
            "NEW",
            "IN_REVIEW",
            "NOT_CONFIGURED",
          ].includes(value),
          "border-rose-500/30 bg-rose-500/10 text-rose-200": [
            "FAILED",
            "CRITICAL",
            "HIGH",
            "SPAM",
          ].includes(value),
          "border-slate-500/20 bg-slate-500/10 text-slate-400": [
            "CANCELLED",
            "SKIPPED",
            "CLOSED",
          ].includes(value),
        },
      )}
    >
      {value.replaceAll("_", " ")}
    </span>
  );
}
