import { ArrowRight } from "lucide-react";

const modes = [
  ["QUICK", "Quick Scan", "Fast passive scan"],
  ["FULL", "Full Scan", "Deep application scan"],
  ["MAXIMUM", "Maximum Scan", "Maximum practical coverage"],
] as const;

type ScanMode = (typeof modes)[number][0];

export function isScanMode(
  value: string | null | undefined,
): value is ScanMode {
  return modes.some(([mode]) => mode === value);
}

export function NewScanForm({
  error,
  initialMode = "FULL",
  initialUrl = "",
}: {
  error?: string;
  initialMode?: ScanMode;
  initialUrl?: string;
}) {
  return (
    <form action="/api/scans" className="mt-8 space-y-7" method="post">
      <label className="block">
        <span className="text-sm font-medium text-slate-200">Website URL</span>
        <input
          autoComplete="url"
          autoFocus
          className="input mt-2 h-12"
          defaultValue={initialUrl}
          inputMode="url"
          name="url"
          placeholder="https://target-website.com"
          required
          type="text"
        />
      </label>
      <fieldset>
        <legend className="text-sm font-medium text-slate-200">
          Scan Mode
        </legend>
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          {modes.map(([value, label, description]) => (
            <label
              className="flex cursor-pointer items-start gap-3 rounded-xl border border-line bg-white/[.015] p-4 text-left transition hover:border-slate-600"
              key={value}
            >
              <input
                className="mt-1 size-4 shrink-0 accent-signal"
                defaultChecked={initialMode === value}
                name="mode"
                type="radio"
                value={value}
              />
              <span className="block">
                <span className="block text-sm font-semibold text-slate-100">
                  {label}
                </span>
                <span className="mt-1 block text-xs leading-5 text-slate-500">
                  {description}
                </span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset className="rounded-xl border border-line bg-white/[.015] p-4">
        <legend className="px-2 text-sm font-medium text-slate-200">
          Advanced coverage
        </legend>
        <div className="grid gap-3 sm:grid-cols-3">
          {[
            ["browserRendering", "Browser rendering"],
            ["apiDiscovery", "API discovery"],
            ["screenshotCapture", "Screenshots"],
          ].map(([name, label]) => (
            <label
              className="flex items-center gap-3 rounded-lg border border-line bg-black/20 px-3 py-2 text-sm text-slate-300"
              key={name}
            >
              <input className="size-4 accent-signal" name={name} type="checkbox" />
              {label}
            </label>
          ))}
        </div>
        <div className="mt-4 grid gap-4">
          <label className="block">
            <span className="text-sm font-medium text-slate-200">
              Authorization header
            </span>
            <input
              autoComplete="off"
              className="input mt-2"
              name="authHeader"
              placeholder="Bearer ey..."
              type="password"
            />
          </label>
          <label className="block">
            <span className="text-sm font-medium text-slate-200">
              Cookie header
            </span>
            <input
              autoComplete="off"
              className="input mt-2"
              name="cookieHeader"
              placeholder="session=..."
              type="password"
            />
          </label>
        </div>
      </fieldset>
      {error && (
        <p
          className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300"
          role="alert"
        >
          {error}
        </p>
      )}
      <button className="button h-12 w-full" type="submit">
        Start Security Scan
        <ArrowRight size={16} />
      </button>
    </form>
  );
}
