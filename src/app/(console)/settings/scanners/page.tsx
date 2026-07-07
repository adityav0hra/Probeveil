import { db } from "@/lib/db";
import { StatusPill } from "@/components/status-pill";

const engineNotes: Record<string, string> = {
  "Adaptive Differential Probes":
    "Compares safe request variants to surface authorization, routing and parameter-handling anomalies.",
  Nuclei:
    "Runs template-based HTTP checks when the nuclei CLI is installed on the worker.",
  Nikto:
    "Runs web-server baseline diagnostics when the nikto CLI is installed on the worker.",
  "OWASP ZAP Baseline":
    "Runs passive DAST baseline checks in maximum mode when zap-baseline.py is installed.",
  "Probeveil Passive":
    "Built-in crawler and response analyzer for DNS, TLS, headers, cookies, CORS, CSP, routes and evidence.",
  Semgrep:
    "Runs local Semgrep rules against downloaded same-scope JavaScript assets when semgrep is installed.",
  SSLyze:
    "Runs TLS and certificate diagnostics when sslyze is installed on the worker.",
  "Probeveil Nikto-style Checks":
    "Built-in fallback checks for common web-server diagnostic, legacy and sensitive path exposures.",
  "Probeveil Technology Checks":
    "Built-in framework-aware review for Next.js, WordPress, Spring/OpenAPI and GraphQL surfaces.",
  "testssl.sh":
    "Runs TLS and certificate diagnostics when testssl.sh is installed on the worker.",
};

export default async function ScannersPage() {
  const tools = await db.scannerTool.findMany({ orderBy: { name: "asc" } });

  return (
    <>
      <p className="eyebrow">System configuration</p>
      <h1 className="mt-2 text-3xl font-semibold">Scanner configuration</h1>
      <p className="muted mt-2">
        Installed engines used by Probeveil during scan execution.
      </p>
      <div className="mt-8 grid gap-4 lg:grid-cols-2">
        {tools.map((tool) => (
          <div className="panel p-5" key={tool.id}>
            <div className="flex justify-between gap-4">
              <div>
                <h2 className="font-semibold">{tool.name}</h2>
                <p className="mt-1 text-xs text-slate-600">
                  {tool.kind} · version {tool.version}
                </p>
              </div>
              <StatusPill value={tool.enabled ? "READY" : "SKIPPED"} />
            </div>
            <p className="mt-4 text-sm leading-6 text-slate-400">
              {engineNotes[tool.name] ?? "Configured scanner engine."}
            </p>
            <p className="mt-4 text-xs leading-5 text-slate-500">
              {Array.isArray(tool.capabilities)
                ? tool.capabilities.join(" · ")
                : "Configured capabilities"}
            </p>
          </div>
        ))}
      </div>
    </>
  );
}
