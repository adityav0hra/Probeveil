import { createHash } from "node:crypto";
import { promises as dns } from "node:dns";
import tls from "node:tls";
import { assertAddressesAllowed } from "@/lib/scope";
import { isSameOriginOrSubdomain } from "@/lib/url";
import { runExternalScanners } from "./external-scanners";
import type { FindingInput, ScanJob } from "./types";

const MAX_BODY = 2 * 1024 * 1024;
const TIMEOUT = 12_000;
const HIGH_VALUE_ROUTE =
  /\/(?:api|admin|internal|graphql|export|download|invite|approve|reject|publish|archive|restore|batch|search|webhook|callback|oauth|settings|billing|users?|accounts?|orders?|submissions?|votes?)(?:\/|$|[?])/i;
const ROUTE_TOKEN =
  /["'`](\/(?:api|admin|internal|graphql|auth|oauth|users?|accounts?|settings|dashboard|export|download|invite|approve|reject|publish|archive|restore|batch|search|webhook|callback|v\d+|_next\/data)[A-Za-z0-9._~!$&'()*+,;=:@%/?#\-[\]]*)["'`]/g;
const FIELD_TOKEN =
  /\b(?:role|isAdmin|admin|ownerId|userId|tenantId|accountId|price|amount|status|state|redirect|callback|returnUrl|next|url|file|path|template|query|filter|sort|limit|offset|token|secret|invite|approve|publish|archive)\b/gi;
const SECRET_VALUE_TOKEN =
  /\b(?:api[_-]?key|secret|token|password|passwd|pwd|private[_-]?key|access[_-]?key|client[_-]?secret|database[_-]?url|jwt|stripe|sendgrid|mailgun|aws[_-]?access|aws[_-]?secret|github[_-]?token)\b\s*[:=]\s*["']?[A-Za-z0-9_./+=:@%$!#-]{8,}/i;
const EXPOSURE_CANDIDATES: Array<{
  path: string;
  rule: string;
  title: string;
  category: string;
  cwe: string;
  severity: FindingInput["severity"];
  confidence?: FindingInput["confidence"];
  impact: string;
  remediation: string;
}> = [
  {
    path: "/.git/config",
    rule: "exposure/git-config",
    title: "Git repository metadata is exposed",
    category: "Sensitive file exposure",
    cwe: "CWE-548",
    severity: "HIGH",
    confidence: "CONFIRMED",
    impact:
      "Public Git metadata can reveal repository origins, branch names and may enable source-code recovery when other .git objects are reachable.",
    remediation:
      "Block access to .git paths at the web server and remove repository metadata from the deployed web root.",
  },
  ...["/.env", "/.env.local", "/.env.production", "/.env.development"].map(
    (path) => ({
      path,
      rule: "exposure/env-file",
      title: "Environment file is exposed",
      category: "Secret exposure",
      cwe: "CWE-200",
      severity: "HIGH" as const,
      confidence: "CONFIRMED" as const,
      impact:
        "Environment files often contain database URLs, API keys, signing secrets, cloud credentials and service tokens.",
      remediation:
        "Remove the file from the public web root, rotate any exposed secrets, and add explicit deny rules for environment files.",
    }),
  ),
  ...[
    "/backup.zip",
    "/backup.tar.gz",
    "/site.zip",
    "/www.zip",
    "/public.zip",
    "/database.sql",
    "/db.sql",
    "/dump.sql",
    "/backup.sql",
  ].map((path) => ({
    path,
    rule: "exposure/backup-artifact",
    title: "Backup or database artifact is publicly reachable",
    category: "Sensitive file exposure",
    cwe: "CWE-530",
    severity: "HIGH" as const,
    confidence: "HIGH" as const,
    impact:
      "Public backups and SQL dumps can expose source code, credentials, customer data or complete database contents.",
    remediation:
      "Move backups outside the web root, require authentication for administrative artifacts, and rotate any secrets exposed inside the artifact.",
  })),
  ...["/phpinfo.php", "/info.php"].map((path) => ({
    path,
    rule: "exposure/phpinfo",
    title: "PHP information page is exposed",
    category: "Information disclosure",
    cwe: "CWE-200",
    severity: "HIGH" as const,
    confidence: "CONFIRMED" as const,
    impact:
      "phpinfo output exposes server configuration, loaded modules, paths and environment variables that can accelerate exploitation.",
    remediation:
      "Remove phpinfo pages from production and restrict diagnostic endpoints to authenticated administrative networks.",
  })),
  ...[
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger-ui.html",
    "/docs",
  ].map((path) => ({
    path,
    rule: "exposure/api-documentation",
    title: "API documentation is publicly reachable",
    category: "Attack surface exposure",
    cwe: "CWE-200",
    severity: "MEDIUM" as const,
    confidence: "HIGH" as const,
    impact:
      "Public API documentation can reveal hidden routes, parameters, schemas, authentication assumptions and administrative workflows.",
    remediation:
      "Restrict internal API documentation or publish only intentionally public API references with sensitive routes removed.",
  })),
  {
    path: "/server-status",
    rule: "exposure/server-status",
    title: "Server status endpoint is exposed",
    category: "Information disclosure",
    cwe: "CWE-200",
    severity: "HIGH",
    confidence: "CONFIRMED",
    impact:
      "Server status pages can expose active requests, paths, client IPs, worker state and backend operational detail.",
    remediation:
      "Disable public server-status access or restrict it to authenticated administrative networks.",
  },
  ...["/actuator/env", "/actuator/heapdump", "/actuator/configprops"].map(
    (path) => ({
      path,
      rule: "exposure/spring-actuator",
      title: "Sensitive Spring Actuator endpoint is exposed",
      category: "Sensitive endpoint exposure",
      cwe: "CWE-200",
      severity: "HIGH" as const,
      confidence: "HIGH" as const,
      impact:
        "Sensitive actuator endpoints can expose environment variables, heap contents, configuration properties and application internals.",
      remediation:
        "Disable sensitive actuator endpoints publicly and require strong authentication for operational endpoints.",
    }),
  ),
  {
    path: "/.DS_Store",
    rule: "exposure/ds-store",
    title: "macOS .DS_Store metadata is exposed",
    category: "Information disclosure",
    cwe: "CWE-548",
    severity: "MEDIUM",
    confidence: "HIGH",
    impact:
      ".DS_Store files can reveal hidden filenames and directory structure that are not linked from the application.",
    remediation:
      "Remove .DS_Store files from the deployment and block dotfile access.",
  },
  {
    path: "/.svn/entries",
    rule: "exposure/svn-entries",
    title: "Subversion metadata is exposed",
    category: "Sensitive file exposure",
    cwe: "CWE-548",
    severity: "HIGH",
    confidence: "HIGH",
    impact:
      "Public version-control metadata can reveal repository layout and may lead to source-code recovery.",
    remediation:
      "Block version-control metadata paths and remove them from the deployed web root.",
  },
  ...["/package-lock.json", "/yarn.lock", "/pnpm-lock.yaml", "/composer.lock"].map(
    (path) => ({
      path,
      rule: "exposure/dependency-lockfile",
      title: "Dependency lockfile is exposed",
      category: "Information disclosure",
      cwe: "CWE-200",
      severity: "MEDIUM" as const,
      confidence: "HIGH" as const,
      impact:
        "Lockfiles reveal exact dependency versions that can be matched against known vulnerabilities.",
      remediation:
        "Do not serve build and dependency metadata from the production web root.",
    }),
  ),
];

type PageArtifact = {
  url: string;
  contentType?: string;
  body: string;
  headers: Record<string, string>;
  status: number;
};
type TechnologyInput = {
  name: string;
  version?: string;
  category?: string;
  evidence?: string;
};
type ParameterInput = {
  endpointUrl: string;
  method: string;
  name: string;
  location: string;
  dataType?: string;
  tested: boolean;
};
type ReviewTask = {
  title: string;
  url: string;
  reason: string;
  priority: FindingInput["severity"];
  variables: string[];
  evidence: string;
};
type ProbeObservation = {
  label: string;
  url: string;
  method: string;
  status?: number;
  contentType?: string;
  location?: string;
  length?: number;
  cache?: string;
  setCookie?: boolean;
  error?: string;
};

export async function runPassive(
  job: ScanJob,
  emit: (event: unknown) => Promise<void>,
  cancelled: () => Promise<boolean>,
) {
  const root = new URL(job.url);
  const findings: FindingInput[] = [];
  const endpoints: Endpoint[] = [];
  const artifacts: PageArtifact[] = [];
  const reviewTasks: ReviewTask[] = [];
  const technologies = new Map<string, TechnologyInput>();
  const parameters = new Map<string, ParameterInput>();
  const seen = new Set<string>();
  const routeCandidates = new Map<string, { url: URL; source: string }>();
  let finalUrl = job.url;

  await stage(emit, "validate", async () => {
    await validateDestination(root);
  });
  await ensureRunning(cancelled);
  let addresses: string[] = [];
  await stage(emit, "dns", async () => {
    const records = await dns.lookup(root.hostname, {
      all: true,
      verbatim: true,
    });
    addresses = [...new Set(records.map((x) => x.address))];
    assertAddressesAllowed(root.hostname, addresses);
    await emit({
      type: "services",
      services: addresses.map((ip) => ({
        host: root.hostname,
        ip,
        port: Number(root.port || (root.protocol === "https:" ? 443 : 80)),
        protocol: root.protocol.slice(0, -1),
      })),
    });
  });
  await ensureRunning(cancelled);
  await stage(emit, "tls", async () => {
    if (root.protocol !== "https:") {
      findings.push(
        finding(
          "Website is not using HTTPS",
          "Transport security",
          "CWE-319",
          "HIGH",
          "CONFIRMED",
          root.toString(),
          "tls/no-https",
          "Traffic can be observed or modified in transit.",
          "Serve the application exclusively over HTTPS and redirect HTTP to HTTPS.",
          "The submitted URL uses HTTP.",
        ),
      );
      return;
    }
    try {
      const certificate = await inspectTls(
        root.hostname,
        Number(root.port || 443),
      );
      await emit({
        type: "services",
        services: [
          {
            host: root.hostname,
            port: Number(root.port || 443),
            protocol: "https",
            tls: certificate,
          },
        ],
      });
      if (
        certificate.validTo &&
        new Date(certificate.validTo).getTime() - Date.now() < 14 * 86400000
      )
        findings.push(
          finding(
            "TLS certificate expires soon",
            "Transport security",
            "CWE-298",
            "MEDIUM",
            "HIGH",
            root.toString(),
            "tls/expiry",
            "An expiring certificate can cause an availability and trust failure.",
            "Renew and automate certificate rotation.",
            JSON.stringify(certificate, null, 2),
          ),
        );
    } catch (error) {
      findings.push(
        finding(
          "TLS certificate validation failed",
          "Transport security",
          "CWE-295",
          "HIGH",
          "CONFIRMED",
          root.toString(),
          "tls/invalid",
          "Clients cannot establish a trustworthy encrypted connection.",
          "Install a valid certificate matching the target hostname and complete certificate chain.",
          String(error),
        ),
      );
    }
  });
  await ensureRunning(cancelled);
  let response!: SafeResponse;
  await stage(emit, "surface", async () => {
    response = await safeFetch(root, root);
    finalUrl = response.url;
    artifacts.push(artifact(response));
    for (const technology of detectTechnologies(response))
      technologies.set(
        `${technology.name}:${technology.version ?? "detected"}`,
        technology,
      );
    for (const candidate of extractRouteCandidates(response.body, response.url))
      routeCandidates.set(candidate.url.toString(), candidate);
    for (const parameter of extractParameters(response))
      parameters.set(parameterKey(parameter), parameter);
    endpoints.push(
      endpoint(
        response.url,
        response.status,
        response.contentType,
        0,
        true,
        "initial-request",
        response.body,
      ),
    );
    if (technologies.size)
      await emit({
        type: "technologies",
        technologies: [...technologies.values()],
      });
  });
  const headers = response.headers;
  await stage(emit, "headers", async () => {
    const checks: Array<[string, string, string, "MEDIUM" | "LOW", string]> = [
      [
        "strict-transport-security",
        "HTTP Strict Transport Security is missing",
        "CWE-319",
        "MEDIUM",
        "Add a long-lived HSTS policy after confirming all subdomains support HTTPS.",
      ],
      [
        "x-content-type-options",
        "MIME sniffing protection is missing",
        "CWE-693",
        "LOW",
        "Set X-Content-Type-Options: nosniff.",
      ],
      [
        "referrer-policy",
        "Referrer Policy is missing",
        "CWE-200",
        "LOW",
        "Set a restrictive Referrer-Policy.",
      ],
      [
        "permissions-policy",
        "Permissions Policy is missing",
        "CWE-693",
        "LOW",
        "Define a least-privilege Permissions-Policy.",
      ],
    ];
    for (const [name, title, cwe, severity, remediation] of checks)
      if (!headers[name])
        findings.push(
          finding(
            title,
            "Security headers",
            cwe,
            severity,
            "HIGH",
            finalUrl,
            `headers/${name}`,
            "Missing browser security controls increase the impact of related vulnerabilities.",
            remediation,
            renderHeaders(headers),
          ),
        );
    if (
      !headers["x-frame-options"] &&
      !headers["content-security-policy"]
        ?.toLowerCase()
        .includes("frame-ancestors")
    )
      findings.push(
        finding(
          "Clickjacking protection is missing",
          "Browser security",
          "CWE-1021",
          "MEDIUM",
          "HIGH",
          finalUrl,
          "headers/clickjacking",
          "The page may be framed by an attacker to trick users into unintended actions.",
          "Set CSP frame-ancestors and retain X-Frame-Options for legacy clients.",
          renderHeaders(headers),
        ),
      );
    if (headers["server"] || headers["x-powered-by"])
      findings.push(
        finding(
          "Server technology is disclosed",
          "Information disclosure",
          "CWE-200",
          "LOW",
          "CONFIRMED",
          finalUrl,
          "headers/technology",
          "Version and platform hints can improve attacker reconnaissance.",
          "Remove unnecessary Server and X-Powered-By response headers.",
          renderHeaders(headers),
        ),
      );
  });
  await stage(emit, "cookies", async () => {
    for (const cookie of response.cookies) {
      const name = cookie.split("=", 1)[0];
      if (!/;\s*secure(?:;|$)/i.test(cookie) && root.protocol === "https:")
        findings.push(
          finding(
            `Cookie ${name} is missing Secure`,
            "Session security",
            "CWE-614",
            "MEDIUM",
            "CONFIRMED",
            finalUrl,
            `cookie/${name}/secure`,
            "The cookie may be sent over an unencrypted connection.",
            "Add the Secure attribute to every sensitive cookie.",
            cookie,
          ),
        );
      if (!/;\s*httponly(?:;|$)/i.test(cookie))
        findings.push(
          finding(
            `Cookie ${name} is missing HttpOnly`,
            "Session security",
            "CWE-1004",
            "LOW",
            "CONFIRMED",
            finalUrl,
            `cookie/${name}/httponly`,
            "Client-side script can read the cookie if script execution is compromised.",
            "Add HttpOnly to cookies that do not require JavaScript access.",
            cookie,
          ),
        );
      if (!/;\s*samesite=/i.test(cookie))
        findings.push(
          finding(
            `Cookie ${name} is missing SameSite`,
            "Session security",
            "CWE-1275",
            "LOW",
            "CONFIRMED",
            finalUrl,
            `cookie/${name}/samesite`,
            "Cross-site requests may include the cookie.",
            "Set SameSite=Lax or Strict unless a documented cross-site flow requires None.",
            cookie,
          ),
        );
    }
  });
  await stage(emit, "csp", async () => {
    const csp = headers["content-security-policy"];
    if (!csp)
      findings.push(
        finding(
          "Content Security Policy is missing",
          "Browser security",
          "CWE-693",
          "MEDIUM",
          "CONFIRMED",
          finalUrl,
          "csp/missing",
          "The browser has no policy limiting script, frame and resource origins.",
          "Deploy a nonce- or hash-based CSP with restrictive default-src, object-src, base-uri and frame-ancestors directives.",
          renderHeaders(headers),
        ),
      );
    else if (/unsafe-inline|unsafe-eval|default-src\s+\*/i.test(csp))
      findings.push(
        finding(
          "Content Security Policy contains unsafe directives",
          "Browser security",
          "CWE-693",
          "MEDIUM",
          "CONFIRMED",
          finalUrl,
          "csp/unsafe",
          "Unsafe CSP directives significantly weaken script-injection defenses.",
          "Remove unsafe-inline, unsafe-eval and wildcard sources; use nonces or hashes.",
          csp,
        ),
      );
  });
  await stage(emit, "cors", async () => {
    const cors = await safeFetch(new URL(finalUrl), new URL(finalUrl), {
      headers: { Origin: "https://probeveil.invalid" },
    });
    const allowOrigin = cors.headers["access-control-allow-origin"];
    if (
      allowOrigin === "https://probeveil.invalid" &&
      cors.headers["access-control-allow-credentials"]?.toLowerCase() === "true"
    )
      findings.push(
        finding(
          "CORS reflects arbitrary origins with credentials",
          "Cross-origin security",
          "CWE-942",
          "HIGH",
          "CONFIRMED",
          finalUrl,
          "cors/reflection",
          "An attacker-controlled origin may read authenticated cross-origin responses.",
          "Use an exact allowlist and never reflect untrusted Origin values when credentials are allowed.",
          renderHeaders(cors.headers),
        ),
      );
    else if (allowOrigin === "*")
      findings.push(
        finding(
          "CORS allows every origin",
          "Cross-origin security",
          "CWE-942",
          "LOW",
          "CONFIRMED",
          finalUrl,
          "cors/wildcard",
          "Any origin can read non-credentialed responses, which may expose public-but-sensitive data.",
          "Restrict Access-Control-Allow-Origin to known application origins.",
          renderHeaders(cors.headers),
        ),
      );
  });
  await ensureRunning(cancelled);
  await stage(emit, "crawl", async () => {
    const limit = job.mode === "QUICK" ? 25 : job.mode === "FULL" ? 100 : 250;
    const queue: Array<{ url: URL; depth: number }> = [
      { url: new URL(finalUrl), depth: 0 },
      new URL("/robots.txt", finalUrl),
      new URL("/sitemap.xml", finalUrl),
    ].map((url, i) => ({
      url: url instanceof URL ? url : url.url,
      depth: i === 0 ? 0 : 1,
    }));
    while (queue.length && seen.size < limit) {
      await ensureRunning(cancelled);
      const current = queue.shift()!;
      const key = canonical(current.url);
      if (seen.has(key)) continue;
      seen.add(key);
      const isExternal = !isSameOriginOrSubdomain(current.url, root);
      try {
        const page =
          !isExternal &&
          current.depth === 0 &&
          current.url.toString() === finalUrl
            ? response
            : await safeFetch(current.url, root, { allowExternal: isExternal });
        artifacts.push(artifact(page));
        for (const technology of detectTechnologies(page))
          technologies.set(
            `${technology.name}:${technology.version ?? "detected"}`,
            technology,
          );
        if (!isExternal)
          for (const candidate of extractRouteCandidates(page.body, page.url))
            routeCandidates.set(candidate.url.toString(), candidate);
        for (const parameter of extractParameters(page))
          parameters.set(parameterKey(parameter), parameter);
        endpoints.push({
          ...endpoint(
            page.url,
            page.status,
            page.contentType,
            current.depth,
            true,
            isExternal ? "external-link" : "http-crawler",
            page.body,
          ),
          external: isExternal,
        });
        if (!isExternal && page.contentType?.includes("text/html"))
          for (const link of extractLinks(page.body, page.url))
            if (!seen.has(canonical(link)))
              queue.push({ url: link, depth: current.depth + 1 });
        if (/directory listing|index of \/</i.test(page.body.slice(0, 5000)))
          findings.push(
            finding(
              "Directory listing is enabled",
              "Information disclosure",
              "CWE-548",
              "MEDIUM",
              "HIGH",
              page.url,
              "content/directory-listing",
              "Directory contents and potentially sensitive files are exposed.",
              "Disable directory indexes and allowlist intentionally public files.",
              page.body.slice(0, 5000),
            ),
          );
        if (
          /\b(stack trace|traceback \(most recent call|exception in thread|sqlstate\[)/i.test(
            page.body,
          )
        )
          findings.push(
            finding(
              "Verbose error details are exposed",
              "Information disclosure",
              "CWE-209",
              "MEDIUM",
              "HIGH",
              page.url,
              "content/verbose-error",
              "Internal implementation details may reveal code paths, queries or secrets.",
              "Return generic errors to clients and retain detail only in protected server logs.",
              page.body.slice(0, 10000),
            ),
          );
      } catch (error) {
        endpoints.push({
          ...endpoint(
            current.url.toString(),
            undefined,
            undefined,
            current.depth,
            false,
            isExternal ? "external-link" : "http-crawler",
          ),
          external: isExternal,
          title: String(error),
        });
      }
    }
    if (technologies.size)
      await emit({
        type: "technologies",
        technologies: [...technologies.values()],
      });
  });
  await stage(emit, "exposure-probes", async () => {
    const exposureCandidates = exposureProbeCandidates(new URL(finalUrl));
    const limit = job.mode === "QUICK" ? 20 : job.mode === "FULL" ? 60 : 120;
    for (const candidate of exposureCandidates.slice(0, limit)) {
      await ensureRunning(cancelled);
      try {
        const page = await safeFetch(candidate.url, root, {
          headers: { "x-probeveil-discovery": candidate.source },
        });
        endpoints.push(
          endpoint(
            page.url,
            page.status,
            page.contentType,
            1,
            true,
            candidate.source,
            page.body,
          ),
        );
        artifacts.push(artifact(page));
        for (const technology of detectTechnologies(page))
          technologies.set(
            `${technology.name}:${technology.version ?? "detected"}`,
            technology,
          );
        for (const parameter of extractParameters(page))
          parameters.set(parameterKey(parameter), parameter);
        const detected = exposureFindingFor(candidate.probe, page);
        if (detected) findings.push(detected);
        for (const routeCandidate of extractRouteCandidates(page.body, page.url))
          routeCandidates.set(routeCandidate.url.toString(), routeCandidate);
      } catch (error) {
        endpoints.push({
          ...endpoint(
            candidate.url.toString(),
            undefined,
            undefined,
            1,
            false,
            candidate.source,
          ),
          title: error instanceof Error ? error.message : String(error),
        });
      }
    }
  });
  await stage(emit, "hidden-surface", async () => {
    const limit = job.mode === "QUICK" ? 20 : job.mode === "FULL" ? 60 : 140;
    for (const candidate of generateFrameworkCandidates(new URL(finalUrl), [
      ...technologies.values(),
    ]))
      routeCandidates.set(candidate.url.toString(), candidate);
    for (const candidate of [...routeCandidates.values()].slice(0, limit)) {
      await ensureRunning(cancelled);
      if (!isSameOriginOrSubdomain(candidate.url, root)) continue;
      try {
        const page = await safeFetch(candidate.url, root, {
          headers: { "x-probeveil-discovery": candidate.source },
        });
        const discovered = endpoint(
          page.url,
          page.status,
          page.contentType,
          1,
          true,
          `hidden-surface:${candidate.source}`,
          page.body,
        );
        endpoints.push(discovered);
        artifacts.push(artifact(page));
        for (const parameter of extractParameters(page))
          parameters.set(parameterKey(parameter), parameter);
        if (candidate.url.pathname.toLowerCase().includes("graphql")) {
          const graphQlObservations = await graphqlProbe(candidate.url, root);
          reviewTasks.push({
            title: `Review GraphQL surface ${candidate.url.pathname}`,
            url: candidate.url.toString(),
            reason:
              "A GraphQL endpoint candidate responded to safe probing. GraphQL risk often appears through resolver-level authorization, nested traversal, batching, alias duplication, variable coercion and mutation replay rather than basic introspection alone.",
            priority: "MEDIUM",
            variables: suspiciousVariables(
              graphQlObservations.map(renderObservation).join("\n"),
            ),
            evidence: graphQlObservations.map(renderObservation).join("\n\n"),
          });
        }
        if (
          page.status < 400 ||
          HIGH_VALUE_ROUTE.test(candidate.url.pathname)
        ) {
          const variables = suspiciousVariables(
            `${candidate.url.pathname}\n${page.body.slice(0, 4000)}`,
          );
          reviewTasks.push({
            title: `Review hidden surface ${candidate.url.pathname}`,
            url: candidate.url.toString(),
            reason: `${candidate.source} exposed a high-value route candidate with HTTP ${page.status}. Hidden or undocumented routes often carry weaker authorization, export, search, batch or workflow controls than linked UI routes.`,
            priority: HIGH_VALUE_ROUTE.test(candidate.url.pathname)
              ? "MEDIUM"
              : "LOW",
            variables,
            evidence: renderObservation({
              label: candidate.source,
              url: page.url,
              method: "GET",
              status: page.status,
              contentType: page.contentType,
              location: page.headers.location,
              length: page.body.length,
              cache: page.headers["cache-control"],
              setCookie: page.cookies.length > 0,
            }),
          });
        }
      } catch (error) {
        endpoints.push({
          ...endpoint(
            candidate.url.toString(),
            undefined,
            undefined,
            1,
            false,
            `hidden-surface:${candidate.source}`,
          ),
          title: error instanceof Error ? error.message : String(error),
        });
      }
    }
  });
  await stage(emit, "adaptive-differential", async () => {
    const targets = dedupeEndpoints(endpoints)
      .filter(
        (item) =>
          item.tested &&
          !item.external &&
          item.statusCode &&
          item.statusCode < 500,
      )
      .filter(
        (item) =>
          HIGH_VALUE_ROUTE.test(new URL(item.url).pathname) || item.depth <= 1,
      )
      .slice(0, job.mode === "QUICK" ? 8 : job.mode === "FULL" ? 20 : 50);
    for (const target of targets) {
      await ensureRunning(cancelled);
      const observations = await differentialProbe(new URL(target.url), root);
      const interesting = analyseDifferential(observations);
      if (!interesting) continue;
      reviewTasks.push({
        title: `Review inconsistent request handling for ${new URL(target.url).pathname}`,
        url: target.url,
        reason: interesting,
        priority: HIGH_VALUE_ROUTE.test(new URL(target.url).pathname)
          ? "MEDIUM"
          : "LOW",
        variables: suspiciousVariables(
          `${target.url}\n${observations.map(renderObservation).join("\n")}`,
        ),
        evidence: observations.map(renderObservation).join("\n\n"),
      });
    }
  });
  await stage(emit, "manual-review", async () => {
    for (const task of parameterReviewTasks([...parameters.values()]))
      reviewTasks.push(task);
    const tasks = dedupeReviewTasks(reviewTasks).slice(
      0,
      job.mode === "QUICK" ? 8 : job.mode === "FULL" ? 20 : 50,
    );
    for (const task of tasks)
      findings.push(manualReviewFinding(task, root.toString()));
  });
  await stage(emit, "external-scanners", async () => {
    findings.push(
      ...(await runExternalScanners({
        cancelled,
        endpoints: dedupeEndpoints(endpoints),
        job,
      })),
    );
  });
  await stage(emit, "passive", async () => {
    for (let index = 0; index < findings.length; index += 100) {
      await emit({
        type: "findings",
        findings: findings.slice(index, index + 100),
      });
    }
  });
  await stage(emit, "correlate", async () => {
    await emit({ type: "endpoints", endpoints: dedupeEndpoints(endpoints) });
    if (parameters.size)
      await emit({
        type: "parameters",
        parameters: [...parameters.values()].slice(0, 1000),
      });
  });
  await stage(emit, "score", async () => undefined);
  await stage(emit, "report", async () => undefined);
  await emit({ type: "complete", finalUrl });
}

type Endpoint = {
  url: string;
  method: string;
  statusCode?: number;
  contentType?: string;
  title?: string;
  depth: number;
  tested: boolean;
  external: boolean;
  discoveredBy: string;
};
type SafeResponse = {
  url: string;
  status: number;
  headers: Record<string, string>;
  cookies: string[];
  body: string;
  contentType?: string;
};

function artifact(response: SafeResponse): PageArtifact {
  return {
    url: response.url,
    contentType: response.contentType,
    body: response.body,
    headers: response.headers,
    status: response.status,
  };
}

function detectTechnologies(response: SafeResponse): TechnologyInput[] {
  const body = response.body.slice(0, 250_000);
  const headers = renderHeaders(response.headers).toLowerCase();
  const found: TechnologyInput[] = [];
  if (body.includes("/_next/") || body.includes("__NEXT_DATA__"))
    found.push({
      name: "Next.js",
      category: "Framework",
      evidence: "Next.js asset or hydration marker observed",
    });
  if (
    body.includes("data-reactroot") ||
    body.includes("__REACT_DEVTOOLS_GLOBAL_HOOK__") ||
    /react(?:-dom)?[.@-]\d/i.test(body)
  )
    found.push({
      name: "React",
      category: "Frontend framework",
      evidence: "React hydration or bundle marker observed",
    });
  if (body.includes("ng-version") || body.includes("_ngcontent-"))
    found.push({
      name: "Angular",
      category: "Frontend framework",
      evidence: "Angular DOM marker observed",
    });
  if (body.includes("data-v-") || body.includes("__VUE__"))
    found.push({
      name: "Vue",
      category: "Frontend framework",
      evidence: "Vue DOM or runtime marker observed",
    });
  if (body.includes("__svelte") || body.includes("svelte-"))
    found.push({
      name: "Svelte",
      category: "Frontend framework",
      evidence: "Svelte DOM or runtime marker observed",
    });
  if (headers.includes("x-powered-by: express"))
    found.push({
      name: "Express",
      category: "Server framework",
      evidence: "X-Powered-By header",
    });
  if (headers.includes("x-powered-by: next.js"))
    found.push({
      name: "Next.js",
      category: "Framework",
      evidence: "X-Powered-By header",
    });
  if (
    headers.includes("x-generator: wordpress") ||
    body.includes("wp-content/")
  )
    found.push({
      name: "WordPress",
      category: "CMS",
      evidence: "WordPress asset or generator marker observed",
    });
  if (body.includes("/graphql") || body.includes("GraphQL"))
    found.push({
      name: "GraphQL",
      category: "API",
      evidence: "GraphQL route or text marker observed",
    });
  return [
    ...new Map(
      found.map((item) => [`${item.name}:${item.category}`, item]),
    ).values(),
  ];
}

function extractRouteCandidates(content: string, base: string) {
  const candidates: Array<{ url: URL; source: string }> = [];
  for (const link of extractLinks(content, base))
    if (
      HIGH_VALUE_ROUTE.test(link.pathname) ||
      link.pathname.includes("/_next/")
    )
      candidates.push({ url: link, source: "linked-resource" });
  for (const match of content.matchAll(ROUTE_TOKEN)) {
    try {
      const raw = match[1].replaceAll("\\/", "/");
      if (raw.includes("${") || raw.includes("[object")) continue;
      const url = new URL(raw, base);
      url.hash = "";
      candidates.push({ url, source: "bundle-route-token" });
    } catch {}
  }
  return dedupeCandidates(candidates);
}

function extractParameters(response: SafeResponse): ParameterInput[] {
  const parameters: ParameterInput[] = [];
  const url = new URL(response.url);
  for (const name of url.searchParams.keys())
    parameters.push({
      endpointUrl: stripSearch(url).toString(),
      method: "GET",
      name,
      location: "query",
      dataType: inferDataType(name),
      tested: false,
    });
  for (const form of extractForms(response.body, response.url)) {
    for (const field of form.fields)
      parameters.push({
        endpointUrl: form.action,
        method: form.method,
        name: field.name,
        location: field.location,
        dataType: field.type || inferDataType(field.name),
        tested: false,
      });
  }
  for (const name of suspiciousVariables(response.body).slice(0, 30))
    parameters.push({
      endpointUrl: stripSearch(url).toString(),
      method: "UNKNOWN",
      name,
      location: "body-or-script",
      dataType: inferDataType(name),
      tested: false,
    });
  return [
    ...new Map(
      parameters.map((parameter) => [parameterKey(parameter), parameter]),
    ).values(),
  ];
}

function extractForms(html: string, base: string) {
  const forms: Array<{
    action: string;
    method: string;
    fields: Array<{ name: string; type?: string; location: string }>;
  }> = [];
  for (const formMatch of html.matchAll(
    /<form\b([^>]*)>([\s\S]*?)<\/form>/gi,
  )) {
    const attrs = formMatch[1];
    const body = formMatch[2];
    const action = attr(attrs, "action") || base;
    const method = (attr(attrs, "method") || "GET").toUpperCase();
    const fields: Array<{ name: string; type?: string; location: string }> = [];
    for (const input of body.matchAll(/<(input|select|textarea)\b([^>]*)>/gi)) {
      const tag = input[1].toLowerCase();
      const inputAttrs = input[2];
      const name = attr(inputAttrs, "name");
      if (!name) continue;
      fields.push({
        name,
        type: attr(inputAttrs, "type") || tag,
        location: method === "GET" ? "query" : "form",
      });
    }
    if (fields.length)
      forms.push({ action: new URL(action, base).toString(), method, fields });
  }
  return forms;
}

function attr(input: string, name: string) {
  const match = input.match(
    new RegExp(`${name}\\s*=\\s*["']([^"']+)["']`, "i"),
  );
  return match?.[1];
}

function parameterReviewTasks(parameters: ParameterInput[]): ReviewTask[] {
  return parameters
    .filter((parameter) => isSensitiveParameter(parameter.name))
    .slice(0, 30)
    .map((parameter) => ({
      title: `Review sensitive parameter ${parameter.name}`,
      url: parameter.endpointUrl,
      reason: `${parameter.location} parameter "${parameter.name}" looks security-sensitive. Hardened applications often leave residual issues in property-level authorization, overposting, redirect handling, search filters, export controls, workflow state or object ownership even when generic payload scans are clean.`,
      priority:
        /role|admin|owner|tenant|price|amount|status|state|token|secret/i.test(
          parameter.name,
        )
          ? "MEDIUM"
          : "LOW",
      variables: [parameter.name],
      evidence: [
        `endpoint=${parameter.endpointUrl}`,
        `method=${parameter.method}`,
        `location=${parameter.location}`,
        `inferred_type=${parameter.dataType ?? "unknown"}`,
        "Recommended comparisons: normal value vs another user's object identifier, omitted value vs duplicate value, JSON vs form body, browser request vs raw replay, single request vs repeated request.",
      ].join("\n"),
    }));
}

function isSensitiveParameter(name: string) {
  return /\b(?:role|isAdmin|admin|ownerId|userId|tenantId|accountId|price|amount|status|state|redirect|callback|returnUrl|next|url|file|path|template|query|filter|sort|limit|offset|token|secret|invite|approve|publish|archive)\b/i.test(
    name,
  );
}

function inferDataType(name: string) {
  if (/^(is|has|can)[A-Z_]|admin|enabled|active|verified/i.test(name))
    return "boolean-like";
  if (/id$|Id$|_id$|uuid|tenant|owner|user|account/i.test(name))
    return "identifier-like";
  if (
    /price|amount|total|count|limit|offset|page|size|quantity|score|vote/i.test(
      name,
    )
  )
    return "numeric-like";
  if (/url|uri|redirect|callback|return|next|path|file|template/i.test(name))
    return "url-or-path-like";
  if (/token|secret|key|code|otp|nonce|state/i.test(name)) return "token-like";
  return "string-like";
}

function parameterKey(parameter: ParameterInput) {
  return `${parameter.method}:${parameter.endpointUrl}:${parameter.location}:${parameter.name}`;
}

function generateFrameworkCandidates(
  base: URL,
  technologies: TechnologyInput[],
) {
  const names = new Set(technologies.map((technology) => technology.name));
  const paths = new Set<string>([
    "/api",
    "/api/health",
    "/api/status",
    "/api/search",
    "/api/export",
    "/api/admin",
    "/graphql",
    "/admin",
    "/internal",
    "/download",
    "/export",
    "/search",
    "/.well-known/security.txt",
    "/openapi.json",
    "/swagger.json",
  ]);
  if (names.has("Next.js")) {
    [
      "/_next/static/",
      "/_next/data/",
      "/api/auth/session",
      "/api/auth/csrf",
      "/api/auth/providers",
      "/sitemap.xml",
      "/robots.txt",
    ].forEach((path) => paths.add(path));
  }
  if (names.has("WordPress")) {
    ["/wp-json/", "/wp-admin/", "/xmlrpc.php", "/wp-content/debug.log"].forEach(
      (path) => paths.add(path),
    );
  }
  if (names.has("GraphQL")) {
    ["/graphql", "/api/graphql", "/v1/graphql"].forEach((path) =>
      paths.add(path),
    );
  }
  return [...paths].map((path) => ({
    url: new URL(path, base),
    source: "framework-candidate",
  }));
}

function exposureProbeCandidates(base: URL) {
  return [
    ...new Map(
      EXPOSURE_CANDIDATES.map((probe) => {
        const url = new URL(probe.path, base);
        return [
          canonical(url),
          {
            probe,
            source: `exposure-probe:${probe.rule}`,
            url,
          },
        ];
      }),
    ).values(),
  ];
}

function exposureFindingFor(
  probe: (typeof EXPOSURE_CANDIDATES)[number],
  response: SafeResponse,
) {
  if (response.status >= 400) return undefined;
  const evidence = response.body.slice(0, 12000);
  const contentType = response.contentType?.toLowerCase() ?? "";
  const body = response.body;
  const fallback = looksLikeHtmlFallback(response, probe.path);
  let matched = false;
  switch (probe.rule) {
    case "exposure/git-config":
      matched =
        /\[core\]/i.test(body) &&
        /repositoryformatversion|bare\s*=|logallrefupdates/i.test(body);
      break;
    case "exposure/env-file":
      matched =
        !fallback &&
        (/^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*.{4,}$/m.test(body) ||
          SECRET_VALUE_TOKEN.test(body));
      break;
    case "exposure/backup-artifact":
      matched =
        !fallback &&
        (/application\/(?:zip|gzip|x-gzip|octet-stream)|sql/i.test(
          contentType,
        ) ||
          body.startsWith("PK") ||
          /\b(?:CREATE TABLE|INSERT INTO|mysqldump|PostgreSQL database dump)\b/i.test(
            body,
          ));
      break;
    case "exposure/phpinfo":
      matched = /phpinfo\(\)|PHP Version|<title>phpinfo\(\)<\/title>/i.test(
        body,
      );
      break;
    case "exposure/api-documentation":
      matched =
        /"openapi"\s*:|"swagger"\s*:|"paths"\s*:|Swagger UI|api-docs|redoc/i.test(
          body,
        );
      break;
    case "exposure/server-status":
      matched =
        /Apache Server Status|Server Version|Current Time|Scoreboard|Srv\s+PID\s+Acc/i.test(
          body,
        );
      break;
    case "exposure/spring-actuator":
      matched =
        !fallback &&
        /propertySources|activeProfiles|systemProperties|management\.endpoints|heapdump|spring\./i.test(
          body,
        );
      break;
    case "exposure/ds-store":
      matched = !fallback && (body.includes("Bud1") || body.length > 100);
      break;
    case "exposure/svn-entries":
      matched =
        !fallback &&
        /committed-rev|committed-date|has-props|svn:this_dir|^\s*dir\s*$/im.test(
          body,
        );
      break;
    case "exposure/dependency-lockfile":
      matched =
        !fallback &&
        /"lockfileVersion"\s*:|^# yarn lockfile|^lockfileVersion:|content-hash|packages:/im.test(
          body,
        );
      break;
  }
  if (!matched && !fallback && SECRET_VALUE_TOKEN.test(body)) {
    return finding(
      "Secret-like values are exposed in a public response",
      "Secret exposure",
      "CWE-200",
      "HIGH",
      "HIGH",
      response.url,
      "exposure/secret-like-value",
      "The response contains key, token, password or secret-shaped values that may enable unauthorized access if valid.",
      "Remove the public file or endpoint, rotate any exposed credentials, and add deny rules for secret-bearing files.",
      evidence,
    );
  }
  if (!matched) return undefined;
  const severity = escalateExposureSeverity(probe, body, contentType);
  return finding(
    probe.title,
    probe.category,
    probe.cwe,
    severity,
    probe.confidence ?? "HIGH",
    response.url,
    probe.rule,
    probe.impact,
    probe.remediation,
    evidence,
  );
}

function looksLikeHtmlFallback(response: SafeResponse, requestedPath: string) {
  const body = response.body.slice(0, 30000);
  if (!response.contentType?.toLowerCase().includes("text/html")) return false;
  if (!/<html[\s>]/i.test(body)) return false;
  if (/not found|404|page could not be found|no route matches/i.test(body))
    return true;
  if (
    requestedPath.startsWith("/.") ||
    /\.(?:zip|gz|sql|json|lock|yaml|yml)$/i.test(requestedPath)
  )
    return true;
  return false;
}

function escalateExposureSeverity(
  probe: (typeof EXPOSURE_CANDIDATES)[number],
  body: string,
  contentType: string,
): FindingInput["severity"] {
  if (SECRET_VALUE_TOKEN.test(body)) return "CRITICAL";
  if (
    probe.rule === "exposure/backup-artifact" &&
    (/sql/i.test(contentType) ||
      /\b(?:CREATE TABLE|INSERT INTO|database dump)\b/i.test(body))
  )
    return "CRITICAL";
  return probe.severity;
}

async function differentialProbe(
  url: URL,
  root: URL,
): Promise<ProbeObservation[]> {
  const variants: Array<{ label: string; url: URL; init?: RequestInit }> = [
    { label: "baseline-get", url },
    { label: "head", url, init: { method: "HEAD" } },
    { label: "options", url, init: { method: "OPTIONS" } },
    {
      label: "json-accept",
      url,
      init: { headers: { accept: "application/json" } },
    },
    {
      label: "proxy-headers",
      url,
      init: {
        headers: {
          "x-forwarded-host": "probeveil.invalid",
          "x-forwarded-proto": "https",
          "x-original-url": url.pathname,
        },
      },
    },
    {
      label: "cache-buster",
      url: withParam(url, "__probeveil_probe", "1"),
      init: { headers: { "cache-control": "no-cache" } },
    },
    { label: "case-variant", url: caseVariant(url) },
    { label: "dot-segment", url: dotSegmentVariant(url) },
    ...parameterVariants(url),
  ];
  const observations: ProbeObservation[] = [];
  for (const variant of variants) {
    try {
      const response = await safeFetch(variant.url, root, variant.init ?? {});
      observations.push({
        label: variant.label,
        url: variant.url.toString(),
        method: variant.init?.method?.toString() ?? "GET",
        status: response.status,
        contentType: response.contentType,
        location: response.headers.location,
        length: response.body.length,
        cache: response.headers["cache-control"],
        setCookie: response.cookies.length > 0,
      });
    } catch (error) {
      observations.push({
        label: variant.label,
        url: variant.url.toString(),
        method: variant.init?.method?.toString() ?? "GET",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return observations;
}

function analyseDifferential(observations: ProbeObservation[]) {
  const baseline = observations.find((item) => item.label === "baseline-get");
  if (!baseline?.status) return undefined;
  const statusDrift = observations.filter(
    (item) => item.status && Math.abs(item.status - baseline.status!) >= 100,
  );
  const authBypassShape = observations.find((item) =>
    baseline.status === 401 || baseline.status === 403
      ? item.status && item.status < 400
      : false,
  );
  const proxyInfluence = observations.find(
    (item) =>
      item.label === "proxy-headers" &&
      (item.location || item.status !== baseline.status),
  );
  const cacheShift = observations.find(
    (item) => item.cache && baseline.cache && item.cache !== baseline.cache,
  );
  if (authBypassShape)
    return `${authBypassShape.label} returned HTTP ${authBypassShape.status} while the baseline returned HTTP ${baseline.status}. Compare authentication and authorization checks across request variants before treating this route as safe.`;
  if (proxyInfluence)
    return "Proxy-oriented headers changed status or redirect behaviour. Review host, scheme and original-url trust boundaries for cache poisoning, redirect and route-confusion risk.";
  if (statusDrift.length >= 3)
    return "Multiple semantically equivalent request variants returned different status classes. Review method handling, content negotiation, path normalization and fallback routing for inconsistent security controls.";
  if (cacheShift)
    return "Cache directives changed between request variants. Review whether authenticated, private or user-specific responses share cache keys with public variants.";
  return undefined;
}

function manualReviewFinding(task: ReviewTask, rootUrl: string): FindingInput {
  return {
    title: task.title,
    description: [
      task.reason,
      "This is a targeted manual-review task, not a confirmed vulnerability. It was generated because automated discovery found a route, variable or behavioural difference that commonly precedes access-control, business-logic, cache, parser or workflow issues in hardened applications.",
    ].join(" "),
    category: "Manual review",
    cwe: "CWE-284",
    severity: task.priority,
    confidence: "MANUAL_REVIEW",
    affectedUrl: task.url,
    httpMethod: "GET",
    scannerRuleId: "manual/adversarial-review",
    fingerprint: createHash("sha256")
      .update(`manual/adversarial-review|${task.url}|${task.reason}`)
      .digest("hex"),
    impact:
      "Potential impact depends on the route's real workflow and authorization model. If the route controls ownership, exports, approvals, invitations, search, batch updates or administrative state, a small inconsistency can become a high-impact finding.",
    remediation:
      "Have an admin or tester compare anonymous/authenticated sessions, owner/non-owner resources, alternate methods, skipped workflow steps, content types and replay behaviour. Confirm the server enforces authorization and state transitions independently of the client UI.",
    reproductionSteps: [
      `Start from the submitted target ${rootUrl}.`,
      `Open or replay ${task.url}.`,
      "Compare the same operation as anonymous, authenticated owner, authenticated non-owner and any discoverable elevated role.",
      "Mutate the suspicious variables or route components listed in this task.",
      "Verify expected secure behaviour: no cross-user data, no unauthorized state change, no private export, no weaker batch/search/download path and no cache leakage.",
    ],
    references: [
      "https://owasp.org/www-project-web-security-testing-guide/",
      "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    ],
    evidence: [
      {
        type: "ADVERSARIAL_REVIEW_TASK",
        title: "Why this area needs manual review",
        content: [
          task.evidence,
          "",
          `Suspicious variables: ${task.variables.length ? task.variables.join(", ") : "none directly observed"}`,
          "Compare: anonymous vs authenticated, owner vs non-owner, browser vs raw request, normal sequence vs skipped sequence, single request vs repeated/concurrent request.",
        ].join("\n"),
      },
    ],
  };
}

function suspiciousVariables(input: string) {
  return [
    ...new Set([...input.matchAll(FIELD_TOKEN)].map((match) => match[0])),
  ].slice(0, 20);
}

function dedupeCandidates(candidates: Array<{ url: URL; source: string }>) {
  return [
    ...new Map(
      candidates.map((candidate) => [canonical(candidate.url), candidate]),
    ).values(),
  ];
}

function dedupeReviewTasks(tasks: ReviewTask[]) {
  return [
    ...new Map(
      tasks.map((task) => [`${task.title}|${task.url}`, task]),
    ).values(),
  ];
}

function renderObservation(item: ProbeObservation) {
  return [
    `${item.label} ${item.method} ${item.url}`,
    `status=${item.status ?? "error"} content-type=${item.contentType ?? "unknown"} length=${item.length ?? "unknown"}`,
    item.location ? `location=${item.location}` : undefined,
    item.cache ? `cache-control=${item.cache}` : undefined,
    item.setCookie ? "set-cookie=true" : undefined,
    item.error ? `error=${item.error}` : undefined,
  ]
    .filter(Boolean)
    .join("\n");
}

function withParam(url: URL, key: string, value: string) {
  const clone = new URL(url);
  clone.searchParams.set(key, value);
  return clone;
}

function caseVariant(url: URL) {
  const clone = new URL(url);
  clone.pathname = clone.pathname
    .split("/")
    .map((part, index) => (index % 2 ? part.toUpperCase() : part))
    .join("/");
  return clone;
}

function dotSegmentVariant(url: URL) {
  const clone = new URL(url);
  const path = clone.pathname.startsWith("/")
    ? clone.pathname.slice(1)
    : clone.pathname;
  clone.pathname = `/./${path}`;
  return clone;
}

function parameterVariants(
  url: URL,
): Array<{ label: string; url: URL; init?: RequestInit }> {
  const entries = [...url.searchParams.entries()].slice(0, 3);
  if (!entries.length) return [];
  const variants: Array<{ label: string; url: URL; init?: RequestInit }> = [];
  for (const [key, value] of entries) {
    const duplicate = new URL(url);
    duplicate.searchParams.append(key, value);
    variants.push({ label: `duplicate-param:${key}`, url: duplicate });
    const arrayShape = new URL(url);
    arrayShape.searchParams.set(`${key}[]`, value);
    variants.push({ label: `array-param:${key}`, url: arrayShape });
    if (inferDataType(key) === "numeric-like") {
      const typeShift = new URL(url);
      typeShift.searchParams.set(key, "0");
      variants.push({ label: `numeric-boundary:${key}`, url: typeShift });
    }
  }
  return variants.slice(0, 6);
}

async function graphqlProbe(url: URL, root: URL): Promise<ProbeObservation[]> {
  const probes: Array<{ label: string; body: string }> = [
    {
      label: "graphql-typename",
      body: JSON.stringify({ query: "query ProbeveilTypeName { __typename }" }),
    },
    {
      label: "graphql-introspection-type",
      body: JSON.stringify({
        query:
          "query ProbeveilSchemaProbe { __schema { queryType { name } mutationType { name } } }",
      }),
    },
  ];
  const observations: ProbeObservation[] = [];
  for (const probe of probes) {
    try {
      const response = await safeFetch(url, root, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: probe.body,
      });
      observations.push({
        label: probe.label,
        url: url.toString(),
        method: "POST",
        status: response.status,
        contentType: response.contentType,
        length: response.body.length,
        cache: response.headers["cache-control"],
        setCookie: response.cookies.length > 0,
      });
    } catch (error) {
      observations.push({
        label: probe.label,
        url: url.toString(),
        method: "POST",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return observations;
}

function stripSearch(url: URL) {
  const clone = new URL(url);
  clone.search = "";
  clone.hash = "";
  return clone;
}

async function stage(
  emit: (event: unknown) => Promise<void>,
  key: string,
  work: () => Promise<void>,
) {
  await emit({ type: "stage", key, status: "RUNNING", progress: 10 });
  try {
    await work();
    await emit({ type: "stage", key, status: "COMPLETED", progress: 100 });
  } catch (error) {
    await emit({
      type: "stage",
      key,
      status: "FAILED",
      progress: 100,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}
async function ensureRunning(cancelled: () => Promise<boolean>) {
  if (await cancelled()) throw new Error("Scan cancelled");
}
async function validateDestination(url: URL) {
  const records = await dns.lookup(url.hostname, { all: true, verbatim: true });
  assertAddressesAllowed(
    url.hostname,
    records.map((x) => x.address),
  );
}

type SafeFetchInit = RequestInit & { allowExternal?: boolean };

async function safeFetch(
  start: URL,
  root: URL,
  init: SafeFetchInit = {},
): Promise<SafeResponse> {
  let url = start;
  const { allowExternal = false, ...fetchInit } = init;
  for (let redirects = 0; redirects <= 8; redirects++) {
    if (!["http:", "https:"].includes(url.protocol))
      throw new Error(`Unsupported redirect protocol: ${url.protocol}`);
    await validateDestination(url);
    if (!allowExternal && !isSameOriginOrSubdomain(url, root))
      throw new Error(`Redirect left configured scope: ${url.hostname}`);
    const response = await fetch(url, {
      ...fetchInit,
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT),
      headers: {
        "user-agent": "Probeveil/1.0 security scan",
        accept:
          "text/html,application/xhtml+xml,application/json;q=.8,*/*;q=.2",
        ...fetchInit.headers,
      },
    });
    if (
      response.status >= 300 &&
      response.status < 400 &&
      response.headers.get("location")
    ) {
      url = new URL(response.headers.get("location")!, url);
      continue;
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > MAX_BODY)
      throw new Error("Response exceeded the 2 MiB passive scan limit.");
    const headers = Object.fromEntries(response.headers.entries());
    const cookies =
      typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie()
        : response.headers.get("set-cookie")
          ? [response.headers.get("set-cookie")!]
          : [];
    return {
      url: response.url || url.toString(),
      status: response.status,
      headers,
      cookies,
      body: new TextDecoder().decode(bytes),
      contentType: response.headers.get("content-type") ?? undefined,
    };
  }
  throw new Error("Target exceeded the redirect limit.");
}

function inspectTls(hostname: string, port: number) {
  return new Promise<{
    subject: unknown;
    issuer: unknown;
    validFrom?: string;
    validTo?: string;
    fingerprint256?: string;
    protocol?: string;
  }>((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: true,
        timeout: TIMEOUT,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const result = {
          subject: cert.subject,
          issuer: cert.issuer,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          fingerprint256: cert.fingerprint256,
          protocol: socket.getProtocol() ?? undefined,
        };
        socket.end();
        resolve(result);
      },
    );
    socket.on("error", reject);
    socket.on("timeout", () =>
      socket.destroy(new Error("TLS handshake timed out")),
    );
  });
}
function extractLinks(html: string, base: string) {
  const links: URL[] = [];
  for (const match of html.matchAll(/(?:href|src)\s*=\s*["']([^"'#]+)["']/gi)) {
    try {
      const url = new URL(match[1], base);
      if (["http:", "https:"].includes(url.protocol)) links.push(url);
    } catch {}
  }
  return links;
}
function canonical(url: URL) {
  const clone = new URL(url);
  clone.hash = "";
  [...clone.searchParams.keys()].sort().forEach((key) => {
    const values = clone.searchParams.getAll(key).sort();
    clone.searchParams.delete(key);
    values.forEach((value) => clone.searchParams.append(key, value));
  });
  return clone.toString();
}
function endpoint(
  url: string,
  statusCode: number | undefined,
  contentType: string | undefined,
  depth: number,
  tested: boolean,
  discoveredBy: string,
  body?: string,
): Endpoint {
  return {
    url,
    method: "GET",
    statusCode,
    contentType,
    title: body?.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim(),
    depth,
    tested,
    external: false,
    discoveredBy,
  };
}
function dedupeEndpoints(items: Endpoint[]) {
  return [
    ...new Map(
      items.map((item) => [`${item.method}:${item.url}`, item]),
    ).values(),
  ].slice(0, 500);
}
function renderHeaders(headers: Record<string, string>) {
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}
function finding(
  title: string,
  category: string,
  cwe: string,
  severity: FindingInput["severity"],
  confidence: FindingInput["confidence"],
  affectedUrl: string,
  rule: string,
  impact: string,
  remediation: string,
  evidence: string,
): FindingInput {
  const guidance = ruleGuidance(rule, title);
  const description = [
    `${title} was observed on ${affectedUrl} during the passive scan.`,
    guidance.context,
    `Probeveil assigned ${severity.toLowerCase()} severity with ${confidence.toLowerCase().replaceAll("_", " ")} confidence from response-level evidence. Treat this as an evidence-backed lead: validate whether the affected response handles authentication, sensitive data, privileged actions or security-critical workflows before deciding final risk.`,
  ].join(" ");

  return {
    title,
    description,
    category,
    cwe,
    severity,
    confidence,
    affectedUrl,
    httpMethod: "GET",
    scannerRuleId: rule,
    fingerprint: createHash("sha256")
      .update(`${rule}|${affectedUrl}`)
      .digest("hex"),
    impact: `${impact} ${guidance.impactContext}`,
    remediation: `${remediation} ${guidance.remediationContext}`,
    reproductionSteps: [
      `Send a GET request to ${affectedUrl} with the same host and scheme used in the scan.`,
      `Review the response headers, cookies or body excerpt captured in the evidence section for the signal that triggered ${rule}.`,
      "Confirm whether the affected route is public, authenticated, administrative, or part of a state-changing workflow; raise priority when users, sessions, submissions, tokens or internal details are exposed.",
      "Apply the remediation, redeploy, and rerun the scan against the same URL to confirm the evidence no longer appears.",
    ],
    references: [
      ...new Set([
        `https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`,
        ...guidance.references,
      ]),
    ],
    evidence: [
      { type: "HTTP", title: "Observed response evidence", content: evidence },
    ],
  };
}

function ruleGuidance(rule: string, title: string) {
  if (rule.startsWith("headers/") || rule.startsWith("csp/"))
    return {
      context:
        "This control is enforced by browsers, so the risk depends on which pages can execute attacker-controlled content and whether users perform sensitive actions there.",
      impactContext:
        "Weak browser controls usually increase the blast radius of cross-site scripting, clickjacking, content injection, data leakage or plugin abuse rather than proving exploitation by themselves.",
      remediationContext:
        "Prefer a small allowlist, deploy in report-only mode first for CSP changes, monitor violations, then enforce once legitimate application behavior is covered.",
      references: ["https://owasp.org/www-project-secure-headers/"],
    };
  if (rule.startsWith("cookie/"))
    return {
      context:
        "Cookie attributes determine where browsers send session or preference values and whether client-side scripts can read them.",
      impactContext:
        "The finding becomes more serious when the cookie stores authentication, anti-CSRF, identity, role or session state.",
      remediationContext:
        "Inventory the cookie owner before changing it; session cookies should normally be Secure, HttpOnly and SameSite=Lax or Strict.",
      references: [
        "https://owasp.org/www-community/controls/SecureCookieAttribute",
      ],
    };
  if (rule.startsWith("tls/"))
    return {
      context:
        "Transport security findings affect the channel between users, admins and the target service.",
      impactContext:
        "On shared or hostile networks this can allow interception, content modification, credential capture or complete loss of user trust.",
      remediationContext:
        "After fixing certificates or redirects, verify the full chain, hostname coverage, renewal automation and HTTP-to-HTTPS redirect behavior.",
      references: [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/",
      ],
    };
  if (rule.startsWith("cors/"))
    return {
      context:
        "CORS controls which browser origins can read cross-origin responses through JavaScript.",
      impactContext:
        "Credentialed reflection is especially risky because a malicious site can potentially read authenticated API responses in a victim browser.",
      remediationContext:
        "Use an exact origin allowlist, reject unknown origins, and test both credentialed and non-credentialed requests.",
      references: [
        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
      ],
    };
  if (rule.startsWith("content/"))
    return {
      context:
        "Content exposure findings come from route bodies discovered during the bounded crawl.",
      impactContext:
        "The risk depends on whether exposed data includes source paths, stack traces, directory contents, secrets, usernames, tokens, internal hosts or business logic.",
      remediationContext:
        "Fix the application behavior and then search logs/artifacts for any secrets or internal details that may already have been exposed.",
      references: ["https://owasp.org/www-project-web-security-testing-guide/"],
    };
  return {
    context: `${title} was detected from passive response analysis.`,
    impactContext:
      "Use the attached evidence to decide whether this is exploitable in the target's real user and data context.",
    remediationContext:
      "Document the owner, fix path, validation method and retest result so admins can distinguish accepted risk from remediation.",
    references: ["https://owasp.org/www-project-web-security-testing-guide/"],
  };
}
