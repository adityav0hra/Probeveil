import { createHash } from "node:crypto";
import { promises as dns } from "node:dns";
import chromium from "@sparticuz/chromium";
import { assertAddressesAllowed } from "@/lib/scope";
import { isSameOriginOrSubdomain } from "@/lib/url";
import type { FindingInput, ScanJob } from "./types";

const PAGE_TIMEOUT = 12_000;
const NETWORK_IDLE_TIMEOUT = 3_500;
const INTERACTION_TIMEOUT = 1_500;

export type BrowserRenderedEndpoint = {
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

export type BrowserRenderedParameter = {
  endpointUrl: string;
  method: string;
  name: string;
  location: string;
  dataType?: string;
  tested: boolean;
};

export type BrowserRenderedRouteCandidate = {
  url: URL;
  source: string;
};

export type BrowserRenderedResult = {
  endpoints: BrowserRenderedEndpoint[];
  findings: FindingInput[];
  parameters: BrowserRenderedParameter[];
  routeCandidates: BrowserRenderedRouteCandidate[];
};

type BrowserRuntime = {
  chromium: {
    launch: (options: Record<string, unknown>) => Promise<Browser>;
  };
  executablePath?: string;
  launchArgs: string[];
};

type Browser = {
  close: () => Promise<void>;
  newContext: (options: Record<string, unknown>) => Promise<BrowserContext>;
};

type BrowserContext = {
  addCookies: (cookies: BrowserCookie[]) => Promise<void>;
  close: () => Promise<void>;
  newPage: () => Promise<Page>;
  route: (
    pattern: string,
    handler: (route: Route) => Promise<void>,
  ) => Promise<void>;
};

type BrowserCookie = {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  sameSite: "Lax";
};

type Route = {
  abort: () => Promise<void>;
  continue: () => Promise<void>;
  request: () => { url: () => string };
};

type Page = {
  close: () => Promise<void>;
  evaluate: <T>(fn: string | (() => T | Promise<T>)) => Promise<T>;
  goto: (
    url: string,
    options: Record<string, unknown>,
  ) => Promise<Response | null>;
  locator: (selector: string) => Locator;
  on: (event: "response", handler: (response: Response) => void) => void;
  screenshot: (options: Record<string, unknown>) => Promise<Buffer>;
  title: () => Promise<string>;
  url: () => string;
  waitForLoadState: (
    state: "networkidle",
    options: Record<string, unknown>,
  ) => Promise<void>;
  waitForTimeout: (timeout: number) => Promise<void>;
};

type Locator = {
  count: () => Promise<number>;
  nth: (index: number) => Locator;
  click: (options: Record<string, unknown>) => Promise<void>;
  innerText: (options?: Record<string, unknown>) => Promise<string>;
};

type Response = {
  headers: () => Record<string, string>;
  request: () => {
    method: () => string;
    resourceType: () => string;
  };
  status: () => number;
  url: () => string;
};

type RenderedDom = {
  forms: Array<{
    action: string;
    method: string;
    fields: Array<{ name: string; type?: string; location: string }>;
  }>;
  links: string[];
  routeHints: string[];
  title: string;
};

type ObservedResponse = {
  url: string;
  method: string;
  resourceType: string;
  status: number;
  contentType?: string;
};

export async function runBrowserRenderedScan({
  authHeaders,
  cancelled,
  mode,
  root,
  screenshots,
  startUrls,
}: {
  authHeaders: Record<string, string>;
  cancelled: () => Promise<boolean>;
  mode: ScanJob["mode"];
  root: URL;
  screenshots?: boolean;
  startUrls: URL[];
}): Promise<BrowserRenderedResult> {
  const launched = await launchBrowser();
  if (!launched)
    return {
      endpoints: [],
      parameters: [],
      routeCandidates: [],
      findings: [browserRuntimeUnavailableFinding(root.toString())],
    };
  const { browser } = launched;

  const endpoints = new Map<string, BrowserRenderedEndpoint>();
  const routeCandidates = new Map<string, BrowserRenderedRouteCandidate>();
  const parameters = new Map<string, BrowserRenderedParameter>();
  const observedResponses = new Map<string, ObservedResponse>();
  const screenshotEvidence: string[] = [];
  const blockedHosts = new Set<string>();
  const allowedHostCache = new Map<string, boolean>();
  let pagesRendered = 0;
  let interactions = 0;

  try {
    const context = await browser.newContext({
      extraHTTPHeaders: authHeaders,
      ignoreHTTPSErrors: true,
      userAgent:
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) ProbeveilBrowser/1.0 Chrome Safari/537.36",
      viewport: { width: 1440, height: 1100 },
    });
    try {
      const cookies = cookiesFromHeader(authHeaders.cookie, root);
      if (cookies.length) await context.addCookies(cookies);
      await context.route("**/*", async (route) => {
        const requestUrl = route.request().url();
        try {
          const url = new URL(requestUrl);
          if (!["http:", "https:"].includes(url.protocol)) {
            await route.abort();
            return;
          }
          const allowed = await hostAllowed(url, allowedHostCache);
          if (!allowed) {
            blockedHosts.add(url.hostname);
            await route.abort();
            return;
          }
          await route.continue();
        } catch {
          await route.abort();
        }
      });

      const maxPages = mode === "QUICK" ? 4 : mode === "FULL" ? 10 : 18;
      const queue = uniqueUrls(startUrls).slice(0, maxPages);
      const seen = new Set<string>();
      for (
        let depth = 0;
        queue.length && pagesRendered < maxPages;
        depth += 1
      ) {
        await ensureRunning(cancelled);
        const current = queue.shift()!;
        const key = canonical(current);
        if (seen.has(key)) continue;
        seen.add(key);
        const page = await context.newPage();
        try {
          page.on("response", (response) => {
            const url = response.url();
            const method = response.request().method();
            const resourceType = response.request().resourceType();
            if (!isUsefulBrowserResource(resourceType, url)) return;
            observedResponses.set(`${method}:${url}`, {
              url,
              method,
              resourceType,
              status: response.status(),
              contentType: response.headers()["content-type"],
            });
          });

          const response = await page.goto(current.toString(), {
            timeout: PAGE_TIMEOUT,
            waitUntil: "domcontentloaded",
          });
          await page
            .waitForLoadState("networkidle", { timeout: NETWORK_IDLE_TIMEOUT })
            .catch(() => undefined);
          const dom = await renderedDom(page);
          pagesRendered += 1;

          addEndpoint(endpoints, {
            url: page.url(),
            method: "GET",
            statusCode: response?.status(),
            contentType: response?.headers()["content-type"],
            title: dom.title || (await page.title().catch(() => "")),
            depth,
            tested: true,
            external: !isSameOriginOrSubdomain(new URL(page.url()), root),
            discoveredBy: "browser-rendered:document",
          });
          addRenderedDiscoveries({
            base: page.url(),
            depth,
            dom,
            endpoints,
            parameters,
            queue,
            routeCandidates,
            root,
            seen,
          });

          interactions += await exerciseSafeInteractions(page, cancelled);
          if (screenshots) {
            const buffer = await page
              .screenshot({ fullPage: true, timeout: 5_000, type: "png" })
              .catch(() => undefined);
            if (buffer)
              screenshotEvidence.push(
                `${new URL(page.url()).pathname || "/"} sha256=${createHash("sha256").update(buffer).digest("hex")} bytes=${buffer.byteLength}`,
              );
          }
        } catch (error) {
          addEndpoint(endpoints, {
            url: current.toString(),
            method: "GET",
            title: error instanceof Error ? error.message : String(error),
            depth,
            tested: false,
            external: !isSameOriginOrSubdomain(current, root),
            discoveredBy: "browser-rendered:error",
          });
        } finally {
          await page.close().catch(() => undefined);
        }
      }
    } finally {
      await context.close().catch(() => undefined);
    }
  } finally {
    await browser.close().catch(() => undefined);
  }

  for (const observed of observedResponses.values()) {
    let url: URL;
    try {
      url = new URL(observed.url);
    } catch {
      continue;
    }
    addEndpoint(endpoints, {
      url: observed.url,
      method: observed.method,
      statusCode: observed.status,
      contentType: observed.contentType,
      depth: observed.resourceType === "document" ? 1 : 2,
      tested: true,
      external: !isSameOriginOrSubdomain(url, root),
      discoveredBy: `browser-rendered:${observed.resourceType}`,
    });
    if (isSameOriginOrSubdomain(url, root))
      routeCandidates.set(canonical(url), {
        url,
        source: `browser-rendered:${observed.resourceType}`,
      });
    for (const parameter of queryParameters(url, observed.method))
      parameters.set(parameterKey(parameter), parameter);
  }

  return {
    endpoints: [...endpoints.values()].slice(0, 450),
    findings: [
      browserRenderedCoverageFinding({
        blockedHosts: [...blockedHosts],
        endpoints: [...endpoints.values()],
        interactions,
        pagesRendered,
        parameters: [...parameters.values()],
        root,
        routeCandidates: [...routeCandidates.values()],
        screenshots: screenshotEvidence,
      }),
    ],
    parameters: [...parameters.values()].slice(0, 750),
    routeCandidates: [...routeCandidates.values()].slice(0, 350),
  };
}

async function launchBrowser(): Promise<{ browser: Browser } | undefined> {
  const runtimes = await loadBrowserRuntimes();
  for (const runtime of runtimes) {
    try {
      const browser = await runtime.chromium.launch({
        args: runtime.launchArgs,
        executablePath: runtime.executablePath,
        headless: true,
      });
      return { browser };
    } catch {}
  }
  return undefined;
}

async function loadBrowserRuntimes(): Promise<BrowserRuntime[]> {
  const runtimes: BrowserRuntime[] = [];
  try {
    const playwright = await import("playwright-core");
    const executablePath = await chromium.executablePath();
    runtimes.push({
      chromium: playwright.chromium as unknown as BrowserRuntime["chromium"],
      executablePath,
      launchArgs: [
        ...chromium.args,
        "--disable-dev-shm-usage",
        "--disable-setuid-sandbox",
        "--no-sandbox",
      ],
    });
  } catch {}
  try {
    const playwright = await import("@playwright/test");
    runtimes.push({
      chromium: playwright.chromium as unknown as BrowserRuntime["chromium"],
      launchArgs: ["--disable-dev-shm-usage", "--no-sandbox"],
    });
  } catch {
    return runtimes;
  }
  return runtimes;
}

async function hostAllowed(url: URL, cache: Map<string, boolean>) {
  const cached = cache.get(url.hostname);
  if (cached !== undefined) return cached;
  try {
    const records = await dns.lookup(url.hostname, {
      all: true,
      verbatim: true,
    });
    assertAddressesAllowed(
      url.hostname,
      records.map((record) => record.address),
    );
    cache.set(url.hostname, true);
    return true;
  } catch {
    cache.set(url.hostname, false);
    return false;
  }
}

async function renderedDom(page: Page): Promise<RenderedDom> {
  return page.evaluate<RenderedDom>(`(() => {
    const absolute = (value) => {
      if (!value) return "";
      try {
        return new URL(value, window.location.href).toString();
      } catch {
        return "";
      }
    };
    const links = Array.from(
      document.querySelectorAll(
        "a[href],link[href],script[src],img[src],iframe[src],[data-href],[data-url],[data-route]"
      )
    )
      .flatMap((node) => [
        node.getAttribute("href"),
        node.getAttribute("src"),
        node.getAttribute("data-href"),
        node.getAttribute("data-url"),
        node.getAttribute("data-route"),
      ])
      .map(absolute)
      .filter(Boolean);
    const forms = Array.from(document.querySelectorAll("form")).map((form) => {
      const method = (form.getAttribute("method") || "GET").toUpperCase();
      return {
        action: absolute(form.getAttribute("action")) || window.location.href,
        method,
        fields: Array.from(form.querySelectorAll("input,select,textarea"))
          .map((field) => ({
            name: field.getAttribute("name") || field.id || "",
            type:
              field.getAttribute("type") ||
              field.getAttribute("data-type") ||
              field.tagName.toLowerCase(),
            location: method === "GET" ? "query" : "form",
          }))
          .filter((field) => field.name),
      };
    });
    const hintText = Array.from(
      document.querySelectorAll(
        "[onclick],[hx-get],[hx-post],[x-data],[data-action],[data-endpoint]"
      )
    )
      .flatMap((node) => [
        node.getAttribute("onclick"),
        node.getAttribute("hx-get"),
        node.getAttribute("hx-post"),
        node.getAttribute("data-action"),
        node.getAttribute("data-endpoint"),
      ])
      .filter(Boolean)
      .join("\\n");
    const routeHints = hintText
      .split(/[\\s"'\\\`,()<>]+/)
      .filter((value) =>
        /^\\/(?:api|admin|internal|graphql|auth|users?|accounts?|settings|dashboard|export|download|search|webhook|v\\d+)/i.test(value)
      );
    return {
      forms,
      links,
      routeHints,
      title: document.title,
    };
  })()`);
}

function addRenderedDiscoveries({
  base,
  depth,
  dom,
  endpoints,
  parameters,
  queue,
  routeCandidates,
  root,
  seen,
}: {
  base: string;
  depth: number;
  dom: RenderedDom;
  endpoints: Map<string, BrowserRenderedEndpoint>;
  parameters: Map<string, BrowserRenderedParameter>;
  queue: URL[];
  routeCandidates: Map<string, BrowserRenderedRouteCandidate>;
  root: URL;
  seen: Set<string>;
}) {
  for (const raw of [...dom.links, ...dom.routeHints]) {
    let url: URL;
    try {
      url = new URL(raw, base);
    } catch {
      continue;
    }
    if (!["http:", "https:"].includes(url.protocol)) continue;
    const sameScope = isSameOriginOrSubdomain(url, root);
    addEndpoint(endpoints, {
      url: url.toString(),
      method: "GET",
      depth: depth + 1,
      tested: false,
      external: !sameScope,
      discoveredBy: "browser-rendered:dom-link",
    });
    if (!sameScope) continue;
    routeCandidates.set(canonical(url), {
      url,
      source: "browser-rendered:dom-link",
    });
    if (!seen.has(canonical(url)) && queue.length < 30) queue.push(url);
    for (const parameter of queryParameters(url, "GET"))
      parameters.set(parameterKey(parameter), parameter);
  }

  for (const form of dom.forms) {
    let action: URL;
    try {
      action = new URL(form.action, base);
    } catch {
      continue;
    }
    addEndpoint(endpoints, {
      url: action.toString(),
      method: form.method,
      depth: depth + 1,
      tested: false,
      external: !isSameOriginOrSubdomain(action, root),
      discoveredBy: "browser-rendered:form",
    });
    routeCandidates.set(canonical(action), {
      url: action,
      source: "browser-rendered:form",
    });
    for (const field of form.fields) {
      const parameter = {
        endpointUrl: stripSearch(action).toString(),
        method: form.method,
        name: field.name,
        location: field.location,
        dataType: field.type || inferDataType(field.name),
        tested: false,
      };
      parameters.set(parameterKey(parameter), parameter);
    }
  }
}

async function exerciseSafeInteractions(
  page: Page,
  cancelled: () => Promise<boolean>,
) {
  const locator = page.locator(
    "button,[role=button],a[aria-expanded],summary,[data-state],[data-tab],[aria-controls]",
  );
  const count = Math.min(await locator.count().catch(() => 0), 8);
  let interactions = 0;
  for (let index = 0; index < count; index += 1) {
    await ensureRunning(cancelled);
    const item = locator.nth(index);
    const label = await item
      .innerText({ timeout: 500 })
      .then((text) => text.trim().slice(0, 80))
      .catch(() => "");
    if (!safeInteractionLabel(label)) continue;
    try {
      await item.click({ timeout: INTERACTION_TIMEOUT, trial: true });
      await item.click({ timeout: INTERACTION_TIMEOUT });
      await page.waitForTimeout(500);
      interactions += 1;
    } catch {}
  }
  return interactions;
}

function safeInteractionLabel(label: string) {
  if (
    /delete|remove|destroy|pay|purchase|checkout|submit|save|update|create|send|logout|sign out|cancel|confirm|approve|reject|archive/i.test(
      label,
    )
  )
    return false;
  return (
    !label ||
    /menu|tab|more|load|next|filter|search|show|open|view|details|expand|collapse/i.test(
      label,
    )
  );
}

function addEndpoint(
  endpoints: Map<string, BrowserRenderedEndpoint>,
  endpoint: BrowserRenderedEndpoint,
) {
  const key = `${endpoint.method}:${endpoint.url}`;
  const existing = endpoints.get(key);
  endpoints.set(key, {
    ...existing,
    ...endpoint,
    title: endpoint.title ?? existing?.title,
    tested: Boolean(existing?.tested || endpoint.tested),
  });
}

function queryParameters(url: URL, method: string): BrowserRenderedParameter[] {
  return [...url.searchParams.keys()].map((name) => ({
    endpointUrl: stripSearch(url).toString(),
    method,
    name,
    location: "query",
    dataType: inferDataType(name),
    tested: false,
  }));
}

function cookiesFromHeader(header: string | undefined, root: URL) {
  if (!header) return [];
  return header
    .split(";")
    .map((part) => part.trim())
    .map((part) => {
      const [name, ...rest] = part.split("=");
      return { name, value: rest.join("=") };
    })
    .filter((cookie) => cookie.name && cookie.value)
    .map((cookie) => ({
      name: cookie.name,
      value: cookie.value,
      domain: root.hostname,
      path: "/",
      secure: root.protocol === "https:",
      sameSite: "Lax" as const,
    }));
}

function isUsefulBrowserResource(resourceType: string, url: string) {
  if (/^data:|^blob:/i.test(url)) return false;
  return ["document", "fetch", "xhr", "script"].includes(resourceType);
}

function inferDataType(name: string) {
  if (/^(is|has|can)[A-Z_]|admin|enabled|active|verified/i.test(name))
    return "boolean-like";
  if (/id$|Id$|_id$|uuid|tenant|owner|user|account/i.test(name))
    return "identifier-like";
  if (
    /price|amount|total|count|limit|offset|page|size|quantity|score/i.test(name)
  )
    return "numeric-like";
  if (/url|uri|redirect|callback|return|next|path|file|template/i.test(name))
    return "url-or-path-like";
  if (/token|secret|key|code|otp|nonce|state/i.test(name)) return "token-like";
  return "string-like";
}

function parameterKey(parameter: BrowserRenderedParameter) {
  return `${parameter.method}:${parameter.endpointUrl}:${parameter.location}:${parameter.name}`;
}

function stripSearch(url: URL) {
  const clone = new URL(url);
  clone.search = "";
  clone.hash = "";
  return clone;
}

function uniqueUrls(urls: URL[]) {
  return [...new Map(urls.map((url) => [canonical(url), url])).values()];
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

async function ensureRunning(cancelled: () => Promise<boolean>) {
  if (await cancelled()) throw new Error("Scan cancelled");
}

function browserRenderedCoverageFinding({
  blockedHosts,
  endpoints,
  interactions,
  pagesRendered,
  parameters,
  root,
  routeCandidates,
  screenshots,
}: {
  blockedHosts: string[];
  endpoints: BrowserRenderedEndpoint[];
  interactions: number;
  pagesRendered: number;
  parameters: BrowserRenderedParameter[];
  root: URL;
  routeCandidates: BrowserRenderedRouteCandidate[];
  screenshots: string[];
}): FindingInput {
  const apiLike = endpoints.filter((endpoint) =>
    /\/(?:api|graphql|rpc|rest|v[0-9])(?:\/|$|\?)/i.test(endpoint.url),
  );
  const content = [
    `pages_rendered=${pagesRendered}`,
    `browser_observed_routes=${endpoints.length}`,
    `api_or_fetch_routes=${apiLike.length}`,
    `rendered_parameters=${parameters.length}`,
    `safe_interactions=${interactions}`,
    `client_route_candidates=${routeCandidates.length}`,
    `blocked_reserved_hosts=${blockedHosts.length ? blockedHosts.join(", ") : "none"}`,
    screenshots.length
      ? `screenshot_hashes=\n${screenshots.slice(0, 12).join("\n")}`
      : undefined,
    "",
    "Sample browser-observed routes:",
    endpoints
      .slice(0, 30)
      .map(
        (endpoint) =>
          `${endpoint.method} ${endpoint.statusCode ?? "-"} ${endpoint.discoveredBy} ${endpoint.url}`,
      )
      .join("\n"),
  ]
    .filter(Boolean)
    .join("\n");
  return {
    title: "Browser-rendered surface was scanned",
    description:
      "Probeveil launched a real browser, rendered JavaScript, observed document/fetch/XHR/script responses, collected rendered links and forms, and merged those discoveries into route and parameter coverage.",
    category: "Browser-rendered coverage",
    cwe: "CWE-693",
    owaspCategory: "Security Testing Coverage",
    severity: "INFO",
    confidence: "INFORMATIONAL",
    affectedUrl: root.toString(),
    httpMethod: "GET",
    scannerName: "Probeveil Browser Renderer",
    scannerRuleId: "coverage/browser-rendered-surface",
    scannerVersion: "1.0.0",
    fingerprint: createHash("sha256")
      .update(`coverage/browser-rendered-surface|${root.toString()}`)
      .digest("hex"),
    impact:
      "Rendered crawling expands coverage to client-side routes, API calls and forms that static HTML crawling often misses.",
    remediation:
      "Review browser-observed routes alongside authenticated and role-comparison results, then retest high-value client-side flows with approved credentials.",
    reproductionSteps: [
      "Create a scan with Browser rendering enabled.",
      "Review endpoints discovered by browser-rendered document, fetch, XHR, script, DOM-link and form sources.",
      "Compare the browser-observed route list with the ordinary HTTP crawl to identify JavaScript-only surface.",
    ],
    references: ["https://owasp.org/www-project-web-security-testing-guide/"],
    evidence: [
      {
        type: "BROWSER_RENDERED_SURFACE",
        title: "Browser-rendered discovery summary",
        content,
      },
    ],
  };
}

function browserRuntimeUnavailableFinding(affectedUrl: string): FindingInput {
  return {
    title: "Browser-rendered scanning could not start",
    description:
      "Probeveil attempted to start the browser-rendered crawler, but a usable Chromium runtime was not available in this environment.",
    category: "Browser-rendered coverage",
    cwe: "CWE-693",
    owaspCategory: "Security Testing Coverage",
    severity: "LOW",
    confidence: "PROBABLE",
    affectedUrl,
    httpMethod: "GET",
    scannerName: "Probeveil Browser Renderer",
    scannerRuleId: "coverage/browser-rendered-runtime-unavailable",
    scannerVersion: "1.0.0",
    fingerprint: createHash("sha256")
      .update(`coverage/browser-rendered-runtime-unavailable|${affectedUrl}`)
      .digest("hex"),
    impact:
      "JavaScript-only routes, rendered forms and fetch/XHR API calls may be absent from this scan.",
    remediation:
      "Install the Playwright browser runtime for local workers or deploy with the serverless Chromium dependency included.",
    reproductionSteps: [
      "Create a scan with Browser rendering enabled.",
      "Check the browser-render stage and worker logs for Chromium launch failures.",
      "Rerun the scan after the browser runtime is available.",
    ],
    references: ["https://playwright.dev/docs/browsers"],
    evidence: [
      {
        type: "BROWSER_RENDERED_RUNTIME",
        title: "Browser runtime unavailable",
        content:
          "No usable Playwright Chromium runtime could be loaded by the worker.",
      },
    ],
  };
}
