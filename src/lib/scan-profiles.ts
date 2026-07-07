import type { Prisma, ScanMode, ScheduleCadence } from "@prisma/client";

export type ScanProfilePolicy = {
  alertThresholds: {
    failBuildAt: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
    newFindingDiffs: boolean;
    notifyAt: Array<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO">;
  };
  authConfig: {
    authenticated: boolean;
    roleComparison: boolean;
    routeSeeds: string[];
    verificationPath?: string;
  };
  cadence?: ScheduleCadence;
  description: string;
  engines: Record<string, boolean>;
  features: {
    apiDiscovery: boolean;
    browserRendering: boolean;
    evidenceArchive: boolean;
    screenshots: boolean;
  };
  limits: {
    maxApiEndpoints: number;
    maxDepth: number;
    maxRoutes: number;
    maxRuntimeMinutes: number;
  };
  mode: ScanMode;
  name: string;
  slug: string;
  stageConfig: {
    active: boolean;
    apiSpecific: boolean;
    browserRendered: boolean;
    complianceEvidence: boolean;
    passive: boolean;
  };
};

export type ResolvedScanProfilePolicy = ScanProfilePolicy & { id: string };

export const defaultScanProfiles: ScanProfilePolicy[] = [
  {
    alertThresholds: {
      failBuildAt: "CRITICAL",
      newFindingDiffs: true,
      notifyAt: ["CRITICAL", "HIGH"],
    },
    authConfig: {
      authenticated: false,
      roleComparison: false,
      routeSeeds: [],
    },
    cadence: "WEEKLY",
    description:
      "Fast recurring coverage for public pages, core headers, TLS posture and lightweight route discovery.",
    engines: {
      apiSpecific: false,
      browserCrawler: false,
      niktoStyle: false,
      nuclei: false,
      probeveilPassive: true,
      semgrepJs: false,
      technologyChecks: true,
      tlsDiagnostics: true,
      zapBaseline: false,
    },
    features: {
      apiDiscovery: false,
      browserRendering: false,
      evidenceArchive: true,
      screenshots: false,
    },
    limits: {
      maxApiEndpoints: 20,
      maxDepth: 1,
      maxRoutes: 35,
      maxRuntimeMinutes: 12,
    },
    mode: "QUICK",
    name: "Light weekly",
    slug: "light-weekly",
    stageConfig: {
      active: false,
      apiSpecific: false,
      browserRendered: false,
      complianceEvidence: false,
      passive: true,
    },
  },
  {
    alertThresholds: {
      failBuildAt: "HIGH",
      newFindingDiffs: true,
      notifyAt: ["CRITICAL", "HIGH", "MEDIUM"],
    },
    authConfig: {
      authenticated: false,
      roleComparison: false,
      routeSeeds: [],
    },
    cadence: "MONTHLY",
    description:
      "Broad public-surface review with browser rendering, API discovery, optional external engines and evidence capture.",
    engines: {
      apiSpecific: true,
      browserCrawler: true,
      niktoStyle: true,
      nuclei: true,
      probeveilPassive: true,
      semgrepJs: true,
      technologyChecks: true,
      tlsDiagnostics: true,
      zapBaseline: true,
    },
    features: {
      apiDiscovery: true,
      browserRendering: true,
      evidenceArchive: true,
      screenshots: true,
    },
    limits: {
      maxApiEndpoints: 150,
      maxDepth: 4,
      maxRoutes: 250,
      maxRuntimeMinutes: 60,
    },
    mode: "MAXIMUM",
    name: "Deep monthly",
    slug: "deep-monthly",
    stageConfig: {
      active: true,
      apiSpecific: true,
      browserRendered: true,
      complianceEvidence: false,
      passive: true,
    },
  },
  {
    alertThresholds: {
      failBuildAt: "HIGH",
      newFindingDiffs: true,
      notifyAt: ["CRITICAL", "HIGH"],
    },
    authConfig: {
      authenticated: true,
      roleComparison: true,
      routeSeeds: [
        "/dashboard",
        "/account",
        "/admin",
        "/settings",
        "/billing",
        "/invoices",
        "/exports",
      ],
      verificationPath: "/dashboard",
    },
    cadence: "MONTHLY",
    description:
      "Deeper signed-in coverage for dashboards, settings, exports and role/access-control comparison.",
    engines: {
      apiSpecific: true,
      browserCrawler: true,
      niktoStyle: true,
      nuclei: true,
      probeveilPassive: true,
      semgrepJs: true,
      technologyChecks: true,
      tlsDiagnostics: true,
      zapBaseline: true,
    },
    features: {
      apiDiscovery: true,
      browserRendering: true,
      evidenceArchive: true,
      screenshots: true,
    },
    limits: {
      maxApiEndpoints: 200,
      maxDepth: 5,
      maxRoutes: 300,
      maxRuntimeMinutes: 75,
    },
    mode: "MAXIMUM",
    name: "Authenticated app",
    slug: "authenticated-app",
    stageConfig: {
      active: true,
      apiSpecific: true,
      browserRendered: true,
      complianceEvidence: false,
      passive: true,
    },
  },
  {
    alertThresholds: {
      failBuildAt: "HIGH",
      newFindingDiffs: true,
      notifyAt: ["CRITICAL", "HIGH", "MEDIUM"],
    },
    authConfig: {
      authenticated: false,
      roleComparison: false,
      routeSeeds: [
        "/api",
        "/graphql",
        "/swagger",
        "/openapi.json",
        "/v3/api-docs",
      ],
    },
    cadence: "WEEKLY",
    description:
      "API-first coverage for OpenAPI/Swagger, GraphQL, REST parameters, exports, pagination and auth-header comparison.",
    engines: {
      apiSpecific: true,
      browserCrawler: true,
      niktoStyle: false,
      nuclei: true,
      probeveilPassive: true,
      semgrepJs: true,
      technologyChecks: true,
      tlsDiagnostics: true,
      zapBaseline: false,
    },
    features: {
      apiDiscovery: true,
      browserRendering: true,
      evidenceArchive: true,
      screenshots: false,
    },
    limits: {
      maxApiEndpoints: 350,
      maxDepth: 3,
      maxRoutes: 180,
      maxRuntimeMinutes: 60,
    },
    mode: "FULL",
    name: "API heavy",
    slug: "api-heavy",
    stageConfig: {
      active: true,
      apiSpecific: true,
      browserRendered: true,
      complianceEvidence: false,
      passive: true,
    },
  },
  {
    alertThresholds: {
      failBuildAt: "MEDIUM",
      newFindingDiffs: true,
      notifyAt: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    },
    authConfig: {
      authenticated: true,
      roleComparison: true,
      routeSeeds: [
        "/dashboard",
        "/account",
        "/settings",
        "/audit",
        "/reports",
        "/exports",
        "/privacy",
        "/security",
      ],
    },
    cadence: "MONTHLY",
    description:
      "Evidence-heavy run for audit trails, screenshots, reports, route inventory, request/response archives and low-severity control gaps.",
    engines: {
      apiSpecific: true,
      browserCrawler: true,
      niktoStyle: true,
      nuclei: true,
      probeveilPassive: true,
      semgrepJs: true,
      technologyChecks: true,
      tlsDiagnostics: true,
      zapBaseline: true,
    },
    features: {
      apiDiscovery: true,
      browserRendering: true,
      evidenceArchive: true,
      screenshots: true,
    },
    limits: {
      maxApiEndpoints: 250,
      maxDepth: 5,
      maxRoutes: 350,
      maxRuntimeMinutes: 90,
    },
    mode: "MAXIMUM",
    name: "Compliance evidence",
    slug: "compliance-evidence",
    stageConfig: {
      active: true,
      apiSpecific: true,
      browserRendered: true,
      complianceEvidence: true,
      passive: true,
    },
  },
];

export type ScanProfileLike = {
  alertThresholds: Prisma.JsonValue;
  authConfig: Prisma.JsonValue;
  cadence: ScheduleCadence | null;
  description: string | null;
  engines: Prisma.JsonValue;
  features: Prisma.JsonValue;
  id: string;
  limits: Prisma.JsonValue;
  mode: ScanMode;
  name: string;
  slug: string;
  stageConfig: Prisma.JsonValue;
};

export function scanPolicyFromProfile(
  profile: ScanProfileLike,
): ResolvedScanProfilePolicy {
  return {
    alertThresholds: alertThresholdValue(profile.alertThresholds),
    authConfig: authConfigValue(profile.authConfig),
    ...(profile.cadence ? { cadence: profile.cadence } : {}),
    description: profile.description ?? "",
    engines: booleanRecordValue(profile.engines),
    features: featureValue(profile.features),
    id: profile.id,
    limits: limitsValue(profile.limits),
    mode: profile.mode,
    name: profile.name,
    slug: profile.slug,
    stageConfig: stageConfigValue(profile.stageConfig),
  };
}

export function profileFeatureDefaults(profile?: ScanProfileLike | null) {
  if (!profile) return undefined;
  return featureValue(profile.features);
}

function featureValue(value: Prisma.JsonValue) {
  const data = objectValue(value);
  return {
    apiDiscovery: data.apiDiscovery === true,
    browserRendering: data.browserRendering === true,
    evidenceArchive: data.evidenceArchive !== false,
    screenshots: data.screenshots === true,
  };
}

function alertThresholdValue(value: Prisma.JsonValue) {
  const data = objectValue(value);
  const notifyAt = Array.isArray(data.notifyAt)
    ? data.notifyAt.filter(isSeverity)
    : [];
  const failBuildAt = isSeverity(data.failBuildAt)
    ? data.failBuildAt
    : "CRITICAL";
  return {
    failBuildAt,
    newFindingDiffs: data.newFindingDiffs !== false,
    notifyAt: notifyAt.length
      ? notifyAt
      : ([
          "CRITICAL",
          "HIGH",
        ] satisfies ScanProfilePolicy["alertThresholds"]["notifyAt"]),
  };
}

function authConfigValue(value: Prisma.JsonValue) {
  const data = objectValue(value);
  return {
    authenticated: data.authenticated === true,
    roleComparison: data.roleComparison === true,
    routeSeeds: Array.isArray(data.routeSeeds)
      ? data.routeSeeds.filter(
          (item): item is string => typeof item === "string",
        )
      : [],
    ...(typeof data.verificationPath === "string"
      ? { verificationPath: data.verificationPath }
      : {}),
  };
}

function limitsValue(value: Prisma.JsonValue) {
  const data = objectValue(value);
  return {
    maxApiEndpoints: numberValue(data.maxApiEndpoints, 100),
    maxDepth: numberValue(data.maxDepth, 3),
    maxRoutes: numberValue(data.maxRoutes, 100),
    maxRuntimeMinutes: numberValue(data.maxRuntimeMinutes, 45),
  };
}

function stageConfigValue(value: Prisma.JsonValue) {
  const data = objectValue(value);
  return {
    active: data.active === true,
    apiSpecific: data.apiSpecific === true,
    browserRendered: data.browserRendered === true,
    complianceEvidence: data.complianceEvidence === true,
    passive: data.passive !== false,
  };
}

function booleanRecordValue(value: Prisma.JsonValue) {
  return Object.fromEntries(
    Object.entries(objectValue(value)).map(([key, item]) => [
      key,
      item === true,
    ]),
  );
}

function isSeverity(
  value: unknown,
): value is ScanProfilePolicy["alertThresholds"]["notifyAt"][number] {
  return (
    value === "CRITICAL" ||
    value === "HIGH" ||
    value === "MEDIUM" ||
    value === "LOW" ||
    value === "INFO"
  );
}

function numberValue(value: unknown, fallback: number) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function objectValue(value: Prisma.JsonValue) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
