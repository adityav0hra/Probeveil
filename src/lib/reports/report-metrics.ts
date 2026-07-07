import type { ReportScanData } from "./report-data";

const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const confidenceOrder = [
  "CONFIRMED",
  "HIGH",
  "PROBABLE",
  "POTENTIAL",
  "INFORMATIONAL",
  "MANUAL_REVIEW",
] as const;

export type ChartDatum = { label: string; value: number };

export function countBy<T extends string>(
  values: readonly T[],
  rows: Array<Record<string, unknown>>,
  key: string,
) {
  return values.map((value) => ({
    label: value,
    value: rows.filter((row) => row[key] === value).length,
  }));
}

export function reportMetrics(scan: ReportScanData) {
  const findings = scan.findings;
  const endpoints = scan.endpoints;
  const parameters = endpoints.flatMap((endpoint) => endpoint.parameters ?? []);
  const testedRoutes = endpoints.filter((endpoint) => endpoint.tested).length;
  const testedParameters = parameters.filter(
    (parameter) => parameter.tested,
  ).length;
  const apiEndpoints = endpoints.filter((endpoint) =>
    /\/(?:api|graphql|rpc|rest|v[0-9])(?:\/|$|\?)/i.test(endpoint.url),
  );
  const browserRenderedEndpoints = endpoints.filter((endpoint) =>
    endpoint.discoveredBy?.startsWith("browser-rendered"),
  );
  const manualReviewTasks = findings.filter(
    (finding) => finding.confidence === "MANUAL_REVIEW",
  );
  const evasionSignals = findings.filter(
    (finding) =>
      finding.category === "Evasion signal" ||
      finding.scannerRuleId?.startsWith("evasion/"),
  );
  const severityCounts = countBy(severityOrder, findings, "severity").filter(
    (item) => item.value > 0,
  );
  const confidenceCounts = countBy(
    confidenceOrder,
    findings,
    "confidence",
  ).filter((item) => item.value > 0);
  const failedStages = scan.stages.filter((stage) => stage.status === "FAILED");
  const skippedStages = scan.stages.filter(
    (stage) => stage.status === "SKIPPED",
  );
  const completedStages = scan.stages.filter(
    (stage) => stage.status === "COMPLETED",
  );
  const highestSeverity =
    severityOrder.find((severity) =>
      findings.some((finding) => finding.severity === severity),
    ) ?? "NONE";
  const confidenceScore = findings.length
    ? Math.round(
        (findings.filter((finding) =>
          ["CONFIRMED", "HIGH", "PROBABLE"].includes(finding.confidence),
        ).length /
          findings.length) *
          100,
      )
    : 100;
  const categories = Object.entries(
    findings.reduce<Record<string, number>>((acc, finding) => {
      acc[finding.category] = (acc[finding.category] ?? 0) + 1;
      return acc;
    }, {}),
  )
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value);

  return {
    apiEndpoints: apiEndpoints.length,
    attackPathCount: scan.attackPaths.length,
    categories,
    completedStages: completedStages.length,
    confidenceCounts,
    confidenceScore,
    confirmedFindings: findings.filter(
      (finding) => finding.confidence === "CONFIRMED",
    ).length,
    coverageScore: scan.coverageScore ?? 0,
    failedStages: failedStages.length,
    evasionSignals: evasionSignals.length,
    browserRenderedEndpoints: browserRenderedEndpoints.length,
    graphQlEndpoints: endpoints.filter((endpoint) =>
      /graphql/i.test(endpoint.url),
    ).length,
    highestSeverity,
    manualReviewTasks: manualReviewTasks.length,
    parameters: parameters.length,
    securityScore: scan.securityScore ?? 100,
    severityCounts,
    skippedStages: skippedStages.length,
    stageCounts: [
      { label: "Completed", value: completedStages.length },
      { label: "Failed", value: failedStages.length },
      { label: "Skipped", value: skippedStages.length },
      {
        label: "Cancelled",
        value: scan.stages.filter((stage) => stage.status === "CANCELLED")
          .length,
      },
    ].filter((item) => item.value > 0),
    testedParameters,
    testedRoutes,
    totalFindings: findings.length,
    totalRoutes: endpoints.length,
    websocketEndpoints: endpoints.filter((endpoint) =>
      /websocket|socket|ws/i.test(endpoint.url),
    ).length,
  };
}

export function coverageRows(scan: ReportScanData) {
  const metrics = reportMetrics(scan);
  const rows = [
    {
      area: "Routes",
      discovered: metrics.totalRoutes,
      tested: metrics.testedRoutes,
      skipped: Math.max(metrics.totalRoutes - metrics.testedRoutes, 0),
      failed: 0,
    },
    {
      area: "Parameters",
      discovered: metrics.parameters,
      tested: metrics.testedParameters,
      skipped: Math.max(metrics.parameters - metrics.testedParameters, 0),
      failed: 0,
    },
    {
      area: "APIs",
      discovered: metrics.apiEndpoints,
      tested: metrics.apiEndpoints,
      skipped: 0,
      failed: 0,
    },
    {
      area: "Browser-rendered",
      discovered: metrics.browserRenderedEndpoints,
      tested: metrics.browserRenderedEndpoints,
      skipped: 0,
      failed: 0,
    },
    {
      area: "GraphQL",
      discovered: metrics.graphQlEndpoints,
      tested: metrics.graphQlEndpoints,
      skipped: 0,
      failed: 0,
    },
    {
      area: "WebSockets",
      discovered: metrics.websocketEndpoints,
      tested: metrics.websocketEndpoints,
      skipped: 0,
      failed: 0,
    },
  ];

  return rows.map((row) => ({
    ...row,
    coverage:
      row.discovered === 0
        ? 100
        : Math.round((row.tested / row.discovered) * 100),
  }));
}
