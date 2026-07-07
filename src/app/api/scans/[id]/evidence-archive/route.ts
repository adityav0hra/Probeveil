import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import {
  canonicalScanUrl,
  type ReportScanData,
} from "@/lib/reports/report-data";
import { reportMetrics } from "@/lib/reports/report-metrics";
import { createZip } from "@/lib/zip";

type ArchiveEntry = {
  name: string;
  content: Buffer | string;
};

type ArchiveScan = NonNullable<Awaited<ReturnType<typeof getArchiveScan>>>;

export async function GET(
  _: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  await requireRole(["ADMIN", "AUDITOR"]);
  const { id } = await params;
  const scan = await getArchiveScan(id);
  if (!scan) return new NextResponse("Not found", { status: 404 });

  const hostname = safeHostname(canonicalScanUrl(scan));
  const exportedAt = new Date().toISOString();
  const entries = buildArchiveEntries(scan, exportedAt);
  const manifest = manifestEntry(scan, exportedAt, entries);
  const allEntries = [
    textEntry(
      "README.txt",
      [
        "Probeveil evidence archive",
        "",
        "This ZIP contains persisted scan evidence and metadata for professional review.",
        "Authentication headers submitted for scanning are not stored; request headers are redacted before archival.",
        "Large screenshots may appear as metadata-only records when they exceed the archive safety limit.",
        "",
        "Start with manifest.json, route-inventory/routes.json, findings/findings.json and scanner-logs/stages.json.",
      ].join("\n"),
    ),
    manifest,
    ...entries,
  ];
  allEntries.push(shaSumsEntry(allEntries));
  const zip = createZip(allEntries);
  const digest = sha256(zip);

  await db.report.upsert({
    where: { scanId_type: { scanId: scan.id, type: "EVIDENCE_ARCHIVE" } },
    update: {
      sha256: digest,
      size: zip.byteLength,
      status: "READY",
      path: `evidence-archives/Probeveil-${hostname}-${id}-evidence-archive.zip`,
    },
    create: {
      scanId: scan.id,
      type: "EVIDENCE_ARCHIVE",
      sha256: digest,
      size: zip.byteLength,
      path: `evidence-archives/Probeveil-${hostname}-${id}-evidence-archive.zip`,
    },
  });

  return new NextResponse(new Uint8Array(zip), {
    headers: {
      "content-disposition": `attachment; filename=Probeveil-${hostname}-${id}-evidence-archive.zip`,
      "content-length": String(zip.byteLength),
      "content-type": "application/zip",
      "x-probeveil-archive-sha256": digest,
    },
  });
}

function getArchiveScan(id: string) {
  return db.scan.findUnique({
    include: {
      artifacts: { orderBy: [{ type: "asc" }, { createdAt: "asc" }] },
      attackPaths: true,
      endpoints: { include: { parameters: true }, orderBy: { url: "asc" } },
      findings: {
        include: {
          evidence: {
            include: { artifact: true },
            orderBy: { createdAt: "asc" },
          },
          reviews: {
            include: { user: { select: { email: true, name: true } } },
          },
          issue: {
            include: {
              events: { orderBy: { createdAt: "desc" }, take: 20 },
            },
          },
        },
        orderBy: [{ severity: "asc" }, { detectedAt: "desc" }],
      },
      jobs: { orderBy: { createdAt: "asc" } },
      reports: true,
      retests: true,
      services: true,
      stages: { orderBy: { order: "asc" } },
      targets: true,
      technologies: true,
    },
    where: { id },
  });
}

function buildArchiveEntries(
  scan: ArchiveScan,
  exportedAt: string,
): ArchiveEntry[] {
  const routeInventory = scan.endpoints.map((endpoint) => ({
    id: endpoint.id,
    method: endpoint.method,
    url: endpoint.url,
    statusCode: endpoint.statusCode,
    contentType: endpoint.contentType,
    title: endpoint.title,
    depth: endpoint.depth,
    tested: endpoint.tested,
    external: endpoint.external,
    discoveredBy: endpoint.discoveredBy,
    parameters: endpoint.parameters.map((parameter) => ({
      name: parameter.name,
      location: parameter.location,
      dataType: parameter.dataType,
      tested: parameter.tested,
    })),
  }));

  const findingRows = scan.findings.map((finding) => ({
    id: finding.id,
    issueId: finding.issueId,
    issueStatus: finding.issue?.status,
    issueOccurrenceCount: finding.issue?.occurrenceCount,
    issueFirstSeenAt: finding.issue?.firstSeenAt,
    issueLastSeenAt: finding.issue?.lastSeenAt,
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence,
    status: finding.status,
    category: finding.category,
    cwe: finding.cwe,
    owaspCategory: finding.owaspCategory,
    affectedUrl: finding.affectedUrl,
    httpMethod: finding.httpMethod,
    parameter: finding.parameter,
    scannerName: finding.scannerName,
    scannerRuleId: finding.scannerRuleId,
    scannerVersion: finding.scannerVersion,
    fingerprint: finding.fingerprint,
    detectedAt: finding.detectedAt,
    impact: finding.impact,
    remediation: finding.remediation,
    reproductionSteps: finding.reproductionSteps,
    references: finding.references,
    evidence: finding.evidence.map((evidence) => ({
      id: evidence.id,
      type: evidence.type,
      title: evidence.title,
      sha256: evidence.sha256,
      artifactId: evidence.artifactId,
      metadata: evidence.metadata,
    })),
  }));

  const entries: ArchiveEntry[] = [
    jsonEntry("scan/scan.json", scan),
    jsonEntry("scan/summary.json", {
      exportedAt,
      metrics: reportMetrics(scan as unknown as ReportScanData),
      scan: {
        id: scan.id,
        originalUrl: scan.originalUrl,
        normalizedUrl: scan.normalizedUrl,
        finalUrl: scan.finalUrl,
        mode: scan.mode,
        status: scan.status,
        securityScore: scan.securityScore,
        coverageScore: scan.coverageScore,
        createdAt: scan.createdAt,
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
      },
    }),
    jsonEntry("route-inventory/routes.json", routeInventory),
    textEntry("route-inventory/routes.csv", routeInventoryCsv(routeInventory)),
    jsonEntry("route-inventory/targets.json", scan.targets),
    jsonEntry("findings/findings.json", findingRows),
    jsonEntry("scanner-logs/stages.json", scan.stages),
    textEntry("scanner-logs/stages.ndjson", scan.stages.map(jsonLine).join("")),
    jsonEntry("scanner-logs/worker-jobs.json", scan.jobs),
    jsonEntry("scanner-logs/reports.json", scan.reports),
    jsonEntry("scanner-logs/retests.json", scan.retests),
    jsonEntry("services/services.json", scan.services),
    jsonEntry("services/technologies.json", scan.technologies),
    jsonEntry("attack-paths/attack-paths.json", scan.attackPaths),
    jsonEntry("artifacts/artifacts.json", scan.artifacts),
  ];

  for (const finding of scan.findings) {
    const base = `findings/${safeFilename(finding.severity)}-${safeFilename(finding.id)}`;
    entries.push(jsonEntry(`${base}.json`, finding));
    for (const [index, evidence] of finding.evidence.entries()) {
      entries.push(
        textEntry(
          `${base}/evidence-${String(index + 1).padStart(2, "0")}-${safeFilename(evidence.type)}.txt`,
          [
            `title=${evidence.title}`,
            `type=${evidence.type}`,
            `sha256=${evidence.sha256}`,
            `artifactId=${evidence.artifactId ?? ""}`,
            "",
            evidence.content ?? "",
          ].join("\n"),
        ),
      );
    }
  }

  for (const artifact of scan.artifacts) {
    entries.push(...artifactEntries(artifact));
  }

  const screenshotManifest = screenshotEntries(scan.artifacts);
  entries.push(jsonEntry("screenshots/manifest.json", screenshotManifest));
  return entries;
}

function artifactEntries(artifact: {
  id: string;
  name: string;
  type: string;
  storageKey: string;
  sha256: string;
  size: number;
  contentType: string;
  metadata: unknown;
}) {
  const safeType = safeFilename(artifact.type.toLowerCase());
  if (artifact.type === "HTTP_EXCHANGE")
    return [
      jsonEntry(
        `request-response/${safeFilename(artifact.name)}`,
        artifact.metadata ?? artifact,
      ),
    ];

  if (artifact.type === "SCREENSHOT") {
    const metadata = artifact.metadata as
      | { contentBase64?: string; contentType?: string }
      | undefined;
    const entries: ArchiveEntry[] = [
      jsonEntry(`screenshots/${safeFilename(artifact.name)}.metadata.json`, {
        ...artifact,
        metadata: metadata
          ? {
              ...metadata,
              contentBase64: metadata.contentBase64
                ? "[stored as png file]"
                : undefined,
            }
          : undefined,
      }),
    ];
    if (metadata?.contentBase64)
      entries.push({
        name: `screenshots/${safeFilename(artifact.name)}`,
        content: Buffer.from(metadata.contentBase64, "base64"),
      });
    return entries;
  }

  return [
    jsonEntry(`artifacts/${safeType}/${safeFilename(artifact.name)}.json`, {
      ...artifact,
    }),
  ];
}

function screenshotEntries(
  artifacts: Array<{
    metadata: unknown;
    name: string;
    sha256: string;
    size: number;
    storageKey: string;
    type: string;
  }>,
) {
  return artifacts
    .filter((artifact) => artifact.type === "SCREENSHOT")
    .map((artifact) => {
      const metadata = artifact.metadata as
        | { archived?: boolean; url?: string }
        | undefined;
      return {
        name: artifact.name,
        storageKey: artifact.storageKey,
        url: metadata?.url,
        archived: metadata?.archived ?? false,
        sha256: artifact.sha256,
        size: artifact.size,
      };
    });
}

function manifestEntry(
  scan: {
    id: string;
    originalUrl: string;
    normalizedUrl: string;
    mode: string;
    status: string;
  },
  exportedAt: string,
  entries: ArchiveEntry[],
) {
  return jsonEntry("manifest.json", {
    format: "probeveil-evidence-archive-v2",
    exportedAt,
    limitation:
      "Archive contents are generated from persisted scan evidence. Request authentication headers are redacted before storage.",
    scan: {
      id: scan.id,
      originalUrl: scan.originalUrl,
      normalizedUrl: scan.normalizedUrl,
      mode: scan.mode,
      status: scan.status,
    },
    contents: entries.map((entry) => ({
      path: entry.name,
      size: contentBuffer(entry.content).byteLength,
      sha256: sha256(contentBuffer(entry.content)),
    })),
  });
}

function shaSumsEntry(entries: ArchiveEntry[]) {
  return textEntry(
    "hashes/sha256sums.txt",
    entries
      .map((entry) => `${sha256(contentBuffer(entry.content))}  ${entry.name}`)
      .join("\n")
      .concat("\n"),
  );
}

function jsonEntry(name: string, value: unknown): ArchiveEntry {
  return {
    name,
    content: JSON.stringify(value, null, 2),
  };
}

function textEntry(name: string, content: string): ArchiveEntry {
  return { name, content };
}

function contentBuffer(content: Buffer | string) {
  return typeof content === "string" ? Buffer.from(content) : content;
}

function jsonLine(value: unknown) {
  return `${JSON.stringify(value)}\n`;
}

function routeInventoryCsv(
  rows: Array<{
    contentType: string | null;
    discoveredBy: string;
    external: boolean;
    method: string;
    parameters: Array<{ name: string; location: string }>;
    statusCode: number | null;
    tested: boolean;
    url: string;
  }>,
) {
  return [
    [
      "method",
      "url",
      "status",
      "content_type",
      "tested",
      "external",
      "discovered_by",
      "parameters",
    ].join(","),
    ...rows.map((row) =>
      [
        row.method,
        row.url,
        row.statusCode ?? "",
        row.contentType ?? "",
        row.tested,
        row.external,
        row.discoveredBy,
        row.parameters
          .map((parameter) => `${parameter.location}:${parameter.name}`)
          .join("; "),
      ]
        .map(csvCell)
        .join(","),
    ),
  ].join("\n");
}

function csvCell(value: unknown) {
  const text = String(value);
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function sha256(value: Buffer | string) {
  return createHash("sha256").update(value).digest("hex");
}

function safeHostname(value: string) {
  try {
    return new URL(value).hostname.replace(/[^a-z0-9.-]+/gi, "-");
  } catch {
    return "scan";
  }
}

function safeFilename(value: string) {
  return (
    value
      .replaceAll("\\", "-")
      .replaceAll("/", "-")
      .replace(/[^a-z0-9._-]+/gi, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 120) || "item"
  );
}
