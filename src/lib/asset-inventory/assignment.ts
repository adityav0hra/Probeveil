import "server-only";
import {
  AssetEventType,
  AssetKind,
  AssetStatus,
  type Prisma,
} from "@prisma/client";
import { db } from "@/lib/db";
import { assetIdentityKey, normalizeAssetUrl } from "@/lib/asset-inventory/key";

type AssetObservation = {
  hostname?: string;
  kind: AssetKind;
  label: string;
  metadata?: Record<string, unknown>;
  method?: string;
  port?: number;
  protocol?: string;
  technologyName?: string;
  technologyVersion?: string;
  url?: string;
  value: string;
};

export async function updateAssetInventoryForScan(scanId: string) {
  const scan = await db.scan.findUnique({
    include: {
      endpoints: { include: { parameters: true } },
      services: true,
      targets: true,
      technologies: true,
    },
    where: { id: scanId },
  });
  if (!scan || scan.status !== "COMPLETED") return;

  const observedAt = scan.completedAt ?? new Date();
  const observations = collectAssetObservations(scan);
  const observedIds = new Set<string>();

  for (const observation of observations) {
    const identityKey = assetIdentityKey({
      kind: observation.kind,
      method: observation.method,
      port: observation.port,
      protocol: observation.protocol,
      value: observation.value,
    });
    const existing = await db.assetInventoryItem.findUnique({
      where: {
        normalizedHash_kind_identityKey: {
          identityKey,
          kind: observation.kind,
          normalizedHash: scan.normalizedHash,
        },
      },
    });
    const changed = existing
      ? metadataChanged(existing.metadata, observation.metadata) ||
        existing.label !== observation.label ||
        existing.status === AssetStatus.MISSING
      : false;
    const asset = existing
      ? await db.assetInventoryItem.update({
          where: { id: existing.id },
          data: {
            hostname: observation.hostname,
            label: observation.label,
            lastChangedAt: changed ? observedAt : existing.lastChangedAt,
            lastMissingAt:
              existing.status === AssetStatus.MISSING
                ? null
                : existing.lastMissingAt,
            lastScanId: scan.id,
            lastSeenAt: observedAt,
            metadata: observation.metadata as Prisma.InputJsonValue,
            method: observation.method,
            observationCount: { increment: 1 },
            port: observation.port,
            protocol: observation.protocol,
            status: AssetStatus.ACTIVE,
            technologyName: observation.technologyName,
            technologyVersion: observation.technologyVersion,
            url: observation.url,
            value: observation.value,
          },
        })
      : await db.assetInventoryItem.create({
          data: {
            firstSeenAt: observedAt,
            hostname: observation.hostname,
            identityKey,
            kind: observation.kind,
            label: observation.label,
            lastScanId: scan.id,
            lastSeenAt: observedAt,
            metadata: observation.metadata as Prisma.InputJsonValue,
            method: observation.method,
            normalizedHash: scan.normalizedHash,
            observationCount: 1,
            port: observation.port,
            protocol: observation.protocol,
            status: AssetStatus.ACTIVE,
            technologyName: observation.technologyName,
            technologyVersion: observation.technologyVersion,
            url: observation.url,
            value: observation.value,
          },
        });
    observedIds.add(asset.id);
    await db.assetInventoryEvent.create({
      data: {
        assetId: asset.id,
        eventType: existing
          ? changed
            ? AssetEventType.CHANGED
            : AssetEventType.OBSERVED
          : AssetEventType.DISCOVERED,
        metadata: observation.metadata as Prisma.InputJsonValue,
        nextStatus: AssetStatus.ACTIVE,
        previousStatus: existing?.status,
        scanId: scan.id,
        summary: existing
          ? changed
            ? `${assetLabel(observation.kind)} changed in scan ${scan.id}.`
            : `${assetLabel(observation.kind)} observed again in scan ${scan.id}.`
          : `${assetLabel(observation.kind)} discovered in scan ${scan.id}.`,
      },
    });
  }

  const missing = await db.assetInventoryItem.findMany({
    where: {
      id: { notIn: [...observedIds] },
      normalizedHash: scan.normalizedHash,
      status: AssetStatus.ACTIVE,
    },
  });
  for (const asset of missing) {
    await db.assetInventoryItem.update({
      where: { id: asset.id },
      data: {
        lastMissingAt: observedAt,
        lastScanId: scan.id,
        status: AssetStatus.MISSING,
      },
    });
    await db.assetInventoryEvent.create({
      data: {
        assetId: asset.id,
        eventType: AssetEventType.MISSING,
        nextStatus: AssetStatus.MISSING,
        previousStatus: asset.status,
        scanId: scan.id,
        summary: `${assetLabel(asset.kind)} was not observed in completed scan ${scan.id}.`,
      },
    });
  }
}

function collectAssetObservations(scan: {
  endpoints: Array<{
    contentType: string | null;
    depth: number;
    discoveredBy: string;
    external: boolean;
    method: string;
    parameters: Array<{ dataType: string | null; location: string; name: string }>;
    statusCode: number | null;
    tested: boolean;
    title: string | null;
    url: string;
  }>;
  normalizedUrl: string;
  services: Array<{
    external: boolean;
    host: string;
    ip: string | null;
    port: number | null;
    protocol: string;
    tls: unknown;
  }>;
  targets: Array<{
    hostname: string;
    inScope: boolean;
    kind: string;
    reason: string | null;
    url: string;
  }>;
  technologies: Array<{
    category: string | null;
    evidence: string | null;
    name: string;
    version: string | null;
  }>;
}) {
  const observations = new Map<string, AssetObservation>();
  const add = (observation: AssetObservation) => {
    const key = assetIdentityKey({
      kind: observation.kind,
      method: observation.method,
      port: observation.port,
      protocol: observation.protocol,
      value: observation.value,
    });
    if (!observations.has(key)) observations.set(key, observation);
  };

  for (const target of scan.targets) {
    add({
      hostname: target.hostname,
      kind: AssetKind.DOMAIN,
      label: target.hostname,
      metadata: {
        inScope: target.inScope,
        kind: target.kind,
        reason: target.reason,
        url: target.url,
      },
      url: target.url,
      value: target.hostname.toLowerCase(),
    });
  }
  try {
    const root = new URL(scan.normalizedUrl);
    add({
      hostname: root.hostname,
      kind: AssetKind.DOMAIN,
      label: root.hostname,
      metadata: { source: "scan-root", url: scan.normalizedUrl },
      url: scan.normalizedUrl,
      value: root.hostname.toLowerCase(),
    });
  } catch {}

  for (const endpoint of scan.endpoints) {
    const url = parseUrl(endpoint.url);
    const normalizedUrl = normalizeAssetUrl(endpoint.url);
    if (url)
      add({
        hostname: url.hostname,
        kind: AssetKind.DOMAIN,
        label: url.hostname,
        metadata: { source: "endpoint", url: normalizedUrl },
        url: `${url.protocol}//${url.hostname}/`,
        value: url.hostname.toLowerCase(),
      });
    add({
      hostname: url?.hostname,
      kind: AssetKind.ENDPOINT,
      label: endpointLabel(endpoint.method, normalizedUrl),
      metadata: endpointMetadata(endpoint),
      method: endpoint.method,
      url: normalizedUrl,
      value: normalizedUrl,
    });
    if (isApiEndpoint(endpoint))
      add({
        hostname: url?.hostname,
        kind: AssetKind.API,
        label: endpointLabel(endpoint.method, normalizedUrl),
        metadata: endpointMetadata(endpoint),
        method: endpoint.method,
        url: normalizedUrl,
        value: normalizedUrl,
      });
    if (url && isLoginRoute(url.pathname))
      add({
        hostname: url.hostname,
        kind: AssetKind.LOGIN_PAGE,
        label: endpointLabel(endpoint.method, normalizedUrl),
        metadata: endpointMetadata(endpoint),
        method: endpoint.method,
        url: normalizedUrl,
        value: normalizedUrl,
      });
    if (url && isAdminRoute(url.pathname))
      add({
        hostname: url.hostname,
        kind: AssetKind.ADMIN_ROUTE,
        label: endpointLabel(endpoint.method, normalizedUrl),
        metadata: endpointMetadata(endpoint),
        method: endpoint.method,
        url: normalizedUrl,
        value: normalizedUrl,
      });
  }

  for (const service of scan.services)
    add({
      hostname: service.host,
      kind: AssetKind.SERVICE,
      label: `${service.protocol.toUpperCase()} ${service.host}${service.port ? `:${service.port}` : ""}`,
      metadata: {
        external: service.external,
        ip: service.ip,
        tls: service.tls,
      },
      port: service.port ?? undefined,
      protocol: service.protocol,
      value: `${service.host}:${service.port ?? ""}:${service.protocol}`,
    });

  for (const technology of scan.technologies)
    add({
      kind: AssetKind.TECHNOLOGY,
      label: technology.version
        ? `${technology.name} ${technology.version}`
        : technology.name,
      metadata: {
        category: technology.category,
        evidence: technology.evidence,
      },
      technologyName: technology.name,
      technologyVersion: technology.version ?? undefined,
      value: `${technology.name}:${technology.version ?? "detected"}`,
    });

  return [...observations.values()];
}

function endpointMetadata(endpoint: {
  contentType: string | null;
  depth: number;
  discoveredBy: string;
  external: boolean;
  parameters: Array<{ dataType: string | null; location: string; name: string }>;
  statusCode: number | null;
  tested: boolean;
  title: string | null;
}) {
  return {
    contentType: endpoint.contentType,
    depth: endpoint.depth,
    discoveredBy: endpoint.discoveredBy,
    external: endpoint.external,
    parameterCount: endpoint.parameters.length,
    parameters: endpoint.parameters.slice(0, 50),
    statusCode: endpoint.statusCode,
    tested: endpoint.tested,
    title: endpoint.title,
  };
}

function metadataChanged(previous: Prisma.JsonValue | null, next?: Record<string, unknown>) {
  return JSON.stringify(previous ?? null) !== JSON.stringify(next ?? null);
}

function parseUrl(value: string) {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

function endpointLabel(method: string, url: string) {
  return `${method.toUpperCase()} ${url}`;
}

function isApiEndpoint(endpoint: { contentType: string | null; url: string }) {
  const url = parseUrl(endpoint.url);
  const path = url?.pathname.toLowerCase() ?? endpoint.url.toLowerCase();
  return (
    /\/(?:api|graphql|rest|v\d+)(?:\/|$)/i.test(path) ||
    /(?:openapi|swagger)\.(?:json|ya?ml)$/i.test(path) ||
    endpoint.contentType?.includes("json") === true
  );
}

function isLoginRoute(pathname: string) {
  return /\/(?:login|signin|sign-in|auth|account|portal)(?:\/|$)/i.test(
    pathname,
  );
}

function isAdminRoute(pathname: string) {
  return /\/(?:admin|dashboard|settings|users?|roles?|permissions|billing|invoices|exports?|reports?|audit)(?:\/|$)/i.test(
    pathname,
  );
}

function assetLabel(kind: AssetKind) {
  return kind.replaceAll("_", " ").toLowerCase();
}
