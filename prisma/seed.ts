import { PrismaClient, Role } from "@prisma/client";
import { hash } from "bcryptjs";
import { defaultScanProfiles } from "../src/lib/scan-profiles";

const prisma = new PrismaClient();

async function main() {
  const email = process.env.SEED_ADMIN_EMAIL ?? "admin@example.com";
  const password =
    process.env.SEED_ADMIN_PASSWORD ?? "change-me-before-production";
  await prisma.user.upsert({
    where: { email },
    update: { name: "Security Admin", role: Role.ADMIN },
    create: {
      email,
      name: "Security Admin",
      role: Role.ADMIN,
      passwordHash: await hash(password, 12),
    },
  });
  await prisma.scanProfile.updateMany({
    data: { enabled: false },
    where: { name: { in: ["quick-v1", "full-v1", "maximum-v1"] } },
  });
  for (const profile of defaultScanProfiles) {
    await prisma.scanProfile.upsert({
      where: { slug: profile.slug },
      update: {
        alertThresholds: profile.alertThresholds,
        authConfig: profile.authConfig,
        cadence: profile.cadence,
        description: profile.description,
        enabled: true,
        engines: profile.engines,
        features: profile.features,
        limits: profile.limits,
        mode: profile.mode,
        name: profile.name,
        stageConfig: profile.stageConfig,
      },
      create: {
        alertThresholds: profile.alertThresholds,
        authConfig: profile.authConfig,
        cadence: profile.cadence,
        description: profile.description,
        engines: profile.engines,
        features: profile.features,
        limits: profile.limits,
        mode: profile.mode,
        name: profile.name,
        slug: profile.slug,
        stageConfig: profile.stageConfig,
      },
    });
  }
  await prisma.scannerTool.upsert({
    where: { name: "Probeveil Passive" },
    update: { enabled: true, version: "1.0.0" },
    create: {
      name: "Probeveil Passive",
      version: "1.0.0",
      kind: "PASSIVE_HTTP",
      capabilities: [
        "dns",
        "tls",
        "headers",
        "cookies",
        "cors",
        "csp",
        "crawl",
      ],
    },
  });
  await prisma.scannerTool.upsert({
    where: { name: "Nuclei" },
    update: { enabled: true, version: "external-cli" },
    create: {
      name: "Nuclei",
      version: "external-cli",
      kind: "TEMPLATE_HTTP",
      capabilities: [
        "cves",
        "exposures",
        "misconfigurations",
        "default credentials",
        "known vulnerable components",
      ],
    },
  });
  await prisma.scannerTool.upsert({
    where: { name: "Adaptive Differential Probes" },
    update: { enabled: true, version: "1.0.0" },
    create: {
      name: "Adaptive Differential Probes",
      version: "1.0.0",
      kind: "PROBEVEIL_ACTIVE_SAFE",
      capabilities: [
        "method comparison",
        "header variation",
        "parameter mutation",
        "manual-review prioritization",
      ],
    },
  });
  for (const tool of [
    {
      name: "Nikto",
      kind: "WEB_SERVER_BASELINE",
      capabilities: ["server diagnostics", "dangerous files", "legacy checks"],
    },
    {
      name: "testssl.sh",
      kind: "TLS_DIAGNOSTIC",
      capabilities: ["tls posture", "certificate checks", "cipher review"],
    },
    {
      name: "OWASP ZAP Baseline",
      kind: "DAST_BASELINE",
      capabilities: ["passive DAST", "headers", "browser-era web checks"],
    },
    {
      name: "SSLyze",
      kind: "TLS_DIAGNOSTIC",
      capabilities: ["tls posture", "certificate checks", "protocol review"],
    },
    {
      name: "Semgrep",
      kind: "SOURCE_HINTS",
      capabilities: [
        "downloaded JavaScript review",
        "DOM sink hints",
        "dynamic code execution hints",
      ],
    },
    {
      name: "Probeveil Nikto-style Checks",
      kind: "PROBEVEIL_ACTIVE_SAFE",
      capabilities: [
        "diagnostic paths",
        "legacy web-server checks",
        "admin surface review",
      ],
    },
    {
      name: "Probeveil Technology Checks",
      kind: "PROBEVEIL_ACTIVE_SAFE",
      capabilities: [
        "Next.js review",
        "WordPress review",
        "Spring/OpenAPI review",
        "GraphQL review",
      ],
    },
  ]) {
    await prisma.scannerTool.upsert({
      where: { name: tool.name },
      update: { enabled: true, version: "external-cli" },
      create: {
        name: tool.name,
        version: "external-cli",
        kind: tool.kind,
        capabilities: tool.capabilities,
      },
    });
  }
}

main().finally(() => prisma.$disconnect());
