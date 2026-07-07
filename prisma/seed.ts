import { PrismaClient, Role, ScanMode } from "@prisma/client";
import { hash } from "bcryptjs";

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
  for (const mode of [ScanMode.QUICK, ScanMode.FULL, ScanMode.MAXIMUM]) {
    await prisma.scanProfile.upsert({
      where: { name: `${mode.toLowerCase()}-v1` },
      update: {},
      create: {
        name: `${mode.toLowerCase()}-v1`,
        mode,
        stageConfig: { passive: true, active: mode !== ScanMode.QUICK },
        limits: {
          routes:
            mode === ScanMode.QUICK ? 25 : mode === ScanMode.FULL ? 100 : 250,
        },
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
