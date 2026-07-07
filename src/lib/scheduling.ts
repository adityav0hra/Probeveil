export type ScheduleCadenceValue = "WEEKLY" | "MONTHLY";

export type FindingDiffInput = {
  affectedUrl: string | null;
  parameter?: string | null;
  scannerRuleId: string;
  severity: string;
  title: string;
};

export function nextScheduledRun(
  cadence: ScheduleCadenceValue,
  from = new Date(),
) {
  const next = new Date(from);
  if (cadence === "WEEKLY") {
    next.setUTCDate(next.getUTCDate() + 7);
    return next;
  }

  const day = next.getUTCDate();
  next.setUTCMonth(next.getUTCMonth() + 1, 1);
  const lastDay = new Date(
    Date.UTC(next.getUTCFullYear(), next.getUTCMonth() + 1, 0),
  ).getUTCDate();
  next.setUTCDate(Math.min(day, lastDay));
  return next;
}

export function findingDiffKey(finding: FindingDiffInput) {
  return [
    finding.scannerRuleId.trim().toLowerCase(),
    comparableUrl(finding.affectedUrl),
    finding.parameter?.trim().toLowerCase() ?? "",
    finding.title.trim().toLowerCase(),
  ].join("|");
}

export function diffFindings(
  current: FindingDiffInput[],
  previous: FindingDiffInput[],
) {
  const previousKeys = new Set(previous.map(findingDiffKey));
  const currentKeys = new Set(current.map(findingDiffKey));
  return {
    fixedFindings: previous.filter(
      (finding) => !currentKeys.has(findingDiffKey(finding)),
    ),
    newFindings: current.filter(
      (finding) => !previousKeys.has(findingDiffKey(finding)),
    ),
  };
}

function comparableUrl(value: string | null) {
  if (!value) return "";
  try {
    const url = new URL(value);
    url.hash = "";
    return `${url.hostname.toLowerCase()}${url.pathname}${url.search}`;
  } catch {
    return value.trim().toLowerCase();
  }
}
