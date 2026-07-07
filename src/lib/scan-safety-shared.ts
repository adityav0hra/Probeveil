export const dangerousPayloadClasses = [
  "destructive-state-change",
  "credential-bruteforce",
  "sql-time-delay",
  "command-execution",
  "stored-xss",
  "file-write",
  "ssrf-internal-network",
] as const;

export type ScanSafetyPolicy = {
  approvalId?: string;
  businessHours?: {
    days: number[];
    enabled: boolean;
    end: string;
    start: string;
    timezone: string;
  };
  excludedDangerousPayloadClasses: string[];
  maxRequestsPerScan: number;
  requestsPerMinute: number;
};

export function assertBusinessWindow(
  policy?: Partial<ScanSafetyPolicy>,
  date = new Date(),
) {
  const hours = policy?.businessHours;
  if (!hours?.enabled) return;
  if (!isWithinBusinessWindow(hours, date)) {
    throw new Error(
      `Target approval allows scans only during ${hours.start}-${hours.end} ${hours.timezone}.`,
    );
  }
}

export function isWithinBusinessWindow(
  hours: NonNullable<ScanSafetyPolicy["businessHours"]>,
  date = new Date(),
) {
  const parts = new Intl.DateTimeFormat("en-US", {
    hour: "2-digit",
    hourCycle: "h23",
    minute: "2-digit",
    timeZone: hours.timezone,
    weekday: "short",
  }).formatToParts(date);
  const weekday = weekdayNumber(part(parts, "weekday"));
  const minutes =
    Number(part(parts, "hour")) * 60 + Number(part(parts, "minute"));
  return (
    hours.days.includes(weekday) &&
    minutes >= timeToMinutes(hours.start) &&
    minutes <= timeToMinutes(hours.end)
  );
}

function timeToMinutes(value: string) {
  const [hour, minute] = value.split(":").map(Number);
  return (
    (Number.isFinite(hour) ? hour : 0) * 60 +
    (Number.isFinite(minute) ? minute : 0)
  );
}

function part(
  parts: Intl.DateTimeFormatPart[],
  type: Intl.DateTimeFormatPartTypes,
) {
  return parts.find((item) => item.type === type)?.value ?? "";
}

function weekdayNumber(value: string) {
  return { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 }[value] ?? 1;
}
