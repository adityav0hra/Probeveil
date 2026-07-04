const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const buckets = new Map<string, number[]>();

export function contactRateLimit(key: string) {
  const now = Date.now();
  const recent = (buckets.get(key) ?? []).filter(
    (time) => now - time < WINDOW_MS,
  );
  recent.push(now);
  buckets.set(key, recent);
  return recent.length <= MAX_ATTEMPTS;
}
