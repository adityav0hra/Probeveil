import { isIP } from "node:net";

const blockedV4 = [
  /^0\./,
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^192\.168\./,
  /^224\./,
  /^25[0-5]\./,
];

export function isPrivateAddress(address: string) {
  if (isIP(address) === 4) {
    if (blockedV4.some((pattern) => pattern.test(address))) return true;
    const [a, b] = address.split(".").map(Number);
    return (
      (a === 172 && b >= 16 && b <= 31) || (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (isIP(address) === 6) {
    const value = address.toLowerCase();
    return (
      value === "::1" ||
      value === "::" ||
      value.startsWith("fc") ||
      value.startsWith("fd") ||
      value.startsWith("fe8") ||
      value.startsWith("fe9") ||
      value.startsWith("fea") ||
      value.startsWith("feb")
    );
  }
  return true;
}

export function hostMatchesAllowlist(
  hostname: string,
  entries = (process.env.SCAN_ALLOWED_HOSTS ?? "").split(","),
) {
  return entries
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean)
    .some((entry) =>
      entry.startsWith(".") ? hostname.endsWith(entry) : hostname === entry,
    );
}

export function assertAddressesAllowed(
  hostname: string,
  addresses: string[],
  allowPrivate = process.env.SCAN_ALLOW_PRIVATE_NETWORKS === "true",
) {
  if (addresses.length === 0)
    throw new Error("The target hostname did not resolve.");
  if (
    addresses.some(isPrivateAddress) &&
    !(allowPrivate && hostMatchesAllowlist(hostname))
  ) {
    throw new Error(
      "The target resolves to a private or reserved network outside the configured scope.",
    );
  }
}
