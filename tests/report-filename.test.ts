import { describe, expect, it } from "vitest";
import {
  buildReportFilename,
  contentDisposition,
  hostnameFromScanUrl,
  sanitiseWebsiteName,
} from "../src/lib/reports/filename";

describe("report filename utilities", () => {
  it("extracts canonical hostnames without paths, query strings or fragments", () => {
    expect(
      hostnameFromScanUrl("https://store.example.com/dashboard?x=1#frag"),
    ).toBe("store.example.com");
  });

  it("sanitises hostnames for cross-platform filenames", () => {
    expect(sanitiseWebsiteName("store.example.com")).toBe("store-example-com");
    expect(sanitiseWebsiteName("..a---b.example.com..")).toBe(
      "a-b-example-com",
    );
  });

  it("handles unicode hostnames through ASCII domain conversion", () => {
    expect(sanitiseWebsiteName("bücher.example")).toBe("xn-bcher-kva-example");
  });

  it("falls back safely for invalid hostnames", () => {
    expect(sanitiseWebsiteName("")).toBe("unknown-website");
    expect(hostnameFromScanUrl("://bad")).toBeNull();
  });

  it("builds executive and technical report filenames", () => {
    expect(
      buildReportFilename({
        completedAt: "2026-07-04T02:30:00.000Z",
        kind: "executive",
        productName: "WebGuard",
        url: "https://store.example.com/dashboard",
      }),
    ).toBe(
      "WebGuard-store-example-com-Executive-Security-Report-2026-07-04.pdf",
    );
    expect(
      buildReportFilename({
        completedAt: "2026-07-04T02:30:00.000Z",
        kind: "technical",
        productName: "WebGuard",
        url: "https://example.com",
      }),
    ).toBe(
      "WebGuard-example-com-Full-Technical-Security-Report-2026-07-04.pdf",
    );
  });

  it("emits safe content disposition headers", () => {
    const header = contentDisposition(
      "WebGuard-example-com-Executive-Security-Report-2026-07-04.pdf",
    );
    expect(header).toContain("attachment;");
    expect(header).toContain("filename=");
    expect(header).toContain("filename*=");
  });
});
