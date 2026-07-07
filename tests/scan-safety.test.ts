import { describe, expect, it } from "vitest";
import { isWithinBusinessWindow } from "../src/lib/scan-safety-shared";

describe("scan safety controls", () => {
  it("allows scans inside the approved business window", () => {
    expect(
      isWithinBusinessWindow(
        {
          days: [1, 2, 3, 4, 5],
          enabled: true,
          end: "17:00",
          start: "09:00",
          timezone: "Australia/Sydney",
        },
        new Date("2026-07-07T02:00:00.000Z"),
      ),
    ).toBe(true);
  });

  it("blocks scans outside the approved business window", () => {
    expect(
      isWithinBusinessWindow(
        {
          days: [1, 2, 3, 4, 5],
          enabled: true,
          end: "17:00",
          start: "09:00",
          timezone: "Australia/Sydney",
        },
        new Date("2026-07-07T12:00:00.000Z"),
      ),
    ).toBe(false);
  });
});
