import { describe, expect, it } from "vitest";
import { createZip } from "../src/lib/zip";

describe("createZip", () => {
  it("creates a readable store-method zip archive", () => {
    const archive = createZip([
      { name: "manifest.json", content: '{"ok":true}' },
      { name: "evidence/http.json", content: "request-response" },
    ]);
    const text = archive.toString("latin1");

    expect(archive.subarray(0, 4).toString("hex")).toBe("504b0304");
    expect(text).toContain("manifest.json");
    expect(text).toContain("evidence/http.json");
    expect(text).toContain("PK\u0005\u0006");
  });
});
