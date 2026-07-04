import { describe, expect, it } from "vitest";
import { signWorkerToken, verifyWorkerToken } from "@/lib/worker-token";
describe("worker tokens", () => { it("binds callbacks to scan IDs", () => { const token = signWorkerToken("scan-1"); expect(verifyWorkerToken(token, "scan-1")).toBe(true); expect(verifyWorkerToken(token, "scan-2")).toBe(false); }); it("expires old tokens", () => expect(verifyWorkerToken(signWorkerToken("scan", 1), "scan")).toBe(false)); });
