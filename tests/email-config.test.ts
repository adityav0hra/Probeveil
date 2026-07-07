import { afterEach, describe, expect, it } from "vitest";
import { emailReadiness, notificationDefaultEmail } from "@/lib/email/config";

const keys = [
  "CONTACT_ADMIN_EMAIL",
  "CONTACT_EMAIL_FROM",
  "CONTACT_EMAIL_WEBHOOK_URL",
  "CONTACT_EMAIL_REPLY_TO",
  "EMAIL_FROM",
  "EMAIL_REPLY_TO",
  "NOTIFICATION_DEFAULT_EMAIL",
  "NOTIFICATION_EMAIL_FROM",
  "NOTIFICATION_EMAIL_REPLY_TO",
  "NOTIFICATION_EMAIL_WEBHOOK_URL",
  "RESEND_API_KEY",
] as const;

const original = Object.fromEntries(keys.map((key) => [key, process.env[key]]));

afterEach(() => {
  for (const key of keys) {
    const value = original[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("email provider config", () => {
  it("uses the contact admin email as the notification fallback", () => {
    for (const key of keys) delete process.env[key];
    process.env.CONTACT_ADMIN_EMAIL = "owner@example.com";

    expect(notificationDefaultEmail()).toBe("owner@example.com");
  });

  it("marks notification email ready with Resend and a recipient", () => {
    for (const key of keys) delete process.env[key];
    process.env.CONTACT_ADMIN_EMAIL = "owner@example.com";
    process.env.RESEND_API_KEY = "re_test";

    const readiness = emailReadiness("notification");

    expect(readiness.ready).toBe(true);
    expect(readiness.provider).toBe("RESEND");
    expect(readiness.defaultRecipient).toBe("owner@example.com");
  });

  it("reports the missing provider when no email transport is configured", () => {
    for (const key of keys) delete process.env[key];
    process.env.CONTACT_ADMIN_EMAIL = "owner@example.com";

    const readiness = emailReadiness("notification");

    expect(readiness.ready).toBe(false);
    expect(readiness.missing).toContain(
      "RESEND_API_KEY or NOTIFICATION_EMAIL_WEBHOOK_URL",
    );
  });
});
