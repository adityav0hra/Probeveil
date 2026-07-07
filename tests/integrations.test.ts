import { afterEach, describe, expect, it } from "vitest";
import { getIntegrationStatuses } from "@/lib/integrations/status";

const keys = [
  "SLACK_WEBHOOK_URL",
  "DISCORD_WEBHOOK_URL",
  "TEAMS_WEBHOOK_URL",
  "JIRA_BASE_URL",
  "JIRA_EMAIL",
  "JIRA_API_TOKEN",
  "JIRA_PROJECT_KEY",
  "LINEAR_API_KEY",
  "LINEAR_TEAM_ID",
  "GITHUB_ISSUES_TOKEN",
  "GITHUB_ISSUES_REPO",
  "RESEND_API_KEY",
  "NOTIFICATION_EMAIL_WEBHOOK_URL",
] as const;

const original = Object.fromEntries(keys.map((key) => [key, process.env[key]]));

afterEach(() => {
  for (const key of keys) {
    const value = original[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("integration provider status", () => {
  it("reports missing providers when credentials are absent", () => {
    for (const key of keys) delete process.env[key];

    expect(getIntegrationStatuses().every((status) => !status.configured)).toBe(
      true,
    );
  });

  it("reports configured webhooks and work trackers", () => {
    process.env.SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/test";
    process.env.DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/test";
    process.env.TEAMS_WEBHOOK_URL = "https://example.webhook.office.com/test";
    process.env.JIRA_BASE_URL = "https://example.atlassian.net";
    process.env.JIRA_EMAIL = "security@example.com";
    process.env.JIRA_API_TOKEN = "token";
    process.env.JIRA_PROJECT_KEY = "SEC";
    process.env.LINEAR_API_KEY = "lin_api_key";
    process.env.LINEAR_TEAM_ID = "team_id";
    process.env.GITHUB_ISSUES_TOKEN = "ghp_token";
    process.env.GITHUB_ISSUES_REPO = "owner/repo";
    process.env.RESEND_API_KEY = "re_test";

    const statuses = getIntegrationStatuses();

    expect(statuses.filter((status) => status.configured)).toHaveLength(7);
    expect(statuses.find((status) => status.provider === "JIRA")?.target).toBe(
      "SEC",
    );
    expect(
      statuses.find((status) => status.provider === "GITHUB")?.target,
    ).toBe("owner/repo");
  });
});
