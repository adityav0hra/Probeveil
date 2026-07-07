import { IntegrationProvider } from "@prisma/client";

export type ProviderStatus = {
  configured: boolean;
  label: string;
  provider: IntegrationProvider;
  target: string;
  type: "email" | "issue" | "webhook";
};

export function getIntegrationStatuses(): ProviderStatus[] {
  const emailConfigured = Boolean(
    process.env.RESEND_API_KEY || process.env.NOTIFICATION_EMAIL_WEBHOOK_URL,
  );
  return [
    {
      configured: Boolean(process.env.SLACK_WEBHOOK_URL),
      label: "Slack webhook",
      provider: IntegrationProvider.SLACK,
      target: webhookTarget(process.env.SLACK_WEBHOOK_URL),
      type: "webhook",
    },
    {
      configured: Boolean(process.env.DISCORD_WEBHOOK_URL),
      label: "Discord webhook",
      provider: IntegrationProvider.DISCORD,
      target: webhookTarget(process.env.DISCORD_WEBHOOK_URL),
      type: "webhook",
    },
    {
      configured: Boolean(process.env.TEAMS_WEBHOOK_URL),
      label: "Microsoft Teams webhook",
      provider: IntegrationProvider.TEAMS,
      target: webhookTarget(process.env.TEAMS_WEBHOOK_URL),
      type: "webhook",
    },
    {
      configured: jiraConfigured(),
      label: "Jira issue creation",
      provider: IntegrationProvider.JIRA,
      target: process.env.JIRA_PROJECT_KEY ?? "Missing project",
      type: "issue",
    },
    {
      configured: Boolean(
        process.env.LINEAR_API_KEY && process.env.LINEAR_TEAM_ID,
      ),
      label: "Linear issue creation",
      provider: IntegrationProvider.LINEAR,
      target: process.env.LINEAR_TEAM_ID ?? "Missing team",
      type: "issue",
    },
    {
      configured: Boolean(
        process.env.GITHUB_ISSUES_TOKEN && process.env.GITHUB_ISSUES_REPO,
      ),
      label: "GitHub Issues",
      provider: IntegrationProvider.GITHUB,
      target: process.env.GITHUB_ISSUES_REPO ?? "Missing repo",
      type: "issue",
    },
    {
      configured: emailConfigured,
      label: "Email summaries",
      provider: IntegrationProvider.EMAIL,
      target: emailConfigured
        ? (process.env.NOTIFICATION_EMAIL_FROM ??
          process.env.CONTACT_EMAIL_FROM ??
          "Probeveil <onboarding@resend.dev>")
        : "Missing provider",
      type: "email",
    },
  ];
}

function jiraConfigured() {
  return Boolean(
    process.env.JIRA_BASE_URL &&
      process.env.JIRA_EMAIL &&
      process.env.JIRA_API_TOKEN &&
      process.env.JIRA_PROJECT_KEY,
  );
}

function webhookTarget(value?: string) {
  if (!value) return "Missing webhook";
  try {
    return new URL(value).hostname;
  } catch {
    return "Configured webhook";
  }
}
