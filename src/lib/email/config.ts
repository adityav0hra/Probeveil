export type EmailProvider = "RESEND" | "WEBHOOK" | "NONE";
export type EmailChannel = "contact" | "notification";

export type EmailReadiness = {
  configured: boolean;
  defaultRecipient: string | null;
  from: string | null;
  missing: string[];
  provider: EmailProvider;
  ready: boolean;
  replyTo: string | null;
  resendConfigured: boolean;
  webhookConfigured: boolean;
};

const fallbackFrom = "Probeveil <onboarding@resend.dev>";

export function envValue(key: string) {
  const value = process.env[key]?.trim();
  return value ? value : undefined;
}

export function contactAdminEmail() {
  return envValue("CONTACT_ADMIN_EMAIL");
}

export function notificationDefaultEmail() {
  return envValue("NOTIFICATION_DEFAULT_EMAIL") ?? contactAdminEmail();
}

export function emailFrom(channel: EmailChannel) {
  if (channel === "notification") {
    return (
      envValue("NOTIFICATION_EMAIL_FROM") ??
      envValue("EMAIL_FROM") ??
      envValue("CONTACT_EMAIL_FROM") ??
      fallbackFrom
    );
  }
  return (
    envValue("CONTACT_EMAIL_FROM") ??
    envValue("EMAIL_FROM") ??
    envValue("NOTIFICATION_EMAIL_FROM") ??
    fallbackFrom
  );
}

export function emailReplyTo(channel: EmailChannel) {
  if (channel === "notification") {
    return (
      envValue("NOTIFICATION_EMAIL_REPLY_TO") ??
      envValue("EMAIL_REPLY_TO") ??
      contactAdminEmail() ??
      null
    );
  }
  return (
    envValue("CONTACT_EMAIL_REPLY_TO") ??
    envValue("EMAIL_REPLY_TO") ??
    contactAdminEmail() ??
    null
  );
}

export function emailWebhookUrl(channel: EmailChannel) {
  if (channel === "notification")
    return envValue("NOTIFICATION_EMAIL_WEBHOOK_URL");
  return envValue("CONTACT_EMAIL_WEBHOOK_URL");
}

export function emailWebhookToken(channel: EmailChannel) {
  if (channel === "notification")
    return envValue("NOTIFICATION_EMAIL_WEBHOOK_TOKEN");
  return envValue("CONTACT_EMAIL_WEBHOOK_TOKEN");
}

export function emailProvider(channel: EmailChannel): EmailProvider {
  if (emailWebhookUrl(channel)) return "WEBHOOK";
  if (envValue("RESEND_API_KEY")) return "RESEND";
  return "NONE";
}

export function emailReadiness(channel: EmailChannel): EmailReadiness {
  const provider = emailProvider(channel);
  const from = emailFrom(channel);
  const defaultRecipient =
    channel === "notification"
      ? notificationDefaultEmail()
      : contactAdminEmail();
  const missing: string[] = [];

  if (provider === "NONE") {
    missing.push(
      channel === "notification"
        ? "RESEND_API_KEY or NOTIFICATION_EMAIL_WEBHOOK_URL"
        : "RESEND_API_KEY or CONTACT_EMAIL_WEBHOOK_URL",
    );
  }
  if (!from) {
    missing.push(
      channel === "notification"
        ? "NOTIFICATION_EMAIL_FROM"
        : "CONTACT_EMAIL_FROM",
    );
  }
  if (!defaultRecipient) {
    missing.push(
      channel === "notification"
        ? "NOTIFICATION_DEFAULT_EMAIL or CONTACT_ADMIN_EMAIL"
        : "CONTACT_ADMIN_EMAIL",
    );
  }

  return {
    configured: provider !== "NONE",
    defaultRecipient: defaultRecipient ?? null,
    from: from ?? null,
    missing,
    provider,
    ready: missing.length === 0,
    replyTo: emailReplyTo(channel),
    resendConfigured: Boolean(envValue("RESEND_API_KEY")),
    webhookConfigured: Boolean(emailWebhookUrl(channel)),
  };
}
