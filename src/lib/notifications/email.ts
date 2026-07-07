import "server-only";

import {
  emailFrom,
  emailReadiness,
  emailReplyTo,
  emailWebhookToken,
  emailWebhookUrl,
  envValue,
  notificationDefaultEmail,
} from "@/lib/email/config";

export type NotificationEmailResult = "SENT" | "FAILED" | "NOT_CONFIGURED";
export type NotificationEmailProvider = "WEBHOOK" | "RESEND" | "NONE";

export type NotificationEmailStatus = {
  configured: boolean;
  defaultRecipient: string | null;
  from: string | null;
  missing: string[];
  provider: NotificationEmailProvider;
  ready: boolean;
  replyTo: string | null;
  webhookConfigured: boolean;
};

export type NotificationEmailSendResult = {
  error?: string;
  provider: NotificationEmailProvider;
  status: NotificationEmailResult;
};

export function getNotificationEmailStatus(): NotificationEmailStatus {
  const readiness = emailReadiness("notification");
  return {
    configured: readiness.configured,
    defaultRecipient: readiness.defaultRecipient,
    from: readiness.from,
    missing: readiness.missing,
    provider: readiness.provider,
    ready: readiness.ready,
    replyTo: readiness.replyTo,
    webhookConfigured: readiness.webhookConfigured,
  };
}

async function sendViaWebhook(input: {
  subject: string;
  text: string;
  to: string;
}): Promise<NotificationEmailSendResult> {
  const url = emailWebhookUrl("notification");
  if (!url)
    return {
      provider: "WEBHOOK",
      status: "NOT_CONFIGURED",
    } satisfies NotificationEmailSendResult;

  const response = await fetch(url, {
    body: JSON.stringify({
      ...input,
      from: emailFrom("notification"),
      replyTo: emailReplyTo("notification"),
    }),
    headers: {
      "Content-Type": "application/json",
      ...(emailWebhookToken("notification")
        ? {
            Authorization: `Bearer ${emailWebhookToken("notification")}`,
          }
        : {}),
    },
    method: "POST",
  });
  return {
    error: response.ok ? undefined : `Webhook returned HTTP ${response.status}`,
    provider: "WEBHOOK",
    status: response.ok ? "SENT" : "FAILED",
  } satisfies NotificationEmailSendResult;
}

async function sendViaResend(input: {
  subject: string;
  text: string;
  to: string;
}): Promise<NotificationEmailSendResult> {
  const apiKey = envValue("RESEND_API_KEY");
  const from = emailFrom("notification");
  const replyTo = emailReplyTo("notification");
  if (!apiKey || !from)
    return {
      provider: "RESEND",
      status: "NOT_CONFIGURED",
    } satisfies NotificationEmailSendResult;

  const response = await fetch("https://api.resend.com/emails", {
    body: JSON.stringify({ from, reply_to: replyTo ?? undefined, ...input }),
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    method: "POST",
  });

  const errorText = response.ok
    ? undefined
    : await response.text().catch(() => "");
  if (!response.ok) {
    console.error("Notification email delivery failed", {
      provider: "resend",
      status: response.status,
      to: input.to,
    });
  }

  return {
    error: response.ok
      ? undefined
      : errorText || `Resend returned HTTP ${response.status}`,
    provider: "RESEND",
    status: response.ok ? "SENT" : "FAILED",
  } satisfies NotificationEmailSendResult;
}

export async function sendNotificationEmailDetailed(input: {
  subject: string;
  text: string;
  to?: string | null;
}): Promise<NotificationEmailSendResult> {
  const to = input.to || notificationDefaultEmail();
  if (!to)
    return {
      provider: "NONE",
      status: "NOT_CONFIGURED",
    } satisfies NotificationEmailSendResult;
  const webhookResult = await sendViaWebhook({
    subject: input.subject,
    text: input.text,
    to,
  });
  if (webhookResult.status !== "NOT_CONFIGURED") return webhookResult;
  return sendViaResend({
    subject: input.subject,
    text: input.text,
    to,
  });
}

export async function sendNotificationEmail(input: {
  subject: string;
  text: string;
  to?: string | null;
}): Promise<NotificationEmailResult> {
  return (await sendNotificationEmailDetailed(input)).status;
}
