import "server-only";

export type NotificationEmailResult = "SENT" | "FAILED" | "NOT_CONFIGURED";
export type NotificationEmailProvider = "WEBHOOK" | "RESEND" | "NONE";

export type NotificationEmailStatus = {
  configured: boolean;
  from: string | null;
  provider: NotificationEmailProvider;
  webhookConfigured: boolean;
};

export type NotificationEmailSendResult = {
  error?: string;
  provider: NotificationEmailProvider;
  status: NotificationEmailResult;
};

function fromAddress() {
  return (
    process.env.NOTIFICATION_EMAIL_FROM ??
    process.env.CONTACT_EMAIL_FROM ??
    "Probeveil <onboarding@resend.dev>"
  );
}

export function getNotificationEmailStatus(): NotificationEmailStatus {
  const webhookConfigured = Boolean(process.env.NOTIFICATION_EMAIL_WEBHOOK_URL);
  const resendConfigured = Boolean(process.env.RESEND_API_KEY);
  return {
    configured: webhookConfigured || resendConfigured,
    from: webhookConfigured || resendConfigured ? fromAddress() : null,
    provider: webhookConfigured
      ? "WEBHOOK"
      : resendConfigured
        ? "RESEND"
        : "NONE",
    webhookConfigured,
  };
}

async function sendViaWebhook(input: {
  subject: string;
  text: string;
  to: string;
}): Promise<NotificationEmailSendResult> {
  const url = process.env.NOTIFICATION_EMAIL_WEBHOOK_URL;
  if (!url)
    return {
      provider: "WEBHOOK",
      status: "NOT_CONFIGURED",
    } satisfies NotificationEmailSendResult;

  const response = await fetch(url, {
    body: JSON.stringify(input),
    headers: {
      "Content-Type": "application/json",
      ...(process.env.NOTIFICATION_EMAIL_WEBHOOK_TOKEN
        ? {
            Authorization: `Bearer ${process.env.NOTIFICATION_EMAIL_WEBHOOK_TOKEN}`,
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
  const apiKey = process.env.RESEND_API_KEY;
  const from = fromAddress();
  if (!apiKey || !from)
    return {
      provider: "RESEND",
      status: "NOT_CONFIGURED",
    } satisfies NotificationEmailSendResult;

  const response = await fetch("https://api.resend.com/emails", {
    body: JSON.stringify({ from, ...input }),
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
  if (!input.to)
    return {
      provider: "NONE",
      status: "NOT_CONFIGURED",
    } satisfies NotificationEmailSendResult;
  const webhookResult = await sendViaWebhook({
    subject: input.subject,
    text: input.text,
    to: input.to,
  });
  if (webhookResult.status !== "NOT_CONFIGURED") return webhookResult;
  return sendViaResend({
    subject: input.subject,
    text: input.text,
    to: input.to,
  });
}

export async function sendNotificationEmail(input: {
  subject: string;
  text: string;
  to?: string | null;
}): Promise<NotificationEmailResult> {
  return (await sendNotificationEmailDetailed(input)).status;
}
