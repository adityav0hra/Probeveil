import "server-only";

export type NotificationEmailResult = "SENT" | "FAILED" | "NOT_CONFIGURED";

async function sendViaWebhook(input: {
  subject: string;
  text: string;
  to: string;
}) {
  const url = process.env.NOTIFICATION_EMAIL_WEBHOOK_URL;
  if (!url) return "NOT_CONFIGURED" satisfies NotificationEmailResult;

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
  return response.ok ? "SENT" : "FAILED";
}

async function sendViaResend(input: {
  subject: string;
  text: string;
  to: string;
}) {
  const apiKey = process.env.RESEND_API_KEY;
  const from =
    process.env.NOTIFICATION_EMAIL_FROM ??
    process.env.CONTACT_EMAIL_FROM ??
    "Probeveil <onboarding@resend.dev>";
  if (!apiKey || !from)
    return "NOT_CONFIGURED" satisfies NotificationEmailResult;

  const response = await fetch("https://api.resend.com/emails", {
    body: JSON.stringify({ from, ...input }),
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    method: "POST",
  });

  if (!response.ok) {
    console.error("Notification email delivery failed", {
      provider: "resend",
      status: response.status,
      to: input.to,
    });
  }

  return response.ok ? "SENT" : "FAILED";
}

export async function sendNotificationEmail(input: {
  subject: string;
  text: string;
  to?: string | null;
}) {
  if (!input.to) return "NOT_CONFIGURED" satisfies NotificationEmailResult;
  const webhookResult = await sendViaWebhook({
    subject: input.subject,
    text: input.text,
    to: input.to,
  });
  if (webhookResult !== "NOT_CONFIGURED") return webhookResult;
  return sendViaResend({
    subject: input.subject,
    text: input.text,
    to: input.to,
  });
}
