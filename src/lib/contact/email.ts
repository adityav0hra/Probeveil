import "server-only";
import {
  enquiryTypeLabels,
  preferredScanDepthLabels,
} from "@/lib/contact/options";
import type { ContactEnquiry } from "@prisma/client";
import {
  contactAdminEmail,
  emailFrom,
  emailReplyTo,
  emailWebhookToken,
  emailWebhookUrl,
  envValue,
} from "@/lib/email/config";

type EmailResult = "SENT" | "FAILED" | "NOT_CONFIGURED";

function getBaseUrl() {
  return (
    process.env.NEXTAUTH_URL ??
    process.env.AUTH_URL ??
    process.env.INTERNAL_API_URL ??
    "http://localhost:3000"
  ).replace(/\/$/, "");
}

function plain(value: string | null | undefined) {
  return value?.replace(/[<>]/g, "").trim() || "-";
}

function renderAdminEmail(enquiry: ContactEnquiry) {
  const scanDepth = enquiry.preferredScanDepth
    ? preferredScanDepthLabels[enquiry.preferredScanDepth]
    : "-";
  const adminUrl = `${getBaseUrl()}/contact-enquiries/${enquiry.id}`;
  return [
    "New Probeveil contact enquiry",
    "",
    `Sender: ${plain(enquiry.fullName)}`,
    `Email: ${plain(enquiry.email)}`,
    `Company: ${plain(enquiry.company)}`,
    `Role: ${plain(enquiry.role)}`,
    `Type: ${enquiryTypeLabels[enquiry.enquiryType]}`,
    `Website URL: ${plain(enquiry.websiteUrl)}`,
    `Preferred scan depth: ${scanDepth}`,
    `Submitted: ${enquiry.createdAt.toISOString()}`,
    "",
    "Message:",
    enquiry.message,
    "",
    `Protected admin link: ${adminUrl}`,
  ].join("\n");
}

function renderSenderEmail(enquiry: ContactEnquiry) {
  return [
    `Hi ${plain(enquiry.fullName)},`,
    "",
    "We received your Probeveil enquiry.",
    `Enquiry type: ${enquiryTypeLabels[enquiry.enquiryType]}`,
    "",
    "Please do not send passwords, access tokens, private keys or other sensitive credentials by email.",
    "",
    "Probeveil",
  ].join("\n");
}

async function sendViaResend({
  to,
  subject,
  text,
}: {
  to: string;
  subject: string;
  text: string;
}) {
  const apiKey = envValue("RESEND_API_KEY");
  const from = emailFrom("contact");
  const replyTo = emailReplyTo("contact");
  if (!apiKey || !from) return "NOT_CONFIGURED" satisfies EmailResult;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      reply_to: replyTo ?? undefined,
      to,
      subject,
      text,
    }),
  });

  if (!response.ok) {
    console.error("Contact email delivery failed", {
      provider: "resend",
      status: response.status,
      to,
    });
  }

  return response.ok ? "SENT" : "FAILED";
}

async function sendViaWebhook({
  to,
  subject,
  text,
}: {
  to: string;
  subject: string;
  text: string;
}) {
  const url = emailWebhookUrl("contact");
  if (!url) return "NOT_CONFIGURED" satisfies EmailResult;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(emailWebhookToken("contact")
        ? { Authorization: `Bearer ${emailWebhookToken("contact")}` }
        : {}),
    },
    body: JSON.stringify({
      from: emailFrom("contact"),
      replyTo: emailReplyTo("contact"),
      subject,
      text,
      to,
    }),
  });
  return response.ok ? "SENT" : "FAILED";
}

async function sendEmail(input: { to: string; subject: string; text: string }) {
  const webhookResult = await sendViaWebhook(input);
  if (webhookResult !== "NOT_CONFIGURED") return webhookResult;
  return sendViaResend(input);
}

export async function sendContactEmails(enquiry: ContactEnquiry) {
  const adminTo = contactAdminEmail();
  if (!adminTo) return "NOT_CONFIGURED" satisfies EmailResult;

  const adminResult = await sendEmail({
    to: adminTo,
    subject: `Probeveil enquiry: ${enquiryTypeLabels[enquiry.enquiryType]}`,
    text: renderAdminEmail(enquiry),
  });

  if (process.env.CONTACT_SEND_AUTO_REPLY === "true") {
    const senderResult = await sendEmail({
      to: enquiry.email,
      subject: "We received your Probeveil enquiry",
      text: renderSenderEmail(enquiry),
    });

    if (adminResult === "SENT" && senderResult === "SENT") return "SENT";
    if (adminResult === "NOT_CONFIGURED" && senderResult === "NOT_CONFIGURED")
      return "NOT_CONFIGURED";
    return "FAILED";
  }

  return adminResult;
}
