import "server-only";
import {
  enquiryTypeLabels,
  preferredScanDepthLabels,
} from "@/lib/contact/options";
import type { ContactEnquiry } from "@prisma/client";

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
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.CONTACT_EMAIL_FROM;
  if (!apiKey || !from) return "NOT_CONFIGURED" satisfies EmailResult;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from, to, subject, text }),
  });

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
  const url = process.env.CONTACT_EMAIL_WEBHOOK_URL;
  if (!url) return "NOT_CONFIGURED" satisfies EmailResult;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(process.env.CONTACT_EMAIL_WEBHOOK_TOKEN
        ? { Authorization: `Bearer ${process.env.CONTACT_EMAIL_WEBHOOK_TOKEN}` }
        : {}),
    },
    body: JSON.stringify({ to, subject, text }),
  });
  return response.ok ? "SENT" : "FAILED";
}

async function sendEmail(input: { to: string; subject: string; text: string }) {
  const webhookResult = await sendViaWebhook(input);
  if (webhookResult !== "NOT_CONFIGURED") return webhookResult;
  return sendViaResend(input);
}

export async function sendContactEmails(enquiry: ContactEnquiry) {
  const adminTo = process.env.CONTACT_ADMIN_EMAIL;
  if (!adminTo) return "NOT_CONFIGURED" satisfies EmailResult;

  const adminResult = await sendEmail({
    to: adminTo,
    subject: `Probeveil enquiry: ${enquiryTypeLabels[enquiry.enquiryType]}`,
    text: renderAdminEmail(enquiry),
  });

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
