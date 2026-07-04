"use server";

import { createHash } from "crypto";
import { headers } from "next/headers";
import { revalidatePath } from "next/cache";
import {
  ContactEnquiryStatus,
  ContactEnquiryType,
  ContactScanDepth,
} from "@prisma/client";
import { db } from "@/lib/db";
import { sendContactEmails } from "@/lib/contact/email";
import { contactRateLimit } from "@/lib/contact/rate-limit";
import { contactEnquirySchema } from "@/lib/contact/validation";

export type ContactFormState = {
  ok: boolean;
  message?: string;
  errors?: Record<string, string[]>;
  values?: Record<string, string>;
};

const successMessage =
  "Thanks. Your enquiry has been received by the Probeveil team.";

function getValue(formData: FormData, key: string) {
  const value = formData.get(key);
  return typeof value === "string" ? value : "";
}

function getValues(formData: FormData) {
  return {
    fullName: getValue(formData, "fullName"),
    email: getValue(formData, "email"),
    company: getValue(formData, "company"),
    role: getValue(formData, "role"),
    enquiryType: getValue(formData, "enquiryType"),
    websiteUrl: getValue(formData, "websiteUrl"),
    estimatedWebsiteCount: getValue(formData, "estimatedWebsiteCount"),
    preferredScanDepth: getValue(formData, "preferredScanDepth"),
    message: getValue(formData, "message"),
    consent: getValue(formData, "consent"),
    sourcePage: getValue(formData, "sourcePage") || "/contact",
  };
}

function hashValue(value: string) {
  const salt =
    process.env.CONTACT_HASH_SECRET ??
    process.env.AUTH_SECRET ??
    "probeveil-development-contact-salt";
  return createHash("sha256").update(`${salt}:${value}`).digest("hex");
}

function getRequestIp(requestHeaders: Headers) {
  return (
    requestHeaders.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    requestHeaders.get("x-real-ip") ||
    requestHeaders.get("cf-connecting-ip") ||
    "unknown"
  );
}

function tooLarge(formData: FormData) {
  let total = 0;
  for (const value of formData.values()) {
    if (typeof value === "string") total += value.length;
  }
  return total > 12000;
}

function genericSuccess(): ContactFormState {
  return { ok: true, message: successMessage, values: {} };
}

export async function submitContactEnquiry(
  _previousState: ContactFormState,
  formData: FormData,
): Promise<ContactFormState> {
  const values = getValues(formData);

  if (tooLarge(formData)) {
    return {
      ok: false,
      message: "The message is too large.",
      errors: { message: ["Please shorten the message."] },
      values,
    };
  }

  const honeypot = getValue(formData, "website");
  const startedAt = Number(getValue(formData, "startedAt"));
  const completionMs = Date.now() - startedAt;
  if (honeypot || !Number.isFinite(startedAt) || completionMs < 2500) {
    return genericSuccess();
  }

  const parsed = contactEnquirySchema.safeParse({
    ...values,
    website: honeypot,
    startedAt,
  });

  if (!parsed.success) {
    return {
      ok: false,
      message: "Please fix the highlighted fields.",
      errors: parsed.error.flatten().fieldErrors,
      values,
    };
  }

  const requestHeaders = await headers();
  const ipHash = hashValue(getRequestIp(requestHeaders));
  const emailHash = hashValue(parsed.data.email);
  const messageHash = hashValue(
    `${parsed.data.email}:${parsed.data.message.toLowerCase()}`,
  );

  if (
    !contactRateLimit(`ip:${ipHash}`) ||
    !contactRateLimit(`email:${emailHash}`)
  ) {
    return genericSuccess();
  }

  const duplicate = await db.contactEnquiry.findFirst({
    where: {
      email: parsed.data.email,
      messageHash,
      createdAt: { gt: new Date(Date.now() - 30 * 60 * 1000) },
    },
    select: { id: true },
  });

  if (duplicate) return genericSuccess();

  const enquiry = await db.contactEnquiry.create({
    data: {
      fullName: parsed.data.fullName,
      email: parsed.data.email,
      company: parsed.data.company,
      role: parsed.data.role,
      enquiryType: parsed.data.enquiryType as ContactEnquiryType,
      websiteUrl: parsed.data.websiteUrl,
      estimatedWebsiteCount: parsed.data.estimatedWebsiteCount,
      preferredScanDepth: parsed.data.preferredScanDepth as
        | ContactScanDepth
        | undefined,
      message: parsed.data.message,
      consentAt: new Date(),
      status: ContactEnquiryStatus.NEW,
      sourcePage: parsed.data.sourcePage,
      ipHash,
      userAgent: requestHeaders.get("user-agent"),
      messageHash,
    },
  });

  const emailDeliveryStatus = await sendContactEmails(enquiry);
  await db.contactEnquiry.update({
    where: { id: enquiry.id },
    data: { emailDeliveryStatus },
  });

  revalidatePath("/contact-enquiries");
  return genericSuccess();
}
