import "server-only";
import { z } from "zod";
import {
  contactStatuses,
  enquiryTypes,
  preferredScanDepths,
} from "@/lib/contact/options";

const disposableDomains = new Set([
  "10minutemail.com",
  "guerrillamail.com",
  "mailinator.com",
  "tempmail.com",
  "temp-mail.org",
  "yopmail.com",
]);

const forbiddenMessagePatterns = [
  /password\s*[:=]/i,
  /api[_\s-]*key\s*[:=]/i,
  /private\s+key/i,
  /bearer\s+[a-z0-9._-]{20,}/i,
  /-----BEGIN\s+(RSA|OPENSSH|EC|PRIVATE)\s+KEY-----/i,
];

function emptyToUndefined(value: unknown) {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

function normalizeText(value: unknown) {
  return typeof value === "string"
    ? value.trim().replace(/\r\n/g, "\n")
    : value;
}

function cleanHeaderText(value: unknown) {
  return typeof value === "string"
    ? value.trim().replace(/[\r\n]+/g, " ")
    : value;
}

function parsePositiveInteger(value: unknown) {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return Number(trimmed);
}

function rejectDisposableEmail(email: string) {
  const domain = email.split("@")[1]?.toLowerCase();
  return Boolean(domain) && !disposableDomains.has(domain);
}

function rejectSensitiveContent(message: string) {
  return !forbiddenMessagePatterns.some((pattern) => pattern.test(message));
}

export const contactEnquirySchema = z.object({
  fullName: z.preprocess(
    cleanHeaderText,
    z.string().min(2, "Enter your full name.").max(120, "Name is too long."),
  ),
  email: z.preprocess(
    (value) => (typeof value === "string" ? value.trim().toLowerCase() : value),
    z
      .string()
      .email("Enter a valid work email.")
      .max(254, "Email is too long.")
      .refine(rejectDisposableEmail, "Use a non-disposable work email."),
  ),
  company: z.preprocess(
    emptyToUndefined,
    z.string().max(160, "Company is too long.").optional(),
  ),
  role: z.preprocess(
    emptyToUndefined,
    z.string().max(120, "Role is too long.").optional(),
  ),
  enquiryType: z.enum(
    enquiryTypes.map(([value]) => value) as [string, ...string[]],
    {
      errorMap: () => ({ message: "Choose an enquiry type." }),
    },
  ),
  websiteUrl: z.preprocess(
    emptyToUndefined,
    z
      .string()
      .url("Enter a valid HTTP or HTTPS URL.")
      .max(2048, "Website URL is too long.")
      .refine((value) => /^https?:\/\//i.test(value), "Use HTTP or HTTPS.")
      .optional(),
  ),
  estimatedWebsiteCount: z.preprocess(
    parsePositiveInteger,
    z
      .number({ invalid_type_error: "Enter a whole number." })
      .int("Enter a whole number.")
      .positive("Enter a positive number.")
      .max(100000, "Enter a lower estimate.")
      .optional(),
  ),
  preferredScanDepth: z.preprocess(
    emptyToUndefined,
    z
      .enum(
        preferredScanDepths.map(([value]) => value) as [string, ...string[]],
        { errorMap: () => ({ message: "Choose a valid scan depth." }) },
      )
      .optional(),
  ),
  message: z.preprocess(
    normalizeText,
    z
      .string()
      .min(20, "Add a little more detail.")
      .max(5000, "Message is too long.")
      .refine(
        rejectSensitiveContent,
        "Do not submit passwords, tokens, private keys or sensitive credentials.",
      ),
  ),
  consent: z.literal("on", {
    errorMap: () => ({ message: "Consent is required." }),
  }),
  website: z.literal("", {
    errorMap: () => ({ message: "Submission received." }),
  }),
  startedAt: z.coerce.number().int().positive(),
  sourcePage: z.preprocess(
    emptyToUndefined,
    z.string().max(120).default("/contact"),
  ),
});

export const contactAdminUpdateSchema = z.object({
  status: z.enum(
    contactStatuses.map(([value]) => value) as [string, ...string[]],
  ),
  adminNotes: z.preprocess(
    emptyToUndefined,
    z.string().max(5000, "Admin notes are too long.").optional(),
  ),
});

export type ContactEnquiryInput = z.infer<typeof contactEnquirySchema>;
