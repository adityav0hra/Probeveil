import Link from "next/link";
import { notFound } from "next/navigation";
import {
  ArrowLeft,
  ExternalLink,
  Mail,
  MessageSquareText,
  Trash2,
} from "lucide-react";
import { db } from "@/lib/db";
import {
  contactStatuses,
  enquiryTypeLabels,
  preferredScanDepthLabels,
} from "@/lib/contact/options";
import { CopyButton } from "@/components/copy-button";
import { StatusPill } from "@/components/status-pill";
import {
  deleteContactEnquiry,
  markContactEnquiryResponded,
  markContactEnquirySpam,
  updateContactEnquiry,
} from "@/app/(console)/contact-enquiries/actions";

function safeWebsiteUrl(value: string | null) {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    return url.toString();
  } catch {
    return null;
  }
}

export default async function ContactEnquiryPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const enquiry = await db.contactEnquiry.findUnique({
    where: { id },
    include: { assignedAdmin: true },
  });
  if (!enquiry) notFound();

  const websiteUrl = safeWebsiteUrl(enquiry.websiteUrl);
  const senderDetails = [
    enquiry.fullName,
    enquiry.email,
    enquiry.company,
    enquiry.role,
    websiteUrl,
  ]
    .filter(Boolean)
    .join("\n");

  return (
    <>
      <Link
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-white"
        href="/contact-enquiries"
      >
        <ArrowLeft size={15} />
        Back to enquiries
      </Link>

      <div className="mt-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="eyebrow">Contact enquiry</p>
          <h1 className="mt-2 text-3xl font-semibold">{enquiry.fullName}</h1>
          <p className="muted mt-2">
            {enquiryTypeLabels[enquiry.enquiryType]} received{" "}
            {enquiry.createdAt.toLocaleString()}
          </p>
        </div>
        <StatusPill value={enquiry.status} />
      </div>

      <div className="mt-8 grid gap-6 xl:grid-cols-[1.1fr_.9fr]">
        <section className="panel p-5">
          <div className="flex items-center gap-2">
            <MessageSquareText size={18} className="text-signal" />
            <h2 className="font-semibold">Message</h2>
          </div>
          <p className="mt-5 whitespace-pre-wrap rounded-lg border border-line bg-white/[.02] p-4 text-sm leading-7 text-slate-300">
            {enquiry.message}
          </p>
        </section>

        <section className="panel p-5">
          <h2 className="font-semibold">Sender details</h2>
          <dl className="mt-5 space-y-4 text-sm">
            {[
              ["Email", enquiry.email],
              ["Company", enquiry.company ?? "-"],
              ["Role", enquiry.role ?? "-"],
              ["Website", websiteUrl ?? "-"],
              ["Estimated websites", enquiry.estimatedWebsiteCount ?? "-"],
              [
                "Preferred scan depth",
                enquiry.preferredScanDepth
                  ? preferredScanDepthLabels[enquiry.preferredScanDepth]
                  : "-",
              ],
              ["Consent", enquiry.consentAt.toLocaleString()],
              ["Email delivery", enquiry.emailDeliveryStatus],
              ["Assigned admin", enquiry.assignedAdmin?.email ?? "-"],
            ].map(([label, value]) => (
              <div className="flex justify-between gap-4" key={label}>
                <dt className="text-slate-500">{label}</dt>
                <dd className="max-w-[65%] break-words text-right text-slate-200">
                  {value}
                </dd>
              </div>
            ))}
          </dl>
          <div className="mt-5 flex flex-wrap gap-2">
            <CopyButton label="Copy sender" value={senderDetails} />
            <a className="button-secondary" href={`mailto:${enquiry.email}`}>
              <Mail size={14} />
              Email sender
            </a>
            {websiteUrl && (
              <a
                className="button-secondary"
                href={websiteUrl}
                rel="noopener noreferrer"
                target="_blank"
              >
                <ExternalLink size={14} />
                Open website
              </a>
            )}
          </div>
        </section>
      </div>

      <section className="panel mt-6 p-5">
        <h2 className="font-semibold">Admin handling</h2>
        <form
          action={updateContactEnquiry.bind(null, enquiry.id)}
          className="mt-5 grid gap-4 lg:grid-cols-[260px_1fr_auto]"
        >
          <label className="block text-sm text-slate-300">
            Status
            <select
              className="input mt-2"
              defaultValue={enquiry.status}
              name="status"
            >
              {contactStatuses.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label className="block text-sm text-slate-300">
            Admin notes
            <textarea
              className="input mt-2 min-h-28 resize-y"
              defaultValue={enquiry.adminNotes ?? ""}
              name="adminNotes"
            />
          </label>
          <div className="flex items-end">
            <button className="button w-full" type="submit">
              Save
            </button>
          </div>
        </form>
        <div className="mt-4 flex flex-wrap gap-2">
          <form action={markContactEnquiryResponded.bind(null, enquiry.id)}>
            <button className="button-secondary" type="submit">
              Mark responded
            </button>
          </form>
          <form action={markContactEnquirySpam.bind(null, enquiry.id)}>
            <button className="button-secondary" type="submit">
              Mark spam
            </button>
          </form>
          <form action={deleteContactEnquiry.bind(null, enquiry.id)}>
            <button className="button-secondary text-red-300" type="submit">
              <Trash2 size={14} />
              Delete
            </button>
          </form>
        </div>
      </section>
    </>
  );
}
