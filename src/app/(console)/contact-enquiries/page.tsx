import Link from "next/link";
import { ArrowUpRight, Search } from "lucide-react";
import { Prisma } from "@prisma/client";
import { db } from "@/lib/db";
import {
  contactStatuses,
  enquiryTypeLabels,
  enquiryTypes,
} from "@/lib/contact/options";
import { StatusPill } from "@/components/status-pill";

function parseDate(value?: string) {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

export default async function ContactEnquiriesPage({
  searchParams,
}: {
  searchParams: Promise<{
    q?: string;
    type?: string;
    status?: string;
    from?: string;
    to?: string;
  }>;
}) {
  const params = await searchParams;
  const where: Prisma.ContactEnquiryWhereInput = {};
  const query = params.q?.trim();
  const from = parseDate(params.from);
  const to = parseDate(params.to);

  if (query) {
    where.OR = [
      { fullName: { contains: query, mode: "insensitive" } },
      { email: { contains: query, mode: "insensitive" } },
      { company: { contains: query, mode: "insensitive" } },
      { message: { contains: query, mode: "insensitive" } },
    ];
  }
  if (params.type) where.enquiryType = params.type as never;
  if (params.status) where.status = params.status as never;
  if (from || to) where.createdAt = { gte: from, lte: to };

  const enquiries = await db.contactEnquiry.findMany({
    where,
    orderBy: { createdAt: "desc" },
    take: 200,
  });

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Public contact</p>
          <h1 className="mt-2 text-3xl font-semibold">Contact enquiries</h1>
          <p className="muted mt-2">
            Private inbox for product, demo, partnership and technical messages.
          </p>
        </div>
      </div>

      <form className="panel mt-8 grid gap-3 p-4 lg:grid-cols-[1.2fr_.8fr_.8fr_.7fr_.7fr_auto]">
        <label className="relative block">
          <Search
            className="pointer-events-none absolute left-3 top-3 text-slate-600"
            size={15}
          />
          <input
            className="input pl-9"
            defaultValue={params.q}
            name="q"
            placeholder="Search enquiries"
          />
        </label>
        <select className="input" defaultValue={params.type ?? ""} name="type">
          <option value="">All types</option>
          {enquiryTypes.map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <select
          className="input"
          defaultValue={params.status ?? ""}
          name="status"
        >
          <option value="">All statuses</option>
          {contactStatuses.map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <input
          className="input"
          defaultValue={params.from}
          name="from"
          type="date"
        />
        <input
          className="input"
          defaultValue={params.to}
          name="to"
          type="date"
        />
        <button className="button" type="submit">
          Filter
        </button>
      </form>

      <section className="panel mt-6 overflow-hidden">
        {enquiries.length === 0 ? (
          <div className="muted p-12 text-center">No enquiries found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-white/[.02] text-[10px] uppercase tracking-wider text-slate-600">
                <tr>
                  <th className="px-5 py-3">Sender</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Company</th>
                  <th>Email</th>
                  <th>Received</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {enquiries.map((enquiry) => (
                  <tr className="border-t border-line/70" key={enquiry.id}>
                    <td className="px-5 py-4 font-medium text-slate-200">
                      {enquiry.fullName}
                    </td>
                    <td>{enquiryTypeLabels[enquiry.enquiryType]}</td>
                    <td>
                      <StatusPill value={enquiry.status} />
                    </td>
                    <td className="text-slate-500">{enquiry.company ?? "-"}</td>
                    <td className="text-slate-500">{enquiry.email}</td>
                    <td className="text-xs text-slate-500">
                      {enquiry.createdAt.toLocaleString()}
                    </td>
                    <td>
                      <Link
                        aria-label="Open enquiry"
                        className="text-slate-500 hover:text-signal"
                        href={`/contact-enquiries/${enquiry.id}`}
                      >
                        <ArrowUpRight size={16} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
