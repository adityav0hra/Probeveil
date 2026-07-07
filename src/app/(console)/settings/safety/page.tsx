import type { Metadata } from "next";
import { revalidatePath } from "next/cache";
import { CheckCircle2, ShieldAlert, XCircle } from "lucide-react";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import {
  dangerousPayloadClasses,
  generateProofToken,
  normalizeApprovalHostname,
  proofValueFor,
  verifyDomainApprovalProof,
} from "@/lib/scan-safety";

export const metadata: Metadata = { title: "Scan Safety" };

const weekdays = [
  [1, "Mon"],
  [2, "Tue"],
  [3, "Wed"],
  [4, "Thu"],
  [5, "Fri"],
  [6, "Sat"],
  [7, "Sun"],
] as const;

export default async function SafetyPage() {
  await requireRole(["ADMIN"]);
  const approvals = await db.domainApproval.findMany({
    include: { user: { select: { email: true, name: true } } },
    orderBy: [{ status: "asc" }, { updatedAt: "desc" }],
  });

  return (
    <div className="mx-auto max-w-6xl py-10">
      <div>
        <p className="eyebrow">Settings</p>
        <h1 className="mt-2 text-3xl font-semibold">Scan safety controls</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-500">
          Require target ownership proof, cap request volume, pace scan traffic,
          exclude dangerous payload classes and restrict scans to approved
          windows.
        </p>
      </div>

      <section className="panel mt-8 p-5">
        <div className="flex items-center gap-2">
          <ShieldAlert size={18} className="text-signal" />
          <h2 className="text-lg font-semibold text-slate-100">
            Add domain approval
          </h2>
        </div>
        <form action={createDomainApproval} className="mt-5 grid gap-5">
          <div className="grid gap-4 md:grid-cols-3">
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Domain or URL
              </span>
              <input
                className="input mt-2"
                name="hostname"
                placeholder="example.com"
                required
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Proof method
              </span>
              <select className="input mt-2" name="proofMethod">
                <option value="DNS_TXT">DNS TXT record</option>
                <option value="HTTP_FILE">HTTP well-known file</option>
              </select>
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Expires at
              </span>
              <input className="input mt-2" name="expiresAt" type="date" />
            </label>
          </div>

          <div className="grid gap-4 md:grid-cols-4">
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Max requests
              </span>
              <input
                className="input mt-2"
                defaultValue="250"
                min="1"
                max="2500"
                name="maxRequestsPerScan"
                type="number"
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Requests/min
              </span>
              <input
                className="input mt-2"
                defaultValue="60"
                min="1"
                max="600"
                name="requestsPerMinute"
                type="number"
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Window start
              </span>
              <input
                className="input mt-2"
                defaultValue="09:00"
                name="businessStart"
                type="time"
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Window end
              </span>
              <input
                className="input mt-2"
                defaultValue="17:00"
                name="businessEnd"
                type="time"
              />
            </label>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <fieldset className="rounded-lg border border-line bg-black/20 p-4">
              <label className="flex items-center gap-3 text-sm text-slate-300">
                <input
                  className="size-4 accent-signal"
                  name="businessHoursEnabled"
                  type="checkbox"
                />
                Enforce business-hours window
              </label>
              <input
                className="input mt-3"
                defaultValue="Australia/Sydney"
                name="businessTimezone"
                placeholder="Australia/Sydney"
              />
              <div className="mt-3 flex flex-wrap gap-2">
                {weekdays.map(([value, label]) => (
                  <label
                    className="flex items-center gap-2 rounded-full bg-white/[.04] px-3 py-1 text-xs text-slate-300"
                    key={value}
                  >
                    <input
                      className="accent-signal"
                      defaultChecked={value <= 5}
                      name="businessDays"
                      type="checkbox"
                      value={value}
                    />
                    {label}
                  </label>
                ))}
              </div>
            </fieldset>

            <fieldset className="rounded-lg border border-line bg-black/20 p-4">
              <p className="text-sm font-medium text-slate-200">
                Excluded dangerous payload classes
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {dangerousPayloadClasses.map((item) => (
                  <label
                    className="flex items-center gap-2 rounded-full bg-red-400/10 px-3 py-1 text-xs text-red-100"
                    key={item}
                  >
                    <input
                      className="accent-signal"
                      defaultChecked
                      name="excludedDangerousPayloads"
                      type="checkbox"
                      value={item}
                    />
                    {item}
                  </label>
                ))}
              </div>
            </fieldset>
          </div>

          <label className="block">
            <span className="text-sm font-medium text-slate-200">Notes</span>
            <textarea
              className="input mt-2 min-h-20 resize-y"
              name="notes"
              placeholder="Approval ticket, owner, scope notes"
            />
          </label>

          <button className="button h-11 w-fit px-5" type="submit">
            Create approval record
          </button>
        </form>
      </section>

      <section className="panel mt-8 overflow-hidden p-0">
        <div className="border-b border-line p-5">
          <p className="eyebrow">Domain approvals</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-white/[.03] text-xs uppercase tracking-[.18em] text-slate-500">
              <tr>
                <th className="px-5 py-3">Domain</th>
                <th className="px-5 py-3">Proof</th>
                <th className="px-5 py-3">Limits</th>
                <th className="px-5 py-3">Window</th>
                <th className="px-5 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {approvals.map((approval) => (
                <tr key={approval.id}>
                  <td className="px-5 py-4">
                    <div className="flex items-center gap-2">
                      {approval.status === "APPROVED" ? (
                        <CheckCircle2 size={15} className="text-red-300" />
                      ) : approval.status === "REVOKED" ? (
                        <XCircle size={15} className="text-red-300" />
                      ) : (
                        <ShieldAlert size={15} className="text-amber-200" />
                      )}
                      <p className="font-medium text-slate-100">
                        {approval.normalizedHostname}
                      </p>
                    </div>
                    <p className="mt-1 text-xs text-slate-500">
                      {approval.status.toLowerCase()} · by{" "}
                      {approval.user.name ?? approval.user.email}
                    </p>
                  </td>
                  <td className="max-w-[340px] px-5 py-4">
                    <p className="text-xs text-slate-400">
                      {approval.proofMethod}
                    </p>
                    <code className="mt-1 block break-all rounded bg-black/30 p-2 text-xs text-slate-300">
                      {approval.proofValue}
                    </code>
                  </td>
                  <td className="px-5 py-4 text-xs text-slate-400">
                    <p>{approval.maxRequestsPerScan} requests/scan</p>
                    <p className="mt-1">
                      {approval.requestsPerMinute} requests/min
                    </p>
                    <p className="mt-1">
                      {dangerousCount(approval.excludedDangerousPayloads)}{" "}
                      payload classes excluded
                    </p>
                  </td>
                  <td className="px-5 py-4 text-xs text-slate-400">
                    {approval.businessHoursEnabled ? (
                      <>
                        <p>
                          {approval.businessStart}-{approval.businessEnd}
                        </p>
                        <p className="mt-1">{approval.businessTimezone}</p>
                      </>
                    ) : (
                      "Any time"
                    )}
                  </td>
                  <td className="px-5 py-4">
                    <div className="flex flex-wrap gap-2">
                      {approval.status !== "APPROVED" && (
                        <form action={verifyDomainApproval}>
                          <input name="id" type="hidden" value={approval.id} />
                          <button className="button-secondary px-3 py-2 text-xs">
                            Verify
                          </button>
                        </form>
                      )}
                      {approval.status !== "REVOKED" && (
                        <form action={revokeDomainApproval}>
                          <input name="id" type="hidden" value={approval.id} />
                          <button className="button-secondary px-3 py-2 text-xs">
                            Revoke
                          </button>
                        </form>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {!approvals.length && (
                <tr>
                  <td
                    className="px-5 py-10 text-center text-slate-500"
                    colSpan={5}
                  >
                    No domain approvals yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

async function createDomainApproval(formData: FormData) {
  "use server";
  const session = await requireRole(["ADMIN"]);
  const hostname = normalizeApprovalHostname(value(formData, "hostname"));
  const method = value(formData, "proofMethod") || "DNS_TXT";
  const token = generateProofToken();
  const approval = await db.domainApproval.create({
    data: {
      businessDays: selectedNumbers(formData, "businessDays"),
      businessEnd: value(formData, "businessEnd") || "17:00",
      businessHoursEnabled: formData.get("businessHoursEnabled") === "on",
      businessStart: value(formData, "businessStart") || "09:00",
      businessTimezone:
        value(formData, "businessTimezone") || "Australia/Sydney",
      excludedDangerousPayloads: selectedStrings(
        formData,
        "excludedDangerousPayloads",
      ),
      expiresAt: value(formData, "expiresAt")
        ? new Date(`${value(formData, "expiresAt")}T23:59:59.000Z`)
        : null,
      hostname,
      maxRequestsPerScan: clampNumber(
        value(formData, "maxRequestsPerScan"),
        250,
        1,
        2500,
      ),
      normalizedHostname: hostname,
      notes: value(formData, "notes") || null,
      proofMethod: method,
      proofToken: token,
      proofValue: proofValueFor(hostname, method, token),
      requestsPerMinute: clampNumber(
        value(formData, "requestsPerMinute"),
        60,
        1,
        600,
      ),
      userId: session.user.id,
    },
  });
  await db.auditLog.create({
    data: {
      action: "DOMAIN_APPROVAL_CREATED",
      metadata: {
        hostname,
        maxRequestsPerScan: approval.maxRequestsPerScan,
        proofMethod: method,
        requestsPerMinute: approval.requestsPerMinute,
      },
      resourceId: approval.id,
      resourceType: "DomainApproval",
      userId: session.user.id,
    },
  });
  revalidatePath("/settings/safety");
}

async function verifyDomainApproval(formData: FormData) {
  "use server";
  const session = await requireRole(["ADMIN"]);
  const id = value(formData, "id");
  const approval = await db.domainApproval.findUnique({ where: { id } });
  if (!approval) return;
  const verified = await verifyDomainApprovalProof(approval);
  if (verified) {
    await db.domainApproval.update({
      data: { approvedAt: new Date(), status: "APPROVED" },
      where: { id },
    });
    await db.auditLog.create({
      data: {
        action: "DOMAIN_APPROVAL_VERIFIED",
        resourceId: id,
        resourceType: "DomainApproval",
        userId: session.user.id,
      },
    });
  }
  revalidatePath("/settings/safety");
  revalidatePath("/scans/new");
}

async function revokeDomainApproval(formData: FormData) {
  "use server";
  const session = await requireRole(["ADMIN"]);
  const id = value(formData, "id");
  await db.domainApproval.update({
    data: { revokedAt: new Date(), status: "REVOKED" },
    where: { id },
  });
  await db.auditLog.create({
    data: {
      action: "DOMAIN_APPROVAL_REVOKED",
      resourceId: id,
      resourceType: "DomainApproval",
      userId: session.user.id,
    },
  });
  revalidatePath("/settings/safety");
}

function value(formData: FormData, key: string) {
  const item = formData.get(key);
  return typeof item === "string" ? item.trim() : "";
}

function selectedStrings(formData: FormData, key: string) {
  const selected = formData
    .getAll(key)
    .filter((item): item is string => typeof item === "string");
  return selected.length ? selected : [...dangerousPayloadClasses];
}

function selectedNumbers(formData: FormData, key: string) {
  const selected = formData
    .getAll(key)
    .map(Number)
    .filter((item) => Number.isFinite(item));
  return selected.length ? selected : [1, 2, 3, 4, 5];
}

function clampNumber(
  value: string,
  fallback: number,
  min: number,
  max: number,
) {
  const parsed = Number(value);
  return Math.max(
    min,
    Math.min(max, Number.isFinite(parsed) ? Math.round(parsed) : fallback),
  );
}

function dangerousCount(value: unknown) {
  return Array.isArray(value) ? value.length : dangerousPayloadClasses.length;
}
