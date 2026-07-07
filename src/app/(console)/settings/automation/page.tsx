import { revalidatePath } from "next/cache";
import Link from "next/link";
import { Bell, CalendarClock, Pause, Play, Trash2 } from "lucide-react";
import type { ScanMode } from "@prisma/client";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import { nextScheduledRun, type ScheduleCadenceValue } from "@/lib/scheduling";
import { normalizeUrlInput, urlFingerprint } from "@/lib/url";

const settingKey = "scan_automation";

type AutomationSettings = {
  differentialReports: boolean;
  highSeverityAlerts: boolean;
  notificationEmail: string;
  summaryEmails: boolean;
};

const defaults: AutomationSettings = {
  differentialReports: true,
  highSeverityAlerts: true,
  notificationEmail: "",
  summaryEmails: true,
};

export default async function AutomationSettingsPage() {
  await requireRole(["ADMIN"]);
  const [settings, schedules, notifications] = await Promise.all([
    readSettings(),
    db.scanSchedule.findMany({
      include: {
        _count: { select: { notifications: true, scans: true } },
      },
      orderBy: [{ enabled: "desc" }, { nextRunAt: "asc" }],
    }),
    db.scanNotification.findMany({
      include: {
        scan: { select: { id: true, normalizedUrl: true, status: true } },
        schedule: { select: { name: true } },
      },
      orderBy: { createdAt: "desc" },
      take: 12,
    }),
  ]);

  async function saveDefaults(formData: FormData) {
    "use server";
    const session = await requireRole(["ADMIN"]);
    const next: AutomationSettings = {
      differentialReports: formData.get("differentialReports") === "on",
      highSeverityAlerts: formData.get("highSeverityAlerts") === "on",
      notificationEmail: String(formData.get("notificationEmail") ?? "").trim(),
      summaryEmails: formData.get("summaryEmails") === "on",
    };
    await db.$transaction([
      db.systemSetting.upsert({
        create: { key: settingKey, value: next },
        update: { value: next },
        where: { key: settingKey },
      }),
      db.auditLog.create({
        data: {
          action: "AUTOMATION_SETTINGS_UPDATED",
          metadata: {
            differentialReports: next.differentialReports,
            highSeverityAlerts: next.highSeverityAlerts,
            notificationEmailConfigured: Boolean(next.notificationEmail),
            summaryEmails: next.summaryEmails,
          },
          resourceId: settingKey,
          resourceType: "SystemSetting",
          userId: session.user.id,
        },
      }),
    ]);
    revalidatePath("/settings/automation");
  }

  async function createSchedule(formData: FormData) {
    "use server";
    const session = await requireRole(["ADMIN"]);
    const url = normalizeUrlInput(String(formData.get("url") ?? ""));
    const cadence = parseCadence(formData.get("cadence"));
    const mode = parseMode(formData.get("mode"));
    const name =
      String(formData.get("name") ?? "").trim() || new URL(url).hostname;
    const firstRun = parseFirstRun(formData.get("nextRunAt"), cadence);
    const notificationEmail = String(
      formData.get("notificationEmail") ?? "",
    ).trim();
    const features = {
      apiDiscovery: formData.get("apiDiscovery") === "on",
      browserRendering: formData.get("browserRendering") === "on",
      screenshots: formData.get("screenshots") === "on",
    };

    const schedule = await db.scanSchedule.create({
      data: {
        cadence,
        failedScanAlerts: formData.get("failedScanAlerts") === "on",
        features,
        highSeverityAlerts: formData.get("highSeverityAlerts") === "on",
        mode,
        name,
        newFindingDiffs: formData.get("newFindingDiffs") === "on",
        nextRunAt: firstRun,
        normalizedHash: urlFingerprint(url),
        normalizedUrl: url,
        notificationEmail: notificationEmail || null,
        originalUrl: String(formData.get("url") ?? "").trim(),
        summaryEmails: formData.get("summaryEmails") === "on",
        userId: session.user.id,
      },
    });
    await db.auditLog.create({
      data: {
        action: "SCAN_SCHEDULE_CREATED",
        metadata: {
          cadence,
          mode,
          nextRunAt: firstRun.toISOString(),
          normalizedUrl: url,
          notificationEmailConfigured: Boolean(notificationEmail),
        },
        resourceId: schedule.id,
        resourceType: "ScanSchedule",
        userId: session.user.id,
      },
    });
    revalidatePath("/settings/automation");
  }

  async function toggleSchedule(formData: FormData) {
    "use server";
    const session = await requireRole(["ADMIN"]);
    const id = String(formData.get("id") ?? "");
    const enabled = formData.get("enabled") === "true";
    await db.$transaction([
      db.scanSchedule.update({ data: { enabled }, where: { id } }),
      db.auditLog.create({
        data: {
          action: enabled ? "SCAN_SCHEDULE_RESUMED" : "SCAN_SCHEDULE_PAUSED",
          metadata: { enabled },
          resourceId: id,
          resourceType: "ScanSchedule",
          userId: session.user.id,
        },
      }),
    ]);
    revalidatePath("/settings/automation");
  }

  async function deleteSchedule(formData: FormData) {
    "use server";
    const session = await requireRole(["ADMIN"]);
    const id = String(formData.get("id") ?? "");
    await db.$transaction([
      db.scanSchedule.delete({ where: { id } }),
      db.auditLog.create({
        data: {
          action: "SCAN_SCHEDULE_DELETED",
          metadata: {},
          resourceId: id,
          resourceType: "ScanSchedule",
          userId: session.user.id,
        },
      }),
    ]);
    revalidatePath("/settings/automation");
  }

  return (
    <>
      <p className="eyebrow">System configuration</p>
      <h1 className="mt-2 text-3xl font-semibold">Scheduling</h1>
      <p className="muted mt-2">
        Run recurring scans, send alert emails and track what changed since the
        last scan.
      </p>

      <div className="mt-8 grid gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(360px,.9fr)]">
        <form action={createSchedule} className="panel p-6">
          <div className="flex items-center gap-3">
            <CalendarClock className="text-signal" size={20} />
            <h2 className="text-lg font-semibold">New recurring scan</h2>
          </div>
          <div className="mt-6 grid gap-4 sm:grid-cols-2">
            <label className="block text-sm text-slate-300">
              Schedule name
              <input
                className="input mt-2"
                name="name"
                placeholder="Production website"
                type="text"
              />
            </label>
            <label className="block text-sm text-slate-300">
              Website URL
              <input
                className="input mt-2"
                name="url"
                placeholder="https://example.com"
                required
                type="text"
              />
            </label>
            <label className="block text-sm text-slate-300">
              Cadence
              <select
                className="input mt-2"
                name="cadence"
                defaultValue="WEEKLY"
              >
                <option value="WEEKLY">Weekly</option>
                <option value="MONTHLY">Monthly</option>
              </select>
            </label>
            <label className="block text-sm text-slate-300">
              Scan mode
              <select className="input mt-2" name="mode" defaultValue="FULL">
                <option value="QUICK">Quick</option>
                <option value="FULL">Full</option>
                <option value="MAXIMUM">Maximum</option>
              </select>
            </label>
            <label className="block text-sm text-slate-300">
              First run
              <input
                className="input mt-2"
                name="nextRunAt"
                type="datetime-local"
              />
            </label>
            <label className="block text-sm text-slate-300">
              Notification email
              <input
                className="input mt-2"
                name="notificationEmail"
                placeholder={
                  settings.notificationEmail || "security@example.com"
                }
                type="email"
              />
            </label>
          </div>
          <div className="mt-5 grid gap-3 sm:grid-cols-3">
            {[
              ["browserRendering", "Browser rendered", true],
              ["apiDiscovery", "API discovery", true],
              ["screenshots", "Screenshots", true],
            ].map(([name, label, checked]) => (
              <Checkbox
                defaultChecked={Boolean(checked)}
                key={String(name)}
                label={String(label)}
                name={String(name)}
              />
            ))}
          </div>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <Checkbox
              defaultChecked
              label="Email summaries"
              name="summaryEmails"
            />
            <Checkbox
              defaultChecked
              label="Failed scan alerts"
              name="failedScanAlerts"
            />
            <Checkbox
              defaultChecked
              label="High severity alerts"
              name="highSeverityAlerts"
            />
            <Checkbox
              defaultChecked
              label="New finding diffs"
              name="newFindingDiffs"
            />
          </div>
          <button className="button mt-6" type="submit">
            Create schedule
          </button>
        </form>

        <form action={saveDefaults} className="panel p-6">
          <div className="flex items-center gap-3">
            <Bell className="text-signal" size={20} />
            <h2 className="text-lg font-semibold">Notification defaults</h2>
          </div>
          <label className="mt-6 block text-sm text-slate-300">
            Default email
            <input
              className="input mt-2"
              defaultValue={settings.notificationEmail}
              name="notificationEmail"
              placeholder="security@example.com"
              type="email"
            />
          </label>
          <div className="mt-5 grid gap-3">
            <Checkbox
              defaultChecked={settings.summaryEmails}
              label="Send scan summaries"
              name="summaryEmails"
            />
            <Checkbox
              defaultChecked={settings.highSeverityAlerts}
              label="Send high severity alerts"
              name="highSeverityAlerts"
            />
            <Checkbox
              defaultChecked={settings.differentialReports}
              label="Send new finding diffs"
              name="differentialReports"
            />
          </div>
          <button className="button-secondary mt-6" type="submit">
            Save defaults
          </button>
        </form>
      </div>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">Active schedules</h2>
        <div className="mt-4 grid gap-4">
          {schedules.length === 0 ? (
            <div className="panel p-6 text-sm text-slate-400">
              No recurring scans are configured yet.
            </div>
          ) : (
            schedules.map((schedule) => (
              <div className="panel p-5" key={schedule.id}>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <div className="flex flex-wrap items-center gap-3">
                      <h3 className="text-lg font-semibold">{schedule.name}</h3>
                      <span className={statusClass(schedule.enabled)}>
                        {schedule.enabled ? "Enabled" : "Paused"}
                      </span>
                    </div>
                    <p className="mt-1 break-all text-sm text-slate-400">
                      {schedule.normalizedUrl}
                    </p>
                    <div className="mt-3 flex flex-wrap gap-3 text-xs text-slate-500">
                      <span>{schedule.cadence.toLowerCase()}</span>
                      <span>{schedule.mode.toLowerCase()} mode</span>
                      <span>next {formatDate(schedule.nextRunAt)}</span>
                      <span>{schedule._count.scans} scans</span>
                      <span>{schedule._count.notifications} notifications</span>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {schedule.lastScanId && (
                      <Link
                        className="button-secondary"
                        href={`/scans/${schedule.lastScanId}`}
                      >
                        Last scan
                      </Link>
                    )}
                    <form action={toggleSchedule}>
                      <input name="id" type="hidden" value={schedule.id} />
                      <input
                        name="enabled"
                        type="hidden"
                        value={String(!schedule.enabled)}
                      />
                      <button className="button-secondary" type="submit">
                        {schedule.enabled ? (
                          <Pause size={16} />
                        ) : (
                          <Play size={16} />
                        )}
                        {schedule.enabled ? "Pause" : "Resume"}
                      </button>
                    </form>
                    <form action={deleteSchedule}>
                      <input name="id" type="hidden" value={schedule.id} />
                      <button className="button-secondary" type="submit">
                        <Trash2 size={16} />
                        Delete
                      </button>
                    </form>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">Recent notifications</h2>
        <div className="panel mt-4 overflow-hidden">
          {notifications.length === 0 ? (
            <p className="p-6 text-sm text-slate-400">
              Notification history will appear here after scans complete.
            </p>
          ) : (
            <div className="divide-y divide-line">
              {notifications.map((notification) => (
                <div
                  className="grid gap-2 p-4 md:grid-cols-[1fr_auto]"
                  key={notification.id}
                >
                  <div>
                    <p className="text-sm font-medium text-slate-100">
                      {notification.subject}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      {notification.schedule?.name ?? "Manual scan"} ·{" "}
                      {notification.type.replaceAll("_", " ").toLowerCase()} ·{" "}
                      {formatDate(notification.createdAt)}
                    </p>
                    {notification.scan && (
                      <Link
                        className="mt-2 inline-block break-all text-xs text-signal hover:text-emerald-200"
                        href={`/scans/${notification.scan.id}`}
                      >
                        {notification.scan.normalizedUrl}
                      </Link>
                    )}
                  </div>
                  <span className={deliveryClass(notification.status)}>
                    {notification.status.replaceAll("_", " ").toLowerCase()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </>
  );
}

function Checkbox({
  defaultChecked,
  label,
  name,
}: {
  defaultChecked?: boolean;
  label: string;
  name: string;
}) {
  return (
    <label className="flex items-center gap-3 rounded-lg border border-line bg-black/20 px-4 py-3 text-sm text-slate-300">
      <input
        className="size-4 accent-signal"
        defaultChecked={defaultChecked}
        name={name}
        type="checkbox"
      />
      {label}
    </label>
  );
}

async function readSettings() {
  const row = await db.systemSetting.findUnique({ where: { key: settingKey } });
  if (!row?.value || typeof row.value !== "object") return defaults;
  return { ...defaults, ...(row.value as Partial<AutomationSettings>) };
}

function parseCadence(value: FormDataEntryValue | null): ScheduleCadenceValue {
  return value === "MONTHLY" ? "MONTHLY" : "WEEKLY";
}

function parseMode(value: FormDataEntryValue | null): ScanMode {
  if (value === "QUICK" || value === "MAXIMUM") return value;
  return "FULL";
}

function parseFirstRun(
  value: FormDataEntryValue | null,
  cadence: ScheduleCadenceValue,
) {
  if (typeof value === "string" && value) {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  return nextScheduledRun(cadence, new Date());
}

function formatDate(date: Date) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function statusClass(enabled: boolean) {
  return enabled
    ? "rounded-full bg-emerald-400/10 px-2.5 py-1 text-xs font-medium text-emerald-200"
    : "rounded-full bg-slate-500/10 px-2.5 py-1 text-xs font-medium text-slate-300";
}

function deliveryClass(status: string) {
  if (status === "SENT")
    return "h-fit rounded-full bg-emerald-400/10 px-2.5 py-1 text-xs font-medium text-emerald-200";
  if (status === "FAILED")
    return "h-fit rounded-full bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-300";
  return "h-fit rounded-full bg-amber-400/10 px-2.5 py-1 text-xs font-medium text-amber-200";
}
