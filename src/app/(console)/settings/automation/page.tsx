import { revalidatePath } from "next/cache";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";

const settingKey = "scan_automation";

type AutomationSettings = {
  cadence: string;
  differentialReports: boolean;
  highSeverityAlerts: boolean;
  notificationEmail: string;
};

const defaults: AutomationSettings = {
  cadence: "manual",
  differentialReports: true,
  highSeverityAlerts: true,
  notificationEmail: "",
};

export default async function AutomationSettingsPage() {
  await requireRole(["ADMIN"]);
  const settings = await readSettings();

  async function save(formData: FormData) {
    "use server";
    const session = await requireRole(["ADMIN"]);
    const next: AutomationSettings = {
      cadence: String(formData.get("cadence") ?? "manual"),
      differentialReports: formData.get("differentialReports") === "on",
      highSeverityAlerts: formData.get("highSeverityAlerts") === "on",
      notificationEmail: String(formData.get("notificationEmail") ?? "").trim(),
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
            cadence: next.cadence,
            differentialReports: next.differentialReports,
            highSeverityAlerts: next.highSeverityAlerts,
            notificationEmailConfigured: Boolean(next.notificationEmail),
          },
          resourceType: "SystemSetting",
          resourceId: settingKey,
          userId: session.user.id,
        },
      }),
    ]);
    revalidatePath("/settings/automation");
  }

  return (
    <>
      <p className="eyebrow">System configuration</p>
      <h1 className="mt-2 text-3xl font-semibold">Automation</h1>
      <p className="muted mt-2">
        Configure scan cadence, notification routing and report deltas.
      </p>

      <form action={save} className="panel mt-8 max-w-3xl p-6">
        <label className="block text-sm text-slate-300">
          Scan cadence
          <select className="input mt-2" defaultValue={settings.cadence} name="cadence">
            <option value="manual">Manual only</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
            <option value="quarterly">Quarterly</option>
          </select>
        </label>
        <label className="mt-5 block text-sm text-slate-300">
          Notification email
          <input
            className="input mt-2"
            defaultValue={settings.notificationEmail}
            name="notificationEmail"
            placeholder="security@example.com"
            type="email"
          />
        </label>
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          <label className="flex items-center gap-3 rounded-lg border border-line bg-black/20 px-4 py-3 text-sm text-slate-300">
            <input
              className="size-4 accent-signal"
              defaultChecked={settings.highSeverityAlerts}
              name="highSeverityAlerts"
              type="checkbox"
            />
            High-severity alerts
          </label>
          <label className="flex items-center gap-3 rounded-lg border border-line bg-black/20 px-4 py-3 text-sm text-slate-300">
            <input
              className="size-4 accent-signal"
              defaultChecked={settings.differentialReports}
              name="differentialReports"
              type="checkbox"
            />
            New-vs-fixed report deltas
          </label>
        </div>
        <button className="button mt-6" type="submit">
          Save automation settings
        </button>
      </form>
    </>
  );
}

async function readSettings() {
  const row = await db.systemSetting.findUnique({ where: { key: settingKey } });
  if (!row?.value || typeof row.value !== "object") return defaults;
  return { ...defaults, ...(row.value as Partial<AutomationSettings>) };
}
