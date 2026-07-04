"use server";

import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { ContactEnquiryStatus } from "@prisma/client";
import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth";
import { contactAdminUpdateSchema } from "@/lib/contact/validation";

export async function updateContactEnquiry(id: string, formData: FormData) {
  const session = await requireRole(["ADMIN", "AUDITOR"]);
  const parsed = contactAdminUpdateSchema.parse({
    status: formData.get("status"),
    adminNotes: formData.get("adminNotes"),
  });

  await db.contactEnquiry.update({
    where: { id },
    data: {
      status: parsed.status as ContactEnquiryStatus,
      adminNotes: parsed.adminNotes,
      assignedAdminId:
        parsed.status === "IN_REVIEW" ? session.user.id : undefined,
    },
  });
  await db.auditLog.create({
    data: {
      userId: session.user.id,
      action: "CONTACT_ENQUIRY_UPDATED",
      resourceType: "ContactEnquiry",
      resourceId: id,
    },
  });
  revalidatePath("/contact-enquiries");
  revalidatePath(`/contact-enquiries/${id}`);
}

export async function markContactEnquirySpam(id: string) {
  const session = await requireRole(["ADMIN", "AUDITOR"]);
  await db.contactEnquiry.update({
    where: { id },
    data: { status: ContactEnquiryStatus.SPAM },
  });
  await db.auditLog.create({
    data: {
      userId: session.user.id,
      action: "CONTACT_ENQUIRY_MARKED_SPAM",
      resourceType: "ContactEnquiry",
      resourceId: id,
    },
  });
  revalidatePath("/contact-enquiries");
  revalidatePath(`/contact-enquiries/${id}`);
}

export async function markContactEnquiryResponded(id: string) {
  const session = await requireRole(["ADMIN", "AUDITOR"]);
  await db.contactEnquiry.update({
    where: { id },
    data: { status: ContactEnquiryStatus.RESPONDED },
  });
  await db.auditLog.create({
    data: {
      userId: session.user.id,
      action: "CONTACT_ENQUIRY_RESPONDED",
      resourceType: "ContactEnquiry",
      resourceId: id,
    },
  });
  revalidatePath("/contact-enquiries");
  revalidatePath(`/contact-enquiries/${id}`);
}

export async function deleteContactEnquiry(id: string) {
  const session = await requireRole(["ADMIN"]);
  await db.contactEnquiry.delete({ where: { id } });
  await db.auditLog.create({
    data: {
      userId: session.user.id,
      action: "CONTACT_ENQUIRY_DELETED",
      resourceType: "ContactEnquiry",
      resourceId: id,
    },
  });
  revalidatePath("/contact-enquiries");
  redirect("/contact-enquiries");
}
