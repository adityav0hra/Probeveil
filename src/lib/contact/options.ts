export const enquiryTypes = [
  ["PRODUCT_ENQUIRY", "Product enquiry"],
  ["SECURITY_REVIEW", "Security review"],
  ["DEMO_REQUEST", "Demo request"],
  ["PARTNERSHIP", "Partnership"],
  ["TECHNICAL_SUPPORT", "Technical support"],
  ["OTHER", "Other"],
] as const;

export const preferredScanDepths = [
  ["NOT_SURE", "Not sure"],
  ["QUICK_SCAN", "Quick Scan"],
  ["DEEP_SCAN", "Deep Scan"],
  ["EXHAUSTIVE_SCAN", "Exhaustive Scan"],
] as const;

export const contactStatuses = [
  ["NEW", "New"],
  ["IN_REVIEW", "In Review"],
  ["RESPONDED", "Responded"],
  ["CLOSED", "Closed"],
  ["SPAM", "Spam"],
] as const;

export type EnquiryTypeValue = (typeof enquiryTypes)[number][0];
export type PreferredScanDepthValue = (typeof preferredScanDepths)[number][0];
export type ContactStatusValue = (typeof contactStatuses)[number][0];

export const enquiryTypeLabels = Object.fromEntries(enquiryTypes) as Record<
  EnquiryTypeValue,
  string
>;

export const preferredScanDepthLabels = Object.fromEntries(
  preferredScanDepths,
) as Record<PreferredScanDepthValue, string>;

export const contactStatusLabels = Object.fromEntries(
  contactStatuses,
) as Record<ContactStatusValue, string>;
