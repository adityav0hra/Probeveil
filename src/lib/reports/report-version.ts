export const REPORT_TEMPLATE_VERSION = "2026.07.04";
export const REPORT_GENERATOR_VERSION = "webguard-pdf-2";

export function getReportProductName() {
  return process.env.PRODUCT_NAME?.trim() || "WebGuard";
}
