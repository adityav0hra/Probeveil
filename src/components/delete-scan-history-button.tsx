"use client";

import { useState } from "react";
import { Trash2 } from "lucide-react";

export function DeleteScanHistoryButton() {
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function deleteHistory() {
    if (
      !window.confirm(
        "Delete all scan history? This removes scan records, findings, reports, and evidence files from Probeveil.",
      )
    )
      return;

    setDeleting(true);
    setError(null);
    try {
      const response = await fetch("/api/scans/history", { method: "DELETE" });
      if (!response.ok) {
        const data = await response.json().catch(() => null);
        throw new Error(data?.error ?? "Could not delete scan history.");
      }
      window.location.reload();
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Could not delete scan history.",
      );
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="flex flex-col items-start gap-2 sm:items-end">
      <button
        className="button-secondary text-red-300"
        disabled={deleting}
        onClick={deleteHistory}
        type="button"
      >
        <Trash2 size={16} />
        {deleting ? "Deleting..." : "Delete scan history"}
      </button>
      {error ? <p className="max-w-sm text-xs text-red-300">{error}</p> : null}
    </div>
  );
}
