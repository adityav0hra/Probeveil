import { redirect } from "next/navigation";
export default async function ResultsAlias({ params }: { params: Promise<{ id: string }> }) { redirect(`/scans/${(await params).id}`); }
