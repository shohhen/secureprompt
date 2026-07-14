import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { FileScanForm } from "./file-scan-form";

export default async function FileScanPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">File Scan &amp; Secure</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Scan documents for PII, secrets, and prompt injection — or secure a
          file and download a redacted copy in its original format.
        </p>
      </div>
      <FileScanForm />
    </div>
  );
}
