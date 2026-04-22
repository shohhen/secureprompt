import { redirect } from "next/navigation";
import { getServerSession } from "@/lib/session";
import { SearchForm } from "./search-form";

export default async function SemanticSearchPage() {
  const session = await getServerSession();
  if (!session) redirect("/login?reason=unauthenticated");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Semantic Policy Search</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Test whether a prompt matches any indexed policy rules via vector search.
        </p>
      </div>
      <SearchForm />
    </div>
  );
}
