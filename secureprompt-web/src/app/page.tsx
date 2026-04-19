import { redirect } from "next/navigation";

// Dashboard index is added by Plan 05-03.
// Until then, authenticated users also hit /login (proxy.ts sends them onward).
export default function HomePage() {
  redirect("/login");
}
