import { redirect } from "next/navigation";

// Land on the first dashboard page. The proxy handles auth — unauthenticated
// users get bounced to /login from here. Redirecting to /login unconditionally
// causes an infinite loop because the proxy then bounces signed-in users back
// to "/" (the default callbackUrl).
export default function HomePage() {
  redirect("/usage");
}
