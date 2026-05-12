import { NextResponse } from "next/server";

export const runtime = "nodejs";

function timestampPlus5(): string {
  const local = new Date(Date.now() + 5 * 60 * 60 * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${local.getUTCFullYear()}-${pad(local.getUTCMonth() + 1)}-${pad(local.getUTCDate())}` +
    `T${pad(local.getUTCHours())}:${pad(local.getUTCMinutes())}:${pad(local.getUTCSeconds())}+05:00`
  );
}

type Payload = {
  name?: string;
  email?: string;
  message?: string;
};

export async function POST(req: Request) {
  let body: Payload;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }

  const name = (body.name ?? "").trim();
  const email = (body.email ?? "").trim();
  const message = (body.message ?? "").trim();

  if (!name || !email || !message) {
    return NextResponse.json(
      { error: "name, email, and message are required" },
      { status: 400 },
    );
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return NextResponse.json({ error: "invalid email" }, { status: 400 });
  }

  const endpoint = process.env.CONTACT_FORM_ENDPOINT;
  const payload = {
    timestamp: timestampPlus5(),
    name,
    email,
    message,
  };

  if (!endpoint) {
    console.warn(
      "[contact] CONTACT_FORM_ENDPOINT is not set — logging only",
      payload,
    );
    return NextResponse.json({ ok: true, mode: "logged" });
  }

  try {
    const upstream = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      redirect: "follow",
    });

    if (!upstream.ok) {
      const text = await upstream.text().catch(() => "");
      console.error("[contact] upstream error", upstream.status, text);
      return NextResponse.json(
        { error: "upstream rejected the submission" },
        { status: 502 },
      );
    }

    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error("[contact] forward failed", err);
    return NextResponse.json(
      { error: "could not reach the form endpoint" },
      { status: 502 },
    );
  }
}
