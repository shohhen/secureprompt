# SecurePrompt

**The security gateway for the AI-native enterprise.**

Sits between every application, agent, browser, or copilot in your organization and the LLM providers they call. Redacts PII and secrets before they leave your network, enforces policy at the request level, and gives compliance and security teams a complete audit trail — without slowing developers down or forcing a SaaS dependency.

---

## The problem

Every team in your company is now wiring LLMs into something. Each integration is a new exfiltration vector — a new place where customer data, credentials, internal IP, and regulated PII can leak into a third-party model and end up in training data, vendor logs, or worse.

The choices today are bad:

- **Block LLMs entirely** and lose the productivity gains your competitors are getting.
- **Trust each app to redact** and watch as marketing's chatbot, sales' note-taker, and engineering's copilot all reinvent the same broken regex.
- **Use a SaaS guardrail** and add another vendor to your data flow, your audit scope, and your incident response.

SecurePrompt is the fourth option: a single in-network gateway that every AI integration in your company funnels through, owned by you, deployed on your infrastructure, observable to your security team.

---

## Three products, one platform

### 1. SecurePrompt Gateway

A drop-in OpenAI-compatible API endpoint that proxies traffic to OpenAI, Anthropic, Google, Azure OpenAI, vLLM, Ollama, and any custom OpenAI-compatible upstream you configure.

Point any existing client at it — `OPENAI_API_BASE_URL=https://gateway.your-co.internal/v1` — and you're done. No SDK swap, no application changes. The same `sp_…` key works across every provider you've registered, because the gateway maps your provider catalog server-side.

Not just for chat. The Gateway also covers text completion, embeddings, and agent integrations. The goal is straightforward: **every byte of AI-bound traffic in your network goes through one inspection point**, regardless of which model, which client, or which use case.

### 2. SecurePrompt Chat

A familiar AI chat experience your employees can use on their desktop, deployable inside your network with zero external dependencies.

- Sign-in tied to your existing identity provider — no separate accounts to manage
- Per-user access provisioned by admins in the SecurePrompt console — users never handle credentials themselves
- Every chat is attributed to a specific user and the device they sent it from, captured in the audit log
- Choice of AI model controlled centrally — admins decide which providers and models employees can use
- Identical redaction, policy, and audit guarantees as every other Gateway client

For the team that wants ChatGPT-style productivity without the data risk of ChatGPT, this is the answer. Install on company laptops, plug into your SSO, done.

### 3. SecurePrompt Console

The operator dashboard. Built for the security engineer who has to answer "what got sent, by whom, to which model, and was anything sensitive in it?"

- **Audit Log** — every request, every turn, with raw user message, redacted version forwarded upstream, raw model output, and detokenized response shown side-by-side
- **Analytics** — usage, cost, latency (p50/p95/p99), TTFT, security decisions, broken down by provider, model, key, and user
- **Policy Engine** — rules with priority ordering, dry-run mode, and per-rule enforcement
- **Secure Mode** — workspace-level enforcement levels (permissive / standard / strict) with toggles for PII blocking, prompt-injection blocking, and response-side redaction
- **Workspace budgets** — per-day and per-month token limits with three behaviors: block (hard 402), warn (proceed + header), flag (silent log)
- **Role-based access** — Owner edits everything, Developer reads everything, Employee reads only their own audit rows

---

## Why this is different

### PII redaction that actually works

Most "AI guardrails" run a few regular expressions over your prompt and call it done. SecurePrompt runs a layered detection pipeline — pattern matchers for structural data (credit cards, emails, CVVs, SSNs, account numbers), a multilingual named-entity model for personal names, organizations, addresses, and any custom entity class your business defines, plus a context layer that reduces false positives — and replaces only the precise ranges that match.

That precision matters. Lazy substring replacement breaks the moment a detector flags a short token, mangling the rest of the prompt. SecurePrompt operates on exact positional offsets and uses a request-scoped token vault so the upstream model never sees the original PII, and the response is detokenized back to the original values before it reaches the end user.

The same vault enables **streaming-safe redaction** — placeholder fragments that straddle response chunk boundaries are held until they can be safely emitted or restored.

### Prompt injection detection with realistic tradeoffs

SecurePrompt's injection classifier runs on every request with a high confidence threshold for hard blocks. The reason isn't laziness — it's because every meta-prompt in the world ("respond with the title only", "ignore the prior context") looks like injection at low confidence. The threshold lets legitimate templating through while still catching genuine injection attempts.

When a block does fire, the audit log records the score and the reason so reviewers can see exactly why.

### Per-request token economics

Token accounting and budget enforcement happen with three honest numbers visible to operators:

- **Pre-flight estimate** — a fast approximation, charged before dispatch so concurrent burst traffic can't slip past the budget
- **Actual upstream usage** — input + output tokens reported by the provider
- **Reconciliation** — the post-flight difference is applied so dashboards show real usage, not estimates

Budget behavior is configurable per workspace: **block** the request, **warn** the caller while letting it through, or silently **flag** it for review.

### Latency you can actually act on

We report **time-to-first-byte** from the upstream provider — the metric that correlates with user experience — separately from the gateway's own pre-flight overhead. The split tells you whether a slow session is the model being slow or your gateway being slow, so you know what to fix.

---

## On-premises by default, not as an afterthought

SecurePrompt is built so that the only network egress from your deployment is **the upstream LLM call you authorized**. Everything else stays inside your VPC, on your hardware, in your control.

- **All data stays in your network.** Transactional records, analytics, vector indexes, and caches all run as containers in your stack. No external SaaS dependencies, no shared databases, no vendor lock on storage.
- **Local AI inference for security-critical work.** PII detection and prompt-injection classification run inside your network. Sensitive data never leaves the cluster for the sole purpose of being inspected.
- **Air-gapped capable.** All required AI models ship pre-bundled or are downloaded once at install time. After that, the platform functions without internet access.
- **Minimal attack surface.** Production binaries are stripped of build tooling, language runtimes, and shells — what gets deployed is what runs, nothing more.
- **One-command install for evaluation, enterprise orchestration for production.** Stand up a working cluster in minutes; move to your standard production tooling when you're ready.
- **License-gated.** A signed license file controls activation. Expired licenses fail closed at the boundary before any business logic runs.
- **No outbound telemetry by default.** An optional support tunnel is available for vendor-assisted deployments — explicit opt-in, time-bounded, fully auditable. Off until you turn it on.

This isn't an "on-prem option" bolted onto a cloud product. The cloud version does not exist; on-prem is the only deployment model.

---

## Workflow

```
       ┌──────────────┐                                    ┌─────────────────┐
       │ Application  │                                    │   Upstream LLM  │
       │ Agent        │                                    │   OpenAI / etc. │
       │ Browser      │                                    │                 │
       │ Desktop chat │                                    │                 │
       └──────┬───────┘                                    └────────▲────────┘
              │                                                     │
              ▼                                                     │
   ┌──────────────────────────────────────────────────────────────────────────┐
   │                       SecurePrompt Gateway                               │
   │                                                                          │
   │  ① Authenticate the caller, enforce rate limits                          │
   │  ② Pre-flight budget check                                               │
   │  ③ Detect sensitive content — patterns + AI-assisted entity recognition  │
   │  ④ Classify for prompt-injection risk                                    │
   │  ⑤ Evaluate policy rules (priority order, dry-run supported)             │
   │  ⑥ Apply workspace enforcement level                                     │
   │  ⑦ Tokenize, forward sanitized prompt to the upstream AI ─────────────▶│
   │                                                                       │  │
   │  ⑪ Audit + analytics ◀── ⑩ Reconcile budget ◀── ⑨ Restore ◀── ⑧ Receive │
   │                                                                          │
   └──────────────────────────────────────────────────────────────────────────┘
              │
              ▼
       ┌──────────────┐
       │   Console    │   Audit log, policy editor, analytics, member admin
       │   (dashboard)│
       └──────────────┘
```

Eleven steps, every one observable from the dashboard, every one reversible by an admin via policy. The gateway never holds state about a request after it commits — durability lives in your data stores, not in process memory.

---

## Who this is for

- **Security and compliance teams** who need to say yes to AI without inheriting third-party data risk.
- **Platform engineering** at companies that have outgrown "every team picks their own LLM API key."
- **Regulated industries** — healthcare, finance, legal, government — where data sovereignty isn't optional.
- **Companies with on-prem mandates** for IP-sensitive engineering work, model evaluation, or sovereign deployments.
- **Teams running their own models** (vLLM, Ollama) who want a unified policy and audit layer across self-hosted and commercial providers.

If your company has more than a handful of LLM integrations and your security team can't tell you what data has been sent to which provider in the last 30 days, you have the problem SecurePrompt is built for.

---

## What you get on day one

- A drop-in AI gateway compatible with the tools your developers already use
- A desktop AI chat application your employees can install and start using immediately
- An operator dashboard with role-based access for owners, developers, and employees
- An integration layer for the agent and copilot tools your engineering teams already run
- An air-gapped install path for fully isolated environments
- All AI models needed for security inspection, pre-bundled — no external API calls for security-critical work

---

## Get started

**Talk to us** — for licensed deployments, integration support, custom provider adapters, or air-gapped install consulting.

SecurePrompt is the security gateway you'd build yourself if you had the time. Now you don't have to.
