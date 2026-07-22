---
sidebar_position: 1
---

# Metrics

SecurePrompt exposes Prometheus text-exposition metrics from all three
runtime components. Every family below was verified directly against the
emitting source — no metric name or label here is copied from a dashboard,
alert, or design doc without cross-checking the code that writes it.

## Scrape endpoints

| Service | Endpoint | Port | Auth |
|---|---|---|---|
| API (`secureprompt-api`) | `GET /metrics` | `8080` | None — allowlisted in `http/middleware/license_gate.rs` (also doubles as the Kubernetes liveness/readiness probe) |
| Worker (`secureprompt-worker`) | `GET /metrics` | `9091` (`WORKER_METRICS_PORT`, dedicated metrics-only Axum listener — the worker binds no other HTTP server) | None |
| ML sidecar (`secureprompt-ml`) | `GET /metrics` | `8080` (internal) | None — `make_asgi_app()` mounted directly, matching the API's unauthenticated `/metrics` |

Docker Compose scrapes these as `api:8080`, `worker:9091`, and
`secureprompt-ml:8080` (`monitoring/prometheus/prometheus.yml`); the Helm
chart scrapes the equivalent in-cluster Service DNS names
(`templates/prometheus-configmap.yaml`).

## Histogram shape

Every histogram family below emits the standard Prometheus exposition triad:
cumulative `..._bucket{...,le="<bound>"}` series (including a final
`le="+Inf"` series equal to the total observation count), `..._sum{...}`,
and `..._count{...}`. `histogram_quantile()` in PromQL and Grafana panels
depend on this exact shape.

- **API** — Rust, hand-rolled (`observability::metrics::Histogram`, extended
  in `secureprompt-api/src/observability/metrics.rs`; not the `prometheus`
  crate — a deliberate KPI-2 constraint to keep the existing, load-bearing
  `/metrics` exposition byte-compatible). Fixed bucket bounds (seconds):
  `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10` (+ `+Inf`). Four
  histogram families exist. **Three are conversions-in-place** of metrics
  that were previously Prometheus *summaries* (`_sum`/`_count` only, no
  buckets) — same names, same call sites, now real histograms:
  `secureprompt_dashboard_request_duration_seconds`,
  `secureprompt_dashboard_budget_check_duration_seconds`,
  `secureprompt_dashboard_mart_query_duration_seconds`. **The fourth is new**
  in KPI-2: `secureprompt_request_duration_seconds{model}` — the end-to-end
  gateway request latency the `latency.json` dashboard queries.
- **Worker** — Rust, an independent hand-rolled copy of the same `Histogram`
  type and bucket bounds (`secureprompt-worker/src/metrics.rs`) — a
  deliberate standalone copy rather than a shared crate (the two binaries'
  metric sets are small and different enough that sharing isn't worth the
  coupling). One histogram family: `secureprompt_worker_scheduled_job_duration_seconds`.
- **ML sidecar** — Python `prometheus_client.Histogram` (`secureprompt-ml/app/metrics.py`).
  Two histogram families: `secureprompt_ml_request_duration_seconds` (default
  `prometheus_client` buckets) and `secureprompt_ml_ner_confidence` (custom
  buckets `0.1..1.0` step `0.1`, since confidence scores are always in
  `[0, 1]`; `prometheus_client` appends the final `+Inf` bucket
  automatically).

## API (`secureprompt-api`)

Source: `secureprompt-api/src/observability/metrics.rs`
(`MetricsRegistry::render_prometheus()`) plus four counters appended from
`secureprompt-api/src/ml_sidecar/client.rs`
(`MlSidecarClient::render_prometheus()`) — both are concatenated by the
`GET /metrics` handler in `secureprompt-api/src/http/routes/openai.rs`.

| Metric | Type | Labels | Meaning | Source |
|---|---|---|---|---|
| `secureprompt_requests_total` | counter | — | Total gateway requests completed (buffered, streaming, and policy-denied short-circuits), success + failure. | `observability/metrics.rs` (`record_request`), called from `pipeline/service.rs` at every request-completion site. |
| `secureprompt_request_failures_total` | counter | — | Subset of `requests_total` that failed. | Same call site, `record_request(false)`. |
| `secureprompt_analytics_dropped_total` | counter | — | Analytics events dropped by backpressure — the in-memory buffer was full at `enqueue`. | `observability/metrics.rs` (`record_analytics_drop`). |
| `secureprompt_analytics_failures_total` | counter | — | Analytics events that were dequeued but abandoned after a non-retryable ClickHouse write failure (distinct from the drop counter above — this event entered the channel). | `record_analytics_failure()`, called from `analytics/clickhouse_writer.rs`. |
| `secureprompt_clickhouse_insert_failures_total` | counter | — | ClickHouse insert failures (analytics writer). | `observability/metrics.rs` (`record_clickhouse_insert_failure`). |
| `secureprompt_clickhouse_insert_retries_total` | counter | — | ClickHouse insert retries (analytics writer). | `observability/metrics.rs` (`record_clickhouse_insert_retry`). |
| `secureprompt_dashboard_budget_events_total` | counter | `behavior`, `outcome` | Budget/rate-limit enforcement events. `behavior` ∈ `none`/`block`/`warn`/`flag` (which rule tier fired); `outcome` ∈ `allow`/`exceeded`/`warn`/`flag`. | `record_budget_event()`, called from `http/middleware/rate_limit.rs`. |
| `secureprompt_dashboard_budget_check_duration_seconds` | **histogram** | — | Wall-clock time of one `budget_check` call (rate-limit middleware). | `time_budget_check()`, `http/middleware/rate_limit.rs`. |
| `secureprompt_budget_redis_failure_total` | counter | — | Redis outage fail-open events during budget checks (D-25) — Redis was unreachable so the check fails open rather than blocking traffic. | `record_budget_redis_failure()`, `http/middleware/rate_limit.rs`. |
| `secureprompt_dashboard_request_duration_seconds` | **histogram** | `endpoint`, `outcome` | Dashboard analytics endpoint request duration. `endpoint` ∈ `usage-daily`/`cost-by-model`/`policy-violations`/`latency-pctiles`; `outcome` ∈ `success`/`error`. | `record_dashboard_request()`, `http/routes/dashboard/analytics.rs`. |
| `secureprompt_dashboard_errors_total` | counter | `endpoint`, `code` | Dashboard endpoint errors by HTTP status code. | `inc_dashboard_error()`, `http/routes/dashboard/analytics.rs`. |
| `secureprompt_dashboard_mart_query_duration_seconds` | **histogram** | `mart` | ClickHouse mart-query duration. `mart` ∈ `mart_usage_daily`/`mart_cost_by_model`/`mart_policy_violations`/`mart_latency_pctiles`/`latency_samples_hourly`. | `record_mart_query_duration()`, `analytics/dashboard_reader.rs`. |
| `secureprompt_dashboard_client_errors_total` | counter | `component` | Client-side error reports from the dashboard UI. | `inc_client_error()`, called by `POST /v1/telemetry/client-error` (`http/routes/telemetry.rs`). |
| `secureprompt_request_duration_seconds` | **histogram** | `model` | End-to-end gateway request latency (the core latency signal — covers buffered, streaming, and the policy-denied short-circuit), labelled by the resolved provider model. `model="unknown"` when a request was denied before a provider target was ever selected. | `observe_request_duration()`, `pipeline/service.rs`. |
| `secureprompt_policy_violations_total` | counter | `action` | Count of policy-enforcement outcomes that were not a plain `allow`. `action` ∈ `block`/`redact`/`flag` — see the mapping below. Low-cardinality by design: never a rule id or workspace id. | `record_policy_violation()`, `pipeline/service.rs`, driven by the `policy_violation_label()` helper. |
| `secureprompt_ml_sidecar_calls_total` | counter | — | Successful calls to the ML sidecar (NER, injection-detection, RAG-check). | `ml_sidecar/client.rs` (`MlSidecarClient::render_prometheus`). |
| `secureprompt_ml_sidecar_failures_total` | counter | — | Sidecar call failures — transport error or unparseable response. Explicitly **excludes** 4xx (`detect_chunk`'s malformed/oversized-request arm) and 429 (queue-full) — neither of those is a sidecar health signal, so neither trips this counter or the circuit breaker (P0-4 / Finding 1). | `ml_sidecar/client.rs`. |
| `secureprompt_ml_sidecar_circuit_open_total` | counter | — | Number of times the sidecar client's circuit breaker transitioned to OPEN (5 consecutive failures; auto half-opens after 30s). | `ml_sidecar/client.rs`. |
| `secureprompt_ml_sidecar_saturated_total` | counter | — | Count of `429 Too Many Requests` responses from the sidecar (its NER queue was full) — the chunk gets zero PII coverage, tracked distinctly from generic failures so saturation under load is observable (Finding 1, whole-branch review). | `ml_sidecar/client.rs`. |

### `secureprompt_policy_violations_total{action}` mapping

`action` is derived from the policy engine's `final_action` by
`policy_violation_label()` (`secureprompt-api/src/pipeline/service.rs`):

| Policy engine `final_action` | Recorded `action` label |
|---|---|
| `deny` | `block` |
| `redact` | `redact` |
| `transform` | `redact` |
| `flag` | `flag` |
| `allow` | *(not recorded — no metric event)* |

This mapping runs **after** policy evaluation, the workspace secure-mode
override, and the default-redact safety net have all had their say, so the
label reflects the request's actual final enforcement outcome, not just the
raw policy-rule decision.

## Worker (`secureprompt-worker`)

Source: `secureprompt-worker/src/metrics.rs` (`WorkerMetrics::render()`),
served by a dedicated metrics-only Axum router (`worker::metrics::router`)
started before the worker's cron scheduler and Redis drain loop. Gated by
`SECUREPROMPT_WORKER_METRICS_ENABLED` (default `true`).

| Metric | Type | Labels | Meaning | Source |
|---|---|---|---|---|
| `secureprompt_worker_up` | gauge | — | Liveness signal — always `1` while the metrics server is up. Renders unconditionally, independent of whether anything else in the registry has been touched. | `metrics.rs` (`render`). |
| `secureprompt_worker_scheduled_job_runs_total` | counter | `job` | Cron-job executions. `job` ∈ `optimize_final` (02:00 daily) / `rotation_cleanup` (03:00 daily). Incremented on every tick regardless of outcome. | `record_job()`, called from the two cron closures in `main.rs`. |
| `secureprompt_worker_scheduled_job_failures_total` | counter | `job` | Cron-job failures — only incremented when the job body reports `ok=false`. | `record_job()`, `main.rs`. |
| `secureprompt_worker_scheduled_job_duration_seconds` | **histogram** | `job` | Cron-job wall-clock time, recorded on every run regardless of outcome. | `record_job()`, `main.rs`. |
| `secureprompt_worker_tasks_processed_total` | counter | `task_type`, `outcome` | Redis drain-loop task-dispatch results. `task_type` is one of `secureprompt_common::tasks::task_types` (`analytics.flush`, `audit.export`, `retention.purge`, `api_key.rotation_cleanup`, `policy.index_rule`) or the fixed string `unknown` for an unrecognized type (never the raw, attacker/bug-controlled type string — unbounded cardinality). `outcome` ∈ `ok`/`error`/`unknown`/`stub` — most task types are currently no-op stubs pending Phase 7 implementation; only `policy.index_rule` is fully wired (`ok`/`error`). | `record_task()`, `main.rs`'s task-dispatch match. |
| `secureprompt_worker_queue_drain_errors_total` | counter | — | Redis checkout failures or unparseable task-envelope JSON in the drain loop. | `record_drain_error()`, `main.rs`. |

## ML sidecar (`secureprompt-ml`)

Source: `secureprompt-ml/app/metrics.py`, mounted at `/metrics` via
`prometheus_client.make_asgi_app()` in `app/main.py`. All names are
namespaced `secureprompt_ml_*`. Label cardinality is intentionally bounded:
`endpoint` is always a matched FastAPI route **template** (`request.scope["route"].path`,
e.g. `/detect/ner`) or the fixed string `unmatched` for unrouted paths —
never a live path containing an ID. No request text, PII, workspace ID, or
user ID is ever used as a label value.

| Metric | Type | Labels | Meaning | Source |
|---|---|---|---|---|
| `secureprompt_ml_requests_total` | counter | `endpoint`, `status` | Total HTTP requests handled by the sidecar. `status` is `ok` (HTTP status `< 500`) or `error`. `/metrics` itself is excluded from instrumentation (the middleware skips it) to avoid the endpoint scraping its own request. | `_metrics_middleware()`, `app/main.py`, via `metrics.observe_request()`. |
| `secureprompt_ml_request_duration_seconds` | **histogram** | `endpoint` | Request latency in seconds, per endpoint. Default `prometheus_client` bucket bounds. | Same middleware, `metrics.observe_request()`. |
| `secureprompt_ml_ner_entities_detected_total` | counter | `entity_type` | Total NER entities detected, by entity type (PERSON, EMAIL, SSN, PHONE_NUMBER, ...) — drift-detection groundwork for the DRIFT-01 round. | `metrics.record_ner()`, called after `/detect/ner` inference in `app/main.py`. |
| `secureprompt_ml_ner_confidence` | **histogram** | `entity_type` | Confidence-score distribution of detected entities, per type. Buckets `0.1, 0.2, ..., 1.0` (`+Inf` appended automatically). This is the intended signal source for the next round's model-drift detection (DRIFT-01). | `metrics.record_ner()`, `app/main.py`. |
| `secureprompt_ml_model_info` | gauge (info pattern, value always `1`) | `model`, `backend` | Static info metric identifying the currently active NER model(s) and backend as label values (not the numeric value). | `metrics.set_model_info()`, called on model load / reload in `app/main.py`'s lifespan handler. |
| `secureprompt_ml_ready` | gauge | — | `1` once the sidecar's models have finished loading, `0` otherwise — mirrors the `_ready` asyncio Event backing `GET /ready`. Drives the `MLSidecarNotReady` alert. | `metrics.set_ready()`, `app/main.py` (lifespan + reload paths). |

`record_ner()` accepts both dict-shaped detections (`{"entity_type": ...,
"score": ...}`, the raw wire format) and attribute-style `NerEntity`
instances — entries missing an `entity_type` or `score` are silently
skipped rather than raising, so a metrics hiccup can never break detection
itself.
