# SECURITY.md

**Phase:** 03 — ML Sidecar PII + Injection Detection
**ASVS Level:** L1
**Audit Date:** 2026-04-17
**Auditor:** gsd-security-auditor (claude-sonnet-4-6)

---

## Threat Verification Summary

11 of 13 declared threats are CLOSED. 2 threats are OPEN.

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-03-W0-02 | DoS | mitigate | CLOSED | `conftest.py:6-29` — all fixtures use `MagicMock`; no real model downloads; `pyproject.toml:1-7` — pytest config with `asyncio_mode=auto`, testpaths = ["tests"] |
| T-03-01 | Tampering | mitigate | CLOSED | `models.py:6` — `NerRequest.text: str = Field(..., max_length=32768)` |
| T-03-02 | DoS | mitigate | CLOSED | `batching.py:53` — `asyncio.Queue(maxsize=100)` in BatchProcessor; `main.py:25` — same `maxsize=100` in lifespan; `main.py:61-63` — `put_nowait` raises `QueueFull` → HTTP 429 |
| T-03-03 | Tampering | mitigate | CLOSED | `models.py:23` — `InjectionRequest.text: str = Field(..., max_length=2048)`; `injection.py:17,29` — `truncation=True, max_length=512` in both `detect_injection` and `classify_injection` |
| T-03-04 | DoS | mitigate | CLOSED | `main.py:22-24` — all three models loaded via `asyncio.to_thread(...)`; `main.py:48-51` — `/ready` returns HTTP 503 until `_ready.is_set()` |
| T-03-05a | Availability | mitigate | CLOSED | `Dockerfile:35` — `ENV TRANSFORMERS_OFFLINE=1`; `Dockerfile:19-21` — GLiNER, DeBERTa injection model, and sentence-transformers pre-downloaded in builder RUN steps |
| T-03-05b | Spoofing | mitigate | OPEN | `client.rs:72-94` — `MlSidecarClient::new()` accepts any non-empty string as `base_url` with no `starts_with("http://")` or `starts_with("https://")` guard. The SSRF mitigation (URL scheme validation) declared in the plan is absent. |
| T-03-06b | DoS | mitigate | OPEN | Circuit breaker logic is implemented (`client.rs:14-53` — OPEN after 5 failures, half-open at 30s). Two sub-mitigations are absent: (1) `docker-compose.yml` has no `restart: on-failure` policy on `secureprompt-ml`; (2) `ml_sidecar_circuit_open_total` Prometheus counter is not present in `client.rs` or any observability file. |
| T-03-07 | Tampering | mitigate | CLOSED | `merge.rs:9-22` — `merge_detections` keeps all regex detections first; ML detections added only when `!overlaps_any(&result, ml_det.span)`. Regex wins on span overlap enforced. Tests at lines 62-68 confirm. |
| T-03-09 | DoS | mitigate | CLOSED | `client.rs:83` — `.timeout(Duration::from_millis(timeout_ms))` on `Client::builder()`; `main.rs:45` — instantiated with `timeout_ms=200`; circuit opens after 5 consecutive failures per `client.rs:47-52`. Client-level timeout is functionally equivalent to per-request timeout per constraints. |
| T-03-10 | Availability | mitigate | CLOSED | `docker-compose.yml:28-45` — `secureprompt-ml` service has no `ports:` mapping; `docker-compose.yml:55` — API uses `ML_SIDECAR_URL: http://secureprompt-ml:8080` via Docker DNS |
| T-03-11 | Availability | mitigate | CLOSED | `docker-compose.yml:36-45` — healthcheck targets `/ready`; `start_period: 30s`; `docker-compose.yml:63-64` — `api.depends_on.secureprompt-ml.condition: service_healthy` |
| T-03-12 | Availability | mitigate | CLOSED | `ci.yml:203-208` — `phase-3-ml-integration` job has no `ML_SIDECAR_URL` env var; comment at line 204 documents "no sidecar required"; runs `--lib` tests targeting `ml_sidecar detection::merge` |

---

## Open Threats

### T-03-05b — SSRF via ML_SIDECAR_URL (Spoofing)

**Files Searched:** `secureprompt-api/src/ml_sidecar/client.rs`

**Mitigation Expected:** `MlSidecarClient::new` validates that `base_url` starts with `http://` or `https://` before constructing the client.

**Finding:** `client.rs:72-94` — the constructor accepts any non-empty string as `base_url`. No URL scheme check exists anywhere in the file. An operator who misconfigures `ML_SIDECAR_URL` with a file:// or other URI scheme could trigger unexpected behavior; a malicious environment-variable injection could direct the client to internal services.

**Required Fix:** Add a guard in `MlSidecarClient::new`:
```rust
if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
    panic!("ML_SIDECAR_URL must start with http:// or https://");
}
```
Or return an `Err` and propagate from `main.rs`.

---

### T-03-06b — Circuit Breaker Permanently OPEN (DoS)

**Files Searched:** `secureprompt-api/src/ml_sidecar/client.rs`, `docker-compose.yml`, `secureprompt-api/src/observability/metrics.rs`

**Mitigation Expected (plan):** Three sub-controls: (1) Docker `restart: on-failure` on `secureprompt-ml`; (2) half-open probe at 30s; (3) `ml_sidecar_circuit_open_total` Prometheus counter.

**Finding:**
- Half-open probe at 30s: CLOSED — `client.rs:33-38` resets `open_since` and `consecutive_failures` after `OPEN_DURATION_SECS` (30s).
- `restart: on-failure`: ABSENT — `docker-compose.yml:28-45` has no `restart:` key on `secureprompt-ml`. Without this, a crashed sidecar process is not automatically restarted by Docker Compose.
- `ml_sidecar_circuit_open_total` counter: ABSENT — not present in `client.rs` or any file under `secureprompt-api/src/observability/`.

**Required Fix:**
1. Add `restart: on-failure` (or `restart: unless-stopped`) to the `secureprompt-ml` service in `docker-compose.yml`.
2. Register and increment a `ml_sidecar_circuit_open_total` counter in `AtomicCircuit::record_failure()` when the circuit trips.

---

## Unregistered Threat Flags

No `## Threat Flags` sections were found in any SUMMARY.md file across plans 03-01 through 03-04.

---

## Accepted Risks Log

None declared for Phase 03.

---

## Phase 02 Threat Verification (retained)

| Threat ID | Category | Disposition | Status | Evidence |
|-----------|----------|-------------|--------|----------|
| T-02-01 | Spoofing | mitigate | CLOSED | `api_key_auth.rs:29-36` — `strip_prefix("Bearer ")` + `starts_with("sp_")` enforced; `api_key_repo.rs:86,108` — SHA-256 hash comparison via `hash_api_key()` and `WHERE key_hash = $1` query |
| T-02-02 | Elevation of Privilege | mitigate | CLOSED | `openai.rs:38-67` — `ChatCompletionsRequest`, `CompletionRequest`, `EmbeddingsRequest` contain no provider field; provider selected only via `resolve_model()` → DB-resolved `ModelTarget` |
| T-02-03 | Denial of Service | mitigate | CLOSED | `openai.rs:79-81` — `enforce_rate_limit(&state, &auth)` called before pipeline; `rate_limit.rs:62-70` — dual bucket check on `api_key:{id}` and `workspace:{id}` |
| T-02-04 | Information Disclosure | mitigate | CLOSED | `api_key_auth.rs:11-16` — `AuthContext` carries `workspace_id`; `model_router.rs:98` — cache key scoped as `{workspace_id}:{model}`; `provider_repo.rs:144,162` — `set_config('app.current_workspace_id')` + `WHERE models.workspace_id = $1` |
| T-02-05 | Information Disclosure | mitigate | CLOSED | `vault/redaction.rs` — vault is in-memory `HashMap`; no DB/Redis write paths in vault module |
| T-02-06 | Tampering | mitigate | CLOSED | `pipeline/service.rs:72-96` — stage order enforced: detect → evaluate → invoke → restore |
| T-02-07 | Elevation of Privilege | mitigate | CLOSED | `policy/engine.rs:29-95` — first-match-wins `break` on deny/allow/redact/transform/flag |
| T-02-08 | Information Disclosure | mitigate | CLOSED | `secureprompt-common/src/types.rs:89-95` — unrecognized placeholders remain as `[REDACTED:...]` |
| T-02-09 | Information Disclosure | mitigate | CLOSED | `pipeline/service.rs:72,129-143` — `sanitized_messages` sent to provider; raw prompt never forwarded |
| T-02-10 | Tampering | mitigate | CLOSED | `http/streaming.rs:23-72` — `placeholder_safe_chunks()` buffers across chunk boundaries |
| T-02-11 | Denial of Service | mitigate | CLOSED | `http/streaming.rs:75-77` — `fallback_allowed(emitted_chunks) -> bool { emitted_chunks == 0 }` |
| T-02-12 | Information Disclosure | mitigate | CLOSED | `secureprompt-common/Cargo.toml` — no reqwest/clickhouse/redis deps |
| T-02-13 | Denial of Service | mitigate | CLOSED | `analytics/clickhouse_writer.rs:37-44` — `try_send` (non-blocking); drops on full channel |
| T-02-14 | Tampering | mitigate | CLOSED | `token_usage/dispatch.rs:16-32` — provider-reported usage first; estimated fallback flagged |
| T-02-15 | Information Disclosure | mitigate | CLOSED | `observability/tracing.rs` — structured fields carry no secret material or raw content |
| T-02-16 | Denial of Service | mitigate | CLOSED | `analytics/clickhouse_writer.rs:9` — `mpsc::channel::<RequestEvent>(256)` bounded |
| T-02-17 | Information Disclosure | mitigate | CLOSED | `tests/fuzz_placeholder_boundaries.rs:6-31` — exhaustive chunk-size loop `1..=len` |
| T-02-18 | Tampering | mitigate | CLOSED | `tests/provider_fallback.rs:62-65` — `fallback_is_disallowed_after_streaming_starts` |
| T-02-19 | Denial of Service | mitigate | CLOSED | `docs/proxying/sse.md` — nginx buffering disabled; CI job runs all 5 streaming-path tests |
| T-02-20 | Elevation of Privilege | mitigate | CLOSED | All integration tests use `Bearer sp_...` API key; unauthenticated paths return 401 |
