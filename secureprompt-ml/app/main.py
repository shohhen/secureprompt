import asyncio
import hmac
import json
import logging
import os
import time as _time
import uuid
from contextlib import asynccontextmanager
from urllib.parse import quote
from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile, File, Response
from app import config
from app import metrics
from app.models import (
    NerRequest, NerResponse, NerEntity,
    InjectionRequest, InjectionResponse,
    EmbedRequest, EmbedResponse,
    RagCheckRequest, RagCheckResponse, RagCheckMatch,
    ScanFileEntity, ScanFileResponse,
    ScanTaskCreated, ScanTaskStatus,
    SecureTaskCreated, SecureSummary, SecureTaskStatus,
)
from app.detection.ner import _load_analyzer as _load_analyzer_base, detect
from app.detection.injection import _load_injection_pipeline, classify_injection
from app.detection.batching import drain_worker
from app.embeddings.embed import _load_embedder, embed
from app.qdrant_init import get_qdrant_client, ensure_collections
from app.rag import rag_check
from app.async_tasks import TaskStore
from app.secure_file import UnsupportedFormat, secure_file as _secure_file

_ready = asyncio.Event()
_models: dict = {}
_ner_queue: asyncio.Queue | None = None
_ner_queue_bulk: asyncio.Queue | None = None

# Module-level state for the deferred key delivery flow.
_model_key: bytes | None = None
_key_event = asyncio.Event()


def _route_queue(text: str) -> asyncio.Queue:
    """Inline lane for chat-sized texts; bulk lane for documents, so a big
    scan can never head-of-line-block interactive traffic (two drain
    workers → two independent worker threads).

    NOTE (whole-branch review, do not conflate): routing by size here picks
    a QUEUE for throughput isolation only — it does NOT change XLM-R/GLiNER
    coverage caps (see detection/scan_profile.py's inline vs. bulk
    `scan_profile`). `/detect/ner` always runs with INLINE caps regardless
    of which queue lane it lands on; only `/v1/scan-file` opts into the
    wider BULK caps.
    """
    from app import config
    if len(text) > config.NER_BULK_THRESHOLD_CHARS and _ner_queue_bulk is not None:
        return _ner_queue_bulk
    return _ner_queue


def _make_process_batch():
    async def _process_batch(texts: list[str]) -> list[list[dict]]:
        # Run the whole batch in ONE worker thread: detect() is CPU-bound
        # (torch inference) and previously starved the event loop — /health
        # and every enqueued request stalled behind a big document.
        def _run(ts: list[str]) -> list[list[dict]]:
            return [detect(_models["analyzer"], t) for t in ts]
        return await asyncio.to_thread(_run, texts)
    return _process_batch


def _load_analyzer(model_key: bytes | None = None):
    """Wrapper around the base _load_analyzer that passes the model_key
    through to maybe_register inside xlmr_ner.

    When model_key is None the behavior is identical to calling _load_analyzer_base()
    directly (backward-compatible default path).
    """
    from app.detection import xlmr_ner as _xlmr_mod

    # Monkey-patch maybe_register call inside _load_analyzer_base so we
    # can inject the key without touching ner.py.  We do this via a
    # temporary patch of xlmr_ner.maybe_register.
    original_maybe_register = _xlmr_mod.maybe_register

    if model_key is not None:
        def _patched_maybe_register(analyzer, resources_dir=None, **kwargs):
            return original_maybe_register(
                analyzer, resources_dir=resources_dir, model_key=model_key,
            )
        _xlmr_mod.maybe_register = _patched_maybe_register

    try:
        return _load_analyzer_base()
    finally:
        _xlmr_mod.maybe_register = original_maybe_register


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _ner_queue, _ner_queue_bulk
    from app import config

    # Always load these synchronous, non-encrypted models first.
    _models["injection"] = await asyncio.to_thread(_load_injection_pipeline)
    _models["embedder"] = await asyncio.to_thread(_load_embedder)
    _models["qdrant"] = await asyncio.to_thread(get_qdrant_client)
    await asyncio.to_thread(ensure_collections, _models["qdrant"])

    _ner_queue = asyncio.Queue(maxsize=100)
    _ner_queue_bulk = asyncio.Queue(maxsize=20)
    _process_batch = _make_process_batch()

    if not config.MODEL_KEY_REQUIRED:
        # Default / backward-compatible path: load XLM-R immediately,
        # set _ready, and yield to serve requests.
        _models["analyzer"] = await asyncio.to_thread(_load_analyzer)
        asyncio.create_task(
            drain_worker(_ner_queue, _process_batch, deadline_ms=50, max_batch=16)
        )
        asyncio.create_task(
            drain_worker(_ner_queue_bulk, _process_batch, deadline_ms=50, max_batch=2)
        )
        _ready.set()
        metrics.set_model_info(config.ACTIVE_NER_MODELS, config.ML_NER_BACKEND)
        metrics.set_ready(True)
        yield
    else:
        # Encrypted-weights path: spawn a background task that waits for
        # the key to arrive via POST /internal/model-key, then loads XLM-R.
        # The lifespan yields immediately so the HTTP server can serve
        # /internal/model-key and /health before the model is loaded.
        # Inference routes gate on _ready (503 until it is set).
        asyncio.create_task(
            drain_worker(_ner_queue, _process_batch, deadline_ms=50, max_batch=16)
        )
        asyncio.create_task(
            drain_worker(_ner_queue_bulk, _process_batch, deadline_ms=50, max_batch=2)
        )

        async def _wait_for_key_then_load():
            await _key_event.wait()
            _models["analyzer"] = await asyncio.to_thread(
                _load_analyzer, _model_key
            )
            _ready.set()
            metrics.set_model_info(config.ACTIVE_NER_MODELS, config.ML_NER_BACKEND)
            metrics.set_ready(True)

        asyncio.create_task(_wait_for_key_then_load())
        yield

    _models.clear()
    _ready.clear()
    metrics.set_ready(False)


# WS1-5 fail-closed boot gate: refuse to start rather than silently serve
# every detection/scan/secure-file route unauthenticated. Mirrors the
# gateway's WS1-3 default-secret gate (secureprompt-common/src/config.rs
# JwtConfig::from_env) — both raise at process/import startup, naming the
# offending env var, instead of falling back to an insecure default.
# Deliberately checked here (module import time, i.e. before `uvicorn
# app.main:app` can ever serve a request) rather than only inside a route
# handler, so a misconfigured deployment fails loudly at container start
# instead of accepting traffic it can't actually authenticate.
#
# MR1 review M12: this used to be a bare `if not config.INTERNAL_TOKEN`, which
# accepts `"   "`, `"\t"` and `"0"`. Whitespace-only is not a bypass — HTTP
# strips optional whitespace around a header value, so the header can never
# match and the sidecar merely becomes unusable in a way nothing reports — but
# `"0"` is a bootable ONE-CHARACTER shared secret on the credential that guards
# /internal/model-key, the model-IP boundary. Both are now refused at import.
#
# The 16-character floor is a deliberate availability trade, stated rather than
# hidden: a deployment running a shorter token stops booting until it is
# rotated. Every token this repo generates is longer — `scripts/init-env.sh`
# and every `docker-compose*.yml` message say `openssl rand -hex 32` (64
# chars), the Helm chart generates 32 bytes, and the test suite's own token is
# 27 characters — so this refuses hand-typed secrets, which is the population
# it is aimed at.
_MIN_INTERNAL_TOKEN_LEN = 16
_stripped_internal_token = config.INTERNAL_TOKEN.strip()

if not _stripped_internal_token:
    raise RuntimeError(
        "ML_SIDECAR_INTERNAL_TOKEN is not set (or is only whitespace) — "
        "refusing to start. Every ML-sidecar route other than /health, "
        "/ready, and /metrics requires this shared secret to authenticate "
        "the gateway. Set ML_SIDECAR_INTERNAL_TOKEN before starting the "
        "sidecar (see secureprompt-common's LicenseConfig::internal_token on "
        "the gateway side, which must be set to the same value)."
    )

if len(_stripped_internal_token) < _MIN_INTERNAL_TOKEN_LEN:
    raise RuntimeError(
        f"ML_SIDECAR_INTERNAL_TOKEN is {len(_stripped_internal_token)} "
        f"characters — refusing to start. This is the shared secret that "
        f"guards every detection, scan, secure-file and /internal/model-key "
        f"call, so it must be at least {_MIN_INTERNAL_TOKEN_LEN} characters. "
        "Generate one with `openssl rand -hex 32` and set it on both the "
        "sidecar and the gateway."
    )

# Fix-round finding: docker-compose.yml defaulted ML_SIDECAR_INTERNAL_TOKEN
# to the published placeholder `dev-sidecar-token-change-me`, which sails
# straight through the "unset/empty" check above and silently defeats the
# boot gate on a value anyone can read in the repo. Reject known
# placeholders too — same rationale and (mostly) the same list as the
# gateway's WS1-3 JwtConfig::PLACEHOLDER_SECRETS.
if config.INTERNAL_TOKEN.strip().lower() in config.PLACEHOLDER_SECRETS:
    raise RuntimeError(
        f"ML_SIDECAR_INTERNAL_TOKEN is set to the placeholder value "
        f"{config.INTERNAL_TOKEN!r} — refusing to start. Generate a real "
        "secret (e.g. `openssl rand -hex 32`) and set "
        "ML_SIDECAR_INTERNAL_TOKEN to it on both the sidecar and the "
        "gateway (secureprompt-common's LicenseConfig::internal_token)."
    )


def _valid_internal_token(auth_header: str) -> bool:
    """``hmac.compare_digest`` check against ``Bearer <ML_SIDECAR_INTERNAL_TOKEN>``.

    Shared by every authenticated route (``/internal/model-key`` plus the
    ``_require_internal_token`` dependency gating everything else) so the
    two paths can never drift apart. Always ``False`` when ``INTERNAL_TOKEN``
    is empty — never authenticate against an empty secret (belt-and-braces;
    the module-level boot gate above already prevents that state at
    startup).

    COMPARES BYTES, NOT ``str`` (MR1 review M9). ``hmac.compare_digest``
    raises ``TypeError`` when either ``str`` operand contains a character
    outside ASCII, and Starlette decodes raw header bytes as latin-1 — so
    ``Authorization: Bearer \\xc3\\xa9`` produced an UNHANDLED ``TypeError``,
    i.e. a 500 with a traceback, PRE-AUTH, on every guarded route. It failed
    closed (no bypass) but it was a one-byte unauthenticated
    error/log-amplification vector.

    latin-1 is the correct re-encoding, not utf-8: it is the codec Starlette
    decoded the wire bytes with, so ``.encode("latin-1")`` recovers exactly
    the bytes the client sent, whatever they were. A caller that hands this
    function a ``str`` carrying codepoints above U+00FF did not come off the
    wire at all; that is rejected rather than coerced.

    Still constant-time for the matching-length case, which is the property
    that matters — ``compare_digest`` on ``bytes`` is the documented
    timing-safe path.
    """
    if not config.INTERNAL_TOKEN:
        return False
    try:
        provided = auth_header.encode("latin-1")
    except UnicodeEncodeError:
        return False
    expected = f"Bearer {config.INTERNAL_TOKEN}".encode("utf-8")
    return hmac.compare_digest(provided, expected)


async def _require_internal_token(request: Request) -> None:
    """FastAPI dependency: 401s any request without a valid bearer token.

    Applied via ``dependencies=[Depends(_require_internal_token)]`` on every
    route except:

    * ``/health`` and ``/ready`` — container/k8s probes depend on these
      staying open;
    * the ``/metrics`` Prometheus scrape mount —
      monitoring/prometheus/prometheus.yml has no bearer_token configured for
      this job, and /metrics exposes only aggregate counters, no request or
      document content;
    * ``/internal/model-key`` — NOT unauthenticated. It is gated by an
      equivalent inline ``_valid_internal_token`` check in its own handler
      rather than by this dependency, because it must distinguish "no token"
      from "wrong token" in its own error shape.

    MR1 review M14: this list used to name only the first three, which reads
    as "everything else goes through this dependency" and would send a
    reviewer auditing the model-IP boundary to the wrong place. The sibling
    docstring on ``_valid_internal_token`` has always got it right.
    """
    if not _valid_internal_token(request.headers.get("authorization", "")):
        raise HTTPException(status_code=401, detail="unauthorized")


# MINOR fix-round finding: FastAPI's own /docs, /redoc, /openapi.json were
# reachable unauthenticated by default (never explicitly disabled). Gate
# them behind ML_SIDECAR_DEBUG rather than leaving the exposure accepted —
# off by default means these routes are never registered at all (404, not
# just "open"); set ML_SIDECAR_DEBUG=true for local/dev exploration only.
app = FastAPI(
    title="SecurePrompt ML Sidecar",
    lifespan=lifespan,
    docs_url="/docs" if config.ML_SIDECAR_DEBUG else None,
    redoc_url="/redoc" if config.ML_SIDECAR_DEBUG else None,
    openapi_url="/openapi.json" if config.ML_SIDECAR_DEBUG else None,
)

# Prometheus scrape endpoint. Unauthenticated, matching the API's /metrics
# (see _require_internal_token's docstring for why this stays exempt).
app.mount("/metrics", metrics.metrics_asgi_app)


@app.middleware("http")
async def _metrics_middleware(request: Request, call_next):
    """Time every request and record it via app.metrics, keyed by the
    matched route TEMPLATE (never a path with a live ID) so label
    cardinality stays bounded. Never lets a metrics failure break the
    actual response — /metrics itself is skipped to avoid the endpoint
    scraping its own request."""
    path = request.url.path
    if path == "/metrics" or path.startswith("/metrics/"):
        return await call_next(request)

    start = _time.perf_counter()
    status = "error"
    try:
        response = await call_next(request)
        status = "ok" if response.status_code < 500 else "error"
        return response
    finally:
        elapsed = _time.perf_counter() - start
        try:
            route = request.scope.get("route")
            endpoint = getattr(route, "path", None) or "unmatched"
            metrics.observe_request(endpoint, status, elapsed)
        except Exception:
            logging.getLogger("secureprompt.ml.metrics").debug(
                "metrics observe_request failed", exc_info=True
            )


@app.post("/internal/model-key")
async def set_model_key(req: Request):
    """Receive the license's WRAPPED model key from the gateway and unwrap it.

    Body: ``{ "wrapped_key": "<base64>", "lic_id": "<uuid>" }``. The plaintext
    model key never crosses the wire — the gateway relays the still-sealed blob
    and the compiled keyloader (.so, MODEL-KEK baked at build) unwraps it here.

    Authentication: ``Authorization: Bearer <ML_SIDECAR_INTERNAL_TOKEN>``.
    The token must be non-empty; an empty token always rejects.
    Uses ``hmac.compare_digest`` to avoid timing-based token leaks.

    Fail-closed: ``_model_key`` is set only after a successful unwrap; a bad blob
    returns 400 and leaves any previously-loaded key untouched.

    This endpoint is intentionally NOT gated by ``_ready`` so the gateway
    can POST the key before the model has loaded (the whole point of the
    concurrent-load design).
    """
    global _model_key

    auth = req.headers.get("authorization", "")
    if not _valid_internal_token(auth):
        raise HTTPException(status_code=401, detail="unauthorized")

    body = await req.json()
    wrapped = body.get("wrapped_key") if isinstance(body, dict) else None
    lic_id = body.get("lic_id") if isinstance(body, dict) else None
    if not isinstance(wrapped, str) or not isinstance(lic_id, str) or not wrapped or not lic_id:
        raise HTTPException(status_code=400, detail="missing wrapped_key or lic_id")
    from app.crypto import keyloader
    try:
        key = keyloader.unwrap_model_key(wrapped, lic_id)
    except Exception:
        raise HTTPException(status_code=400, detail="model key unwrap failed")
    _model_key = key
    _key_event.set()
    return {"status": "accepted"}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    return {"status": "ok"}


@app.post("/detect/ner", response_model=NerResponse, dependencies=[Depends(_require_internal_token)])
async def detect_ner(req: NerRequest):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    loop = asyncio.get_event_loop()
    future: asyncio.Future = loop.create_future()
    try:
        _route_queue(req.text).put_nowait((future, req.text))
    except asyncio.QueueFull:
        raise HTTPException(status_code=429, detail="NER queue full")
    entities_raw = await future
    entities = [NerEntity(**e) for e in entities_raw]
    metrics.record_ner(entities)
    return NerResponse(entities=entities)


@app.post("/detect/injection", response_model=InjectionResponse, dependencies=[Depends(_require_internal_token)])
async def detect_injection(req: InjectionRequest):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    result = await asyncio.to_thread(classify_injection, _models["injection"], req.text)
    return InjectionResponse(**result)


@app.post("/embed", response_model=EmbedResponse, dependencies=[Depends(_require_internal_token)])
async def embed_endpoint(req: EmbedRequest):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    embedding = await asyncio.to_thread(embed, _models["embedder"], req.text)
    return EmbedResponse(embedding=embedding)


@app.post("/v1/rag-check", response_model=RagCheckResponse, dependencies=[Depends(_require_internal_token)])
async def rag_check_endpoint(req: RagCheckRequest):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    matches_raw = await asyncio.to_thread(
        rag_check,
        _models["qdrant"],
        _models["embedder"],
        req.text,
        req.workspace_id,
    )
    matches = [RagCheckMatch(**m) for m in matches_raw]
    return RagCheckResponse(matches=matches, is_match=len(matches) > 0)


# Cap the amount of file content we decode before scanning — protects the
# sidecar from OOM on large uploads. Env-tunable; default 15 MiB (covers
# multi-page PDFs/DOCX). Chat side already allows more (nginx 25M, multer 20M),
# so this sidecar cap is the binding limit.
_SCAN_FILE_MAX_BYTES = int(os.getenv("ML_SCAN_FILE_MAX_BYTES", str(15 * 1024 * 1024)))
_SCAN_FILE_TEXT_PREVIEW = 8 * 1024  # keep redacted_text small in the response


def _redact(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Replace each (start, end) span with a `<LABEL>` placeholder.

    Spans are BYTE offsets (matching what `ner._normalize` emits so the Rust
    gateway agrees on indexing). We slice the UTF-8 representation directly
    to avoid Python's char-based indexing on non-ASCII input.
    """
    if not spans:
        return text
    spans_sorted = sorted(spans, key=lambda s: s[0])
    byte_text = text.encode("utf-8")
    parts: list[bytes] = []
    cursor = 0
    for start, end, label in spans_sorted:
        if start < cursor:
            # Overlapping — earlier span already redacted this range.
            continue
        if start > len(byte_text) or end > len(byte_text):
            continue
        parts.append(byte_text[cursor:start])
        parts.append(f"<{label}>".encode("utf-8"))
        cursor = end
    parts.append(byte_text[cursor:])
    return b"".join(parts).decode("utf-8", errors="replace")


def _redact_reversible(text: str, dets: list[dict]) -> tuple[str, dict[str, str]]:
    """Redact with REVERSIBLE ``{{Type_N}}`` tokens + return the token->value map.

    Same scheme as the gateway vault and secure-file (``build_labels``): one token
    per distinct (type, value), per-type first-appearance numbering, so the chat
    gateway can preload its vault from ``token_map`` and restore the file's PII in
    the model's response. Spans are BYTE offsets (detect() wire format)."""
    from app.secure_labels import build_labels
    labels = build_labels(sorted(dets, key=lambda d: d.get("start", 0)))
    token_map = {label: value for (_typ, value), label in labels.items()}
    if not labels:
        return text, {}
    byte_text = text.encode("utf-8")
    spans = []
    for d in dets:
        token = labels.get((d["entity_type"].upper(), d["text"]))
        if token:
            spans.append((int(d["start"]), int(d["end"]), token))
    spans.sort(key=lambda s: s[0])
    parts: list[bytes] = []
    cursor = 0
    for start, end, token in spans:
        if start < cursor or start > len(byte_text) or end > len(byte_text):
            continue
        parts.append(byte_text[cursor:start])
        parts.append(token.encode("utf-8"))
        cursor = end
    parts.append(byte_text[cursor:])
    return b"".join(parts).decode("utf-8", errors="replace"), token_map


async def _scan_impl(raw: bytes) -> ScanFileResponse:
    """Run the full scan pipeline (decode → NER → injection → secrets →
    redact) on already-read file bytes. Shared by the sync and async
    `/v1/scan-file` endpoints so their behavior stays byte-identical."""
    from app.document_scan import scan_document

    # scan_document runs in-thread and sets the bulk scan profile internally
    # (detect_all -> scan_scope("bulk")), so no outer wrapper is needed.
    doc = await asyncio.to_thread(scan_document, raw, "upload", _models["analyzer"])
    text = doc.text
    ner_raw = doc.detections

    # Prompt-injection on a bounded prefix (the model has a 2 KiB limit).
    injection_text = text[:2000]
    injection = await asyncio.to_thread(
        classify_injection, _models["injection"], injection_text
    )

    # `scan_document` (detect_all) already folded regex secrets into `ner_raw`
    # with byte offsets and an `is_secret` flag — do NOT re-scan (that duplicated
    # every secret and let a char-offset copy shadow the correct byte-offset one).
    entities = [
        ScanFileEntity(
            text=e["text"],
            label=e["entity_type"],
            score=float(e["score"]),
        )
        for e in ner_raw
    ]

    # Reversible {{Type_N}} tokens + token->value map so the chat gateway can
    # restore the file's PII in the response (see gateway vault-stash preload).
    redacted_full, token_map = _redact_reversible(text, ner_raw)
    preview_truncated = len(redacted_full) > _SCAN_FILE_TEXT_PREVIEW
    redacted_preview = redacted_full[:_SCAN_FILE_TEXT_PREVIEW]

    return ScanFileResponse(
        pii_found=any(not e.get("is_secret") for e in ner_raw),
        secrets_found=any(e.get("is_secret") for e in ner_raw),
        injection_detected=bool(injection.get("is_injection")),
        entities=entities,
        redacted_text=redacted_preview,
        file_size_bytes=len(raw),
        preview_truncated=preview_truncated,
        token_map=token_map,
    )


@app.post("/v1/scan-file", response_model=ScanFileResponse, dependencies=[Depends(_require_internal_token)])
async def scan_file_endpoint(file: UploadFile = File(...)):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")

    raw = await file.read(_SCAN_FILE_MAX_BYTES + 1)
    if len(raw) > _SCAN_FILE_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file too large (max {_SCAN_FILE_MAX_BYTES} bytes)",
        )

    return await _scan_impl(raw)


# In-memory task store for the async scan flow. No persistence, no locks —
# a single asyncio event loop gives us atomic dict access between awaits, and
# terminal entries are TTL-pruned on each new task creation so this never
# grows unbounded across a long-running sidecar process.
#
# SCALING NOTE (whole-branch review): this store is PROCESS-LOCAL. Async
# scan-file endpoints (/v1/scan-file/async + its poll/status routes) require
# `ml.replicaCount=1` (or sticky/session-affinity routing, or swapping this
# for a shared store like Redis) before horizontally scaling the ML sidecar —
# otherwise a poll request can land on a different replica than the one that
# created the task and spuriously 404. See helm/secureprompt/values.yaml's
# `ml.replicaCount`.
_scan_tasks: dict[str, dict] = {}
_SCAN_TASK_TTL_S = 15 * 60
# Cap on concurrently-running background scans — each one is a CPU-bound
# NER pass in a worker thread, so unbounded enqueueing is a trivial DoS.
_SCAN_ASYNC_MAX_RUNNING = int(os.getenv("ML_SCAN_ASYNC_MAX_RUNNING", "4"))
# Strong refs to in-flight scan tasks: the event loop only keeps a WEAK
# reference to tasks, so a create_task() result that nobody holds can be
# garbage-collected mid-flight (poller then sees "running" forever).
_scan_task_refs: set = set()


def _prune_scan_tasks() -> None:
    cutoff = _time.monotonic() - _SCAN_TASK_TTL_S
    for tid in [
        t for t, v in _scan_tasks.items()
        if v["created"] < cutoff and v["status"] != "running"
    ]:
        _scan_tasks.pop(tid, None)


@app.post("/v1/scan-file/async", response_model=ScanTaskCreated, status_code=202, dependencies=[Depends(_require_internal_token)])
async def scan_file_async(file: UploadFile = File(...)):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    raw = await file.read(_SCAN_FILE_MAX_BYTES + 1)
    if len(raw) > _SCAN_FILE_MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"file too large (max {_SCAN_FILE_MAX_BYTES} bytes)")
    _prune_scan_tasks()
    running = sum(1 for v in _scan_tasks.values() if v["status"] == "running")
    if running >= _SCAN_ASYNC_MAX_RUNNING:
        raise HTTPException(status_code=429, detail="too many concurrent scans")
    tid = uuid.uuid4().hex
    _scan_tasks[tid] = {"status": "running", "result": None, "error": None,
                        "created": _time.monotonic()}

    async def _run():
        try:
            result = await _scan_impl(raw)
            entry = _scan_tasks.get(tid)
            if entry is not None:
                entry["result"] = result
                entry["status"] = "done"
        except Exception as exc:  # fail visible, never silent
            entry = _scan_tasks.get(tid)
            if entry is not None:
                entry["status"] = "error"
                entry["error"] = str(exc)

    t = asyncio.create_task(_run())
    _scan_task_refs.add(t)
    t.add_done_callback(_scan_task_refs.discard)
    return ScanTaskCreated(task_id=tid)


@app.get("/v1/scan-file/tasks/{task_id}", response_model=ScanTaskStatus, dependencies=[Depends(_require_internal_token)])
async def scan_file_task_status(task_id: str):
    t = _scan_tasks.get(task_id)
    if t is None:
        raise HTTPException(status_code=404, detail="unknown task")
    return ScanTaskStatus(status=t["status"], result=t["result"], error=t["error"])


# Reusable async task store for the secure-file flow (see app.async_tasks).
# Same PROCESS-LOCAL scaling caveat as _scan_tasks above.
_secure_store = TaskStore(max_running=int(os.getenv("ML_SECURE_ASYNC_MAX_RUNNING", "4")))
_secure_log = logging.getLogger("secureprompt.ml.secure_file")


async def _run_secure(raw: bytes, filename: str):
    def _work():
        try:
            return _secure_file(raw, filename, _models["analyzer"])
        except UnsupportedFormat:
            # Re-raise with a fixed message so the async TaskStore never stores
            # attacker-controlled bytes — otherwise both GET .../tasks/{id}
            # (status error) and .../download (500 detail) would echo them back.
            raise UnsupportedFormat("unsupported file type") from None
        except Exception:
            # Parser errors (pdfminer/PIL/openpyxl) can embed input-derived
            # fragments. Log the real detail server-side; surface a generic
            # message so neither the status nor download surface leaks content.
            _secure_log.exception("secure-file processing failed")
            raise RuntimeError("secure-file processing failed") from None
    return await asyncio.to_thread(_work)


def _content_disposition(filename: str) -> str:
    """RFC 6266/5987 header: ASCII fallback + UTF-8 ``filename*`` so non-ASCII
    (Cyrillic/Uzbek) names don't hit Starlette's latin-1 header encoding and 500."""
    ascii_fallback = filename.encode("ascii", "replace").decode("ascii").replace('"', "")
    return "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (
        ascii_fallback, quote(filename, safe=""))


def _file_response(secured) -> Response:
    return Response(
        content=secured.data,
        media_type=secured.mime,
        headers={
            "Content-Disposition": _content_disposition(secured.filename),
            "X-Secure-Summary": json.dumps(secured.summary),
        },
    )


@app.post("/v1/secure-file", dependencies=[Depends(_require_internal_token)])
async def secure_file_sync(file: UploadFile = File(...)):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    raw = await file.read(_SCAN_FILE_MAX_BYTES + 1)
    if len(raw) > _SCAN_FILE_MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"file too large (max {_SCAN_FILE_MAX_BYTES} bytes)")
    try:
        secured = await _run_secure(raw, file.filename or "file")
    except UnsupportedFormat:
        # Do NOT echo str(e) here — UnsupportedFormat's message embeds raw
        # file bytes (`head={head!r}`); a fixed detail avoids reflecting
        # uploaded content back into the HTTP response.
        raise HTTPException(status_code=415, detail="unsupported file type")
    return _file_response(secured)


@app.post("/v1/secure-file/async", response_model=SecureTaskCreated, status_code=202, dependencies=[Depends(_require_internal_token)])
async def secure_file_async(file: UploadFile = File(...)):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    raw = await file.read(_SCAN_FILE_MAX_BYTES + 1)
    if len(raw) > _SCAN_FILE_MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"file too large (max {_SCAN_FILE_MAX_BYTES} bytes)")
    if _secure_store.at_capacity():
        raise HTTPException(status_code=429, detail="too many concurrent secure-file jobs")
    fname = file.filename or "file"
    tid = _secure_store.start(lambda: _run_secure(raw, fname))
    return SecureTaskCreated(task_id=tid)


@app.get("/v1/secure-file/tasks/{task_id}", response_model=SecureTaskStatus, dependencies=[Depends(_require_internal_token)])
async def secure_file_status(task_id: str):
    t = _secure_store.get(task_id)
    if t is None:
        raise HTTPException(status_code=404, detail="unknown task")
    if t["status"] == "done":
        return SecureTaskStatus(status="done", summary=SecureSummary(**t["result"].summary))
    if t["status"] == "error":
        return SecureTaskStatus(status="error", error=t["error"])
    return SecureTaskStatus(status="running")


@app.get("/v1/secure-file/tasks/{task_id}/download", dependencies=[Depends(_require_internal_token)])
async def secure_file_download(task_id: str):
    t = _secure_store.get(task_id)
    if t is None:
        raise HTTPException(status_code=404, detail="unknown task")
    if t["status"] == "error":
        raise HTTPException(status_code=500, detail=t["error"])
    if t["status"] != "done":
        raise HTTPException(status_code=409, detail="not ready")
    return _file_response(t["result"])
