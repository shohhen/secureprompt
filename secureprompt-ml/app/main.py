import asyncio
import hmac
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from app.models import (
    NerRequest, NerResponse, NerEntity,
    InjectionRequest, InjectionResponse,
    EmbedRequest, EmbedResponse,
    RagCheckRequest, RagCheckResponse, RagCheckMatch,
    ScanFileEntity, ScanFileResponse,
)
from app.detection.ner import _load_analyzer as _load_analyzer_base, detect
from app.detection.injection import _load_injection_pipeline, classify_injection
from app.detection.batching import drain_worker
from app.detection.secrets import scan_secrets
from app.embeddings.embed import _load_embedder, embed
from app.qdrant_init import get_qdrant_client, ensure_collections
from app.rag import rag_check

_ready = asyncio.Event()
_models: dict = {}
_ner_queue: asyncio.Queue | None = None

# Module-level state for the deferred key delivery flow.
_model_key: bytes | None = None
_key_event = asyncio.Event()


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
    global _ner_queue
    from app import config

    # Always load these synchronous, non-encrypted models first.
    _models["injection"] = await asyncio.to_thread(_load_injection_pipeline)
    _models["embedder"] = await asyncio.to_thread(_load_embedder)
    _models["qdrant"] = await asyncio.to_thread(get_qdrant_client)
    await asyncio.to_thread(ensure_collections, _models["qdrant"])

    _ner_queue = asyncio.Queue(maxsize=100)

    async def _process_batch(texts: list[str]) -> list[list[dict]]:
        return [detect(_models["analyzer"], t) for t in texts]

    if not config.MODEL_KEY_REQUIRED:
        # Default / backward-compatible path: load XLM-R immediately,
        # set _ready, and yield to serve requests.
        _models["analyzer"] = await asyncio.to_thread(_load_analyzer)
        asyncio.create_task(
            drain_worker(_ner_queue, _process_batch, deadline_ms=50, max_batch=16)
        )
        _ready.set()
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

        async def _wait_for_key_then_load():
            await _key_event.wait()
            _models["analyzer"] = await asyncio.to_thread(
                _load_analyzer, _model_key
            )
            _ready.set()

        asyncio.create_task(_wait_for_key_then_load())
        yield

    _models.clear()
    _ready.clear()


app = FastAPI(title="SecurePrompt ML Sidecar", lifespan=lifespan)


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
    from app import config
    global _model_key

    auth = req.headers.get("authorization", "")
    expected = f"Bearer {config.INTERNAL_TOKEN}"
    if not config.INTERNAL_TOKEN or not hmac.compare_digest(auth, expected):
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


@app.post("/detect/ner", response_model=NerResponse)
async def detect_ner(req: NerRequest):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    loop = asyncio.get_event_loop()
    future: asyncio.Future = loop.create_future()
    try:
        _ner_queue.put_nowait((future, req.text))
    except asyncio.QueueFull:
        raise HTTPException(status_code=429, detail="NER queue full")
    entities_raw = await future
    entities = [NerEntity(**e) for e in entities_raw]
    return NerResponse(entities=entities)


@app.post("/detect/injection", response_model=InjectionResponse)
async def detect_injection(req: InjectionRequest):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    result = await asyncio.to_thread(classify_injection, _models["injection"], req.text)
    return InjectionResponse(**result)


@app.post("/embed", response_model=EmbedResponse)
async def embed_endpoint(req: EmbedRequest):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")
    embedding = await asyncio.to_thread(embed, _models["embedder"], req.text)
    return EmbedResponse(embedding=embedding)


@app.post("/v1/rag-check", response_model=RagCheckResponse)
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
# sidecar from OOM on large uploads. 2 MiB is enough for any reasonable text
# prompt or config file; PDFs are handled best-effort.
_SCAN_FILE_MAX_BYTES = 2 * 1024 * 1024
_SCAN_FILE_TEXT_PREVIEW = 8 * 1024  # keep redacted_text small in the response


def _decode_best_effort(data: bytes) -> str:
    """Decode file bytes to text. PDFs/DOCX are extracted lazily when the
    corresponding library is installed; otherwise fall back to latin-1 so we
    can still run regex + NER on whatever printable ASCII is embedded."""
    head = data[:4]
    # PDF
    if head == b"%PDF":
        try:
            from pypdf import PdfReader  # type: ignore
            import io
            reader = PdfReader(io.BytesIO(data))
            return "\n".join((p.extract_text() or "") for p in reader.pages)
        except Exception:
            pass
    # DOCX (zip + word/document.xml)
    if head[:2] == b"PK":
        try:
            import docx  # type: ignore
            import io
            doc = docx.Document(io.BytesIO(data))
            return "\n".join(p.text for p in doc.paragraphs)
        except Exception:
            pass
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


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


@app.post("/v1/scan-file", response_model=ScanFileResponse)
async def scan_file_endpoint(file: UploadFile = File(...)):
    if not _ready.is_set():
        raise HTTPException(status_code=503, detail="loading")

    raw = await file.read(_SCAN_FILE_MAX_BYTES + 1)
    if len(raw) > _SCAN_FILE_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"file too large (max {_SCAN_FILE_MAX_BYTES} bytes)",
        )

    text = await asyncio.to_thread(_decode_best_effort, raw)

    # NER (PII) detection — same analyzer as /detect/ner.
    ner_raw = await asyncio.to_thread(detect, _models["analyzer"], text)

    # Prompt-injection on a bounded prefix (the model has a 2 KiB limit).
    injection_text = text[:2000]
    injection = await asyncio.to_thread(
        classify_injection, _models["injection"], injection_text
    )

    # Secret regexes on the full decoded text.
    secret_hits = scan_secrets(text)

    entities = [
        ScanFileEntity(
            text=e["text"],
            label=e["entity_type"],
            score=float(e["score"]),
        )
        for e in ner_raw
    ]
    # Include secrets as entities too so the UI can list them.
    for s in secret_hits:
        entities.append(
            ScanFileEntity(text=s.text, label=s.kind.upper(), score=1.0)
        )

    spans: list[tuple[int, int, str]] = [
        (int(e["start"]), int(e["end"]), e["entity_type"].upper()) for e in ner_raw
    ]
    spans.extend((s.start, s.end, s.kind.upper()) for s in secret_hits)

    redacted_full = _redact(text, spans)
    preview_truncated = len(redacted_full) > _SCAN_FILE_TEXT_PREVIEW
    redacted_preview = redacted_full[:_SCAN_FILE_TEXT_PREVIEW]

    return ScanFileResponse(
        pii_found=bool(ner_raw),
        secrets_found=bool(secret_hits),
        injection_detected=bool(injection.get("is_injection")),
        entities=entities,
        redacted_text=redacted_preview,
        file_size_bytes=len(raw),
        preview_truncated=preview_truncated,
    )
