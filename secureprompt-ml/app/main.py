import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, UploadFile, File
from app.models import (
    NerRequest, NerResponse, NerEntity,
    InjectionRequest, InjectionResponse,
    EmbedRequest, EmbedResponse,
    RagCheckRequest, RagCheckResponse, RagCheckMatch,
    ScanFileEntity, ScanFileResponse,
)
from app.detection.ner import _load_analyzer, detect
from app.detection.injection import _load_injection_pipeline, classify_injection
from app.detection.batching import drain_worker
from app.detection.secrets import scan_secrets
from app.embeddings.embed import _load_embedder, embed
from app.qdrant_init import get_qdrant_client, ensure_collections
from app.rag import rag_check

_ready = asyncio.Event()
_models: dict = {}
_ner_queue: asyncio.Queue | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _ner_queue
    _models["analyzer"] = await asyncio.to_thread(_load_analyzer)
    _models["injection"] = await asyncio.to_thread(_load_injection_pipeline)
    _models["embedder"] = await asyncio.to_thread(_load_embedder)
    _models["qdrant"] = await asyncio.to_thread(get_qdrant_client)
    await asyncio.to_thread(ensure_collections, _models["qdrant"])
    _ner_queue = asyncio.Queue(maxsize=100)

    async def _process_batch(texts: list[str]) -> list[list[dict]]:
        return [detect(_models["analyzer"], t) for t in texts]

    asyncio.create_task(
        drain_worker(_ner_queue, _process_batch, deadline_ms=50, max_batch=16)
    )
    _ready.set()
    yield
    _models.clear()
    _ready.clear()


app = FastAPI(title="SecurePrompt ML Sidecar", lifespan=lifespan)


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
