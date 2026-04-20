import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from app.models import (
    NerRequest, NerResponse, NerEntity,
    InjectionRequest, InjectionResponse,
    EmbedRequest, EmbedResponse,
    RagCheckRequest, RagCheckResponse, RagCheckMatch,
)
from app.detection.ner import _load_analyzer, detect
from app.detection.injection import _load_injection_pipeline, classify_injection
from app.detection.batching import drain_worker
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
