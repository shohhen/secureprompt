# syntax=docker/dockerfile:1.7

# ---- Stage 1: dependencies + model caches ----
FROM python:3.11-slim AS deps

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

COPY secureprompt-ml/requirements.txt .

RUN pip install --no-cache-dir \
    "torch==2.6.0+cpu" \
    --extra-index-url https://download.pytorch.org/whl/cpu

RUN pip install --no-cache-dir -r requirements.txt

RUN python -m spacy download en_core_web_sm

RUN python -c "from gliner import GLiNER; GLiNER.from_pretrained('urchade/gliner_multi_pii-v1')"
RUN python -c "from transformers import pipeline; pipeline('text-classification', model='protectai/deberta-v3-base-prompt-injection-v2', device=-1)"
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')"

# ---- Stage 2: Cython compile (.py -> .so, sources stripped) ----
FROM deps AS compile

WORKDIR /build

RUN pip install --no-cache-dir "cython>=3.0,<3.1" "setuptools>=68"

COPY secureprompt-ml/app ./app
COPY secureprompt-ml/cython_build.py ./cython_build.py

RUN python cython_build.py

# ---- Stage 3: minimal runtime (no .py sources, no .pyc) ----
FROM python:3.11-slim AS runtime

WORKDIR /app

RUN mkdir -p /app/.cache/torch /app/.cache/huggingface

COPY --from=deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=deps /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=deps /root/.cache/huggingface /app/.cache/huggingface

# Compiled app: only __init__.py stubs + .so binaries + any data files
COPY --from=compile /build/app ./app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TRANSFORMERS_OFFLINE=1
ENV HF_DATASETS_OFFLINE=1
ENV HF_HOME=/app/.cache/huggingface
ENV HF_HUB_CACHE=/app/.cache/huggingface/hub
ENV TRANSFORMERS_CACHE=/app/.cache/huggingface/hub
ENV SENTENCE_TRANSFORMERS_HOME=/app/.cache/huggingface/hub
ENV TORCH_HOME=/app/.cache/torch
ENV ML_LANGUAGE=en
ENV ML_USE_ONNX=false

EXPOSE 8080

RUN useradd -m -u 1001 appuser && chown -R appuser /app
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
