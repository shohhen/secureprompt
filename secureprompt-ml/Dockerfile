# syntax=docker/dockerfile:1.7
#
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  ENCRYPT THE WEIGHTS ON THE HOST BEFORE BUILDING                          ║
# ║                                                                            ║
# ║  This image ships ONLY the AES-256-GCM encrypted weights                  ║
# ║  (model.safetensors.enc). The plaintext model.safetensors is excluded     ║
# ║  from the build context by .dockerignore, so it never lands in any layer.  ║
# ║                                                                            ║
# ║  1. Encrypt on the host (once, whenever the weights or key change):        ║
# ║       python secureprompt-ml/scripts/encrypt_weights.py \                  ║
# ║         --input  .../model/model.safetensors \                             ║
# ║         --output .../model/model.safetensors.enc \                         ║
# ║         --key-hex \"$(cat secrets/model_key.hex)\"                          ║
# ║                                                                            ║
# ║  2. Build normally (no BuildKit secrets needed):                           ║
# ║       docker build -t secureprompt-ml -f secureprompt-ml/Dockerfile .     ║
# ║                                                                            ║
# ║  model_key.hex must contain exactly 64 hex chars (32-byte AES key).       ║
# ║  The same key is sealed into each license by sp-admin. At runtime the     ║
# ║  gateway relays the still-wrapped key + lic_id and the sidecar .so        ║
# ║  (MODEL-KEK baked at build) unwraps it. Plaintext keys never transit.     ║
# ║                                                                            ║
# ║  Without a valid license the sidecar never receives the decryption key     ║
# ║  and stays 503 — the gateway falls back to regex-only (fail-open) mode.   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

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

# Bake the default English NER model (GLiNER2-PII) into the image cache.
RUN python -c "from gliner2 import GLiNER2; GLiNER2.from_pretrained('fastino/gliner2-privacy-filter-PII-multi')"
RUN python -c "from transformers import pipeline; pipeline('text-classification', model='protectai/deberta-v3-base-prompt-injection-v2', device=-1)"
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')"

# ---- Stage 2: Cython compile (.py -> .so, sources stripped) ----
FROM deps AS compile

WORKDIR /build

RUN pip install --no-cache-dir "cython>=3.0,<3.1" "setuptools>=68"

COPY secureprompt-ml/app ./app
COPY secureprompt-ml/cython_build.py ./cython_build.py

# Bake the MODEL-KEK into the compiled keyloader. This is the key-encryption-key
# that unwraps each license's sealed model key (license model.wrapped_key) — it is
# NOT the weight-encryption key model_key.hex from the header. No default: it must
# be supplied via a protected CI variable and is never committed (the in-repo
# app/crypto/_keyconst.py ships empty). The generated _keyconst.py below is
# Cython-compiled to a .so and its source stripped by cython_build.py, so the KEK
# exists only inside the compiled binary in the final image.
ARG SECUREPROMPT_PINNED_MODEL_KEK
RUN test -n "$SECUREPROMPT_PINNED_MODEL_KEK" \
    || (echo "ERROR: SECUREPROMPT_PINNED_MODEL_KEK build-arg is required" && exit 1)
RUN printf 'MODEL_KEK_B64 = "%s"\n' "$SECUREPROMPT_PINNED_MODEL_KEK" > app/crypto/_keyconst.py

RUN python cython_build.py

# ---- Stage 3: minimal runtime (no .py sources, no .pyc) ----
FROM python:3.11-slim AS runtime

WORKDIR /app

# OCR fallback for /v1/scan-file: pytesseract shells out to `tesseract`, and
# pdf2image shells out to poppler's `pdftoppm`. Language packs: eng (base) + rus
# + Uzbek (Latin & Cyrillic). Runtime binaries only — no build toolchain.
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr tesseract-ocr-rus tesseract-ocr-uzb tesseract-ocr-uzb-cyrl \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/.cache/torch /app/.cache/huggingface

COPY --from=deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=deps /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=deps /root/.cache/huggingface /app/.cache/huggingface

# Compiled app: only __init__.py stubs + .so binaries + any data files.
# NOTE: plaintext model.safetensors is intentionally NOT copied here.
#       Only the AES-256-GCM encrypted variant is included (see below).
COPY --from=compile /build/app ./app

# Ship ONLY the encrypted weights — the plaintext file never touches this layer.
# The .enc is produced on the host (see the header) and rides in via the build
# context; .dockerignore excludes the plaintext model.safetensors next to it.
# Active model dir: multilingual_ner_v7_xlmr (ACTIVE_NER_MODELS default). v5_cold's .enc is
# also shipped so a rollback is an ACTIVE_NER_MODELS env change, not a rebuild.
# To switch checkpoints, change both ACTIVE_NER_MODELS and (for a NEW checkpoint) add a COPY.
COPY secureprompt-ml/app/resources/multilingual_ner_v7_xlmr/model/model.safetensors.enc \
     /app/app/resources/multilingual_ner_v7_xlmr/model/model.safetensors.enc
COPY secureprompt-ml/app/resources/multilingual_ner_v5_cold_xlmr/model/model.safetensors.enc \
     /app/app/resources/multilingual_ner_v5_cold_xlmr/model/model.safetensors.enc

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
# Require the gateway to push a valid model decryption key before serving.
# Without a matching key (sealed in a customer license by sp-admin) the weights
# remain encrypted and the sidecar returns 503; the gateway falls back to
# regex-only detection (fail-open).  Set to "false" only in dev with plaintext
# weights and no license enforcement.
ENV SECUREPROMPT_MODEL_KEY_REQUIRED=true

EXPOSE 8080

RUN useradd -m -u 1001 appuser && chown -R appuser /app
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
