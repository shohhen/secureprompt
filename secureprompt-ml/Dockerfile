# syntax=docker/dockerfile:1.7
#
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  BUILD-TIME SECRETS REQUIRED                                               ║
# ║                                                                            ║
# ║  This image ships ONLY the AES-256-GCM encrypted weights                  ║
# ║  (model.safetensors.enc). Plaintext weights never land in any layer.       ║
# ║                                                                            ║
# ║  Build command (requires BuildKit):                                        ║
# ║    DOCKER_BUILDKIT=1 docker build \                                        ║
# ║      --secret id=model_weights,src=/path/to/model.safetensors \            ║
# ║      --secret id=model_key,src=/path/to/model_key.hex \                   ║
# ║      -t secureprompt-ml .                                                  ║
# ║                                                                            ║
# ║  model_key.hex must contain exactly 64 hex chars (32-byte AES key).       ║
# ║  The same key must be sealed into customer licenses by sp-admin so the     ║
# ║  gateway can push it via ML_SIDECAR_INTERNAL_TOKEN + the license's         ║
# ║  sealed model key at runtime.                                              ║
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

# ---- Stage 3: encrypt the fine-tuned weights (plaintext never lands in a layer) ----
# Requires BuildKit secrets at build time:
#   --secret id=model_weights,src=path/to/model.safetensors
#   --secret id=model_key,src=path/to/model_key.hex   (64 hex chars = the 32-byte model key)
# The same key must be sealed into customer licenses by sp-admin.
FROM python:3.11-slim AS encrypt-weights

RUN pip install --no-cache-dir cryptography

# Copy the encryption script and the crypto package it imports from (app.crypto.weights).
# encrypt_weights.py does: sys.path.insert(0, parent.parent) — when the script lives at
# /encrypt_weights.py its parent.parent is /, so /app/crypto must be present.
COPY secureprompt-ml/scripts/encrypt_weights.py /encrypt_weights.py
COPY secureprompt-ml/app/crypto /app/crypto

# Run the encryption.  Both secrets are mounted read-only and are never written
# to the image filesystem — they exist only for the duration of this RUN step.
RUN --mount=type=secret,id=model_weights,target=/model.safetensors \
    --mount=type=secret,id=model_key,target=/model_key.hex \
    python /encrypt_weights.py \
      --input /model.safetensors \
      --output /model.safetensors.enc \
      --key-hex "$(cat /model_key.hex)"

# ---- Stage 4: minimal runtime (no .py sources, no .pyc) ----
FROM python:3.11-slim AS runtime

WORKDIR /app

RUN mkdir -p /app/.cache/torch /app/.cache/huggingface

COPY --from=deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=deps /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=deps /root/.cache/huggingface /app/.cache/huggingface

# Compiled app: only __init__.py stubs + .so binaries + any data files.
# NOTE: plaintext model.safetensors is intentionally NOT copied here.
#       Only the AES-256-GCM encrypted variant is included (see below).
COPY --from=compile /build/app ./app

# Ship ONLY the encrypted weights — the plaintext file never touches this layer.
# Active model dir: multilingual_ner_v3_no_ssn_xlmr (ACTIVE_NER_MODELS default).
# To switch checkpoints, change both the src dir below and ACTIVE_NER_MODELS at runtime.
COPY --from=encrypt-weights /model.safetensors.enc \
     /app/app/resources/multilingual_ner_v3_no_ssn_xlmr/model/model.safetensors.enc

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
