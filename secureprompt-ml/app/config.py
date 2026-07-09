import os

ML_LANGUAGE: str = os.getenv("ML_LANGUAGE", "en")
ML_USE_ONNX: bool = os.getenv("ML_USE_ONNX", "false").lower() == "true"

# Which EN PII recognizer backend to register in place of the default GLiNER
# slot. "gliner" (default) is the current `gliner_multi_pii-v1` recognizer.
# "gliner2" swaps in the GLiNER2-PII recognizer (app/detection/gliner2_ner.py,
# P1-5) — requires the optional `gliner2` dependency
# (requirements-optional.txt) plus transformers>=5 image validation.
ML_NER_BACKEND: str = os.getenv("ML_NER_BACKEND", "gliner2").lower()
ML_SIDECAR_PORT: int = int(os.getenv("ML_SIDECAR_PORT", "8080"))
INTERNAL_TOKEN: str = os.getenv("ML_SIDECAR_INTERNAL_TOKEN", "")
MODEL_KEY_REQUIRED: bool = os.getenv("SECUREPROMPT_MODEL_KEY_REQUIRED", "false").lower() in ("1", "true", "yes")

# Which fine-tuned NER checkpoint(s) under app/resources/*_ner*/ to load.
#
# Several v2/v3/v4 checkpoints ship in the image, but loading all of them runs
# 3+ XLM-R models (~1.1 GB each) on every ru/uz request for no benefit. This
# selects the active set: a comma-separated list of resource directory names.
#
# Default: `multilingual_ner_v5_cold_xlmr` (v5 cold-start on the 2026-06-23
# trilingual dataset — 24k rows, 42 entity labels). In a 3-way held-out-test
# comparison it won every language: non-O macro/micro F1 0.9405/0.9512 overall
# (ru 0.9515, uz_latn 0.9385, uz_cyrl 0.9271), beating both the v4_aug baseline
# (0.6928 macro on the same test) and the warm-start variant
# `multilingual_ner_v5_warm_xlmr` (0.9096). It closes the long-standing
# uz_cyrillic gap (+0.32 macro vs v4). Earlier defaults: `multilingual_ner_v4_aug_xlmr`
# (v4 retrain + augmentation), and before that `multilingual_ner_v3_no_ssn_xlmr`
# (deferred SSN to the gateway regex). Set to another dir name to A/B, a
# comma-separated list to run several, or `all`/`*` to register every
# discovered checkpoint (legacy auto-discover-everything behaviour).
ACTIVE_NER_MODELS: str = os.getenv("ACTIVE_NER_MODELS", "multilingual_ner_v7_xlmr")

# Texts longer than this (in characters) route to the bulk NER queue instead
# of the inline one, so a single large document can't head-of-line-block
# chat-sized requests behind it (P2-9, two-lane queue).
NER_BULK_THRESHOLD_CHARS: int = int(os.getenv("NER_BULK_THRESHOLD_CHARS", "8192"))

# GLiNER chunk size and overlap for Presidio. Default 250-char chunks were ~3x
# slower than necessary: recall is flat up to ~2000 chars and collapses past the
# model's 384-word cap (~2.3k chars EN). Findings 2026-07-03.
ML_GLINER_CHUNK_SIZE: int = int(os.getenv("ML_GLINER_CHUNK_SIZE", "1000"))
ML_GLINER_CHUNK_OVERLAP: int = int(os.getenv("ML_GLINER_CHUNK_OVERLAP", "100"))

# Route each contiguous same-language line block through the analyzer with
# that block's own language, instead of detecting one language for the whole
# document. A single whole-doc language call gates entire model families
# (XLM-R ru/uz, English-gated GLiNER) off minority-language content — an EN
# doc with one RU paragraph scored 0.00 recall on that paragraph (findings
# 2026-07-03, P1-6). Single-language documents still take the original
# single-scope fast path (identical behaviour), so this only changes output
# for genuinely mixed-language text. Disable to fall back to the legacy
# whole-document language_scope path.
ML_SEGMENT_LANG_ROUTING: bool = os.getenv("ML_SEGMENT_LANG_ROUTING", "true").lower() == "true"

# Normalize text before NER (remove zero-width/format chars, join line-break
# hyphens, NBSP->space, control/PUA->space) with offset back-mapping so spans
# still point into the original. Default on; disable to fall back to raw text.
ML_NORMALIZE_NER: bool = os.getenv("ML_NORMALIZE_NER", "true").lower() == "true"
