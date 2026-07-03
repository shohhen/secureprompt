import os

ML_LANGUAGE: str = os.getenv("ML_LANGUAGE", "en")
ML_USE_ONNX: bool = os.getenv("ML_USE_ONNX", "false").lower() == "true"
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
ACTIVE_NER_MODELS: str = os.getenv("ACTIVE_NER_MODELS", "multilingual_ner_v5_cold_xlmr")

# Texts longer than this (in characters) route to the bulk NER queue instead
# of the inline one, so a single large document can't head-of-line-block
# chat-sized requests behind it (P2-9, two-lane queue).
NER_BULK_THRESHOLD_CHARS: int = int(os.getenv("NER_BULK_THRESHOLD_CHARS", "8192"))
