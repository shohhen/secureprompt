import os

ML_LANGUAGE: str = os.getenv("ML_LANGUAGE", "en")
ML_USE_ONNX: bool = os.getenv("ML_USE_ONNX", "false").lower() == "true"
ML_SIDECAR_PORT: int = int(os.getenv("ML_SIDECAR_PORT", "8080"))

# Which fine-tuned NER checkpoint(s) under app/resources/*_ner*/ to load.
#
# Several v2/v3 checkpoints ship in the image, but loading all of them runs
# 3+ XLM-R models (~1.1 GB each) on every ru/uz request for no benefit. This
# selects the active set: a comma-separated list of resource directory names.
#
# Default: `multilingual_ner_v3_no_ssn_xlmr` — empirically the best of the v3
# checkpoints (see scripts/compare_v3_models.py / compare_v3_models_report.txt:
# higher non-O macro+micro F1 than v3 in ru/uz/uz_cyrl, statistically tied on
# the shared labels, and it defers SSN to the gateway regex instead of carrying
# a head that scores 0.0 F1 on SSN). Set to another dir name to A/B, a
# comma-separated list to run several, or `all`/`*` to register every
# discovered checkpoint (legacy auto-discover-everything behaviour).
ACTIVE_NER_MODELS: str = os.getenv("ACTIVE_NER_MODELS", "multilingual_ner_v3_no_ssn_xlmr")
