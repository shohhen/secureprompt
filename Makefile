# SecurePrompt — repo-root convenience targets.
#
# DVC-tracked large binaries (datasets under data/, NER model checkpoints
# under secureprompt-ml/app/resources/) are NOT stored in git — only tiny
# `.dvc` pointer files are committed. Run the targets below after a fresh
# clone/checkout, before building images or running the ML sidecar locally.

.PHONY: dvc-pull-models

# Pulls only the two model checkpoints the ML sidecar Docker build actually
# COPYs in (the v8 active model + v7 rollback model). Required before
# `docker build -f secureprompt-ml/Dockerfile .` on a fresh checkout —
# the build COPYs app/resources/<model>/model/model.safetensors.enc
# directly from the working tree, which DVC leaves as a gitignored blob
# until pulled from the DVC remote.
dvc-pull-models:
	dvc pull secureprompt-ml/app/resources/multilingual_ner_v8_xlmr.dvc secureprompt-ml/app/resources/multilingual_ner_v7_xlmr.dvc
