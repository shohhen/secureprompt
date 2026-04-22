import os

ML_LANGUAGE: str = os.getenv("ML_LANGUAGE", "en")
ML_USE_ONNX: bool = os.getenv("ML_USE_ONNX", "false").lower() == "true"
ML_SIDECAR_PORT: int = int(os.getenv("ML_SIDECAR_PORT", "8080"))
