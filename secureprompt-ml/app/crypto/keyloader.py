"""Model-key unwrap. Mirrors sp-license seal wire format byte-for-byte:
base64-STANDARD(nonce[12] || ciphertext+16B GCM tag), AES-256-GCM, AAD = f"{lic_id}:model".
The MODEL-KEK is baked into _keyconst at Docker build time and compiled into this .so."""
from __future__ import annotations
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.crypto import _keyconst

_NONCE_LEN = 12


def _model_kek() -> bytes:
    b64 = _keyconst.MODEL_KEK_B64
    if not b64:
        raise RuntimeError("MODEL-KEK not baked into build")
    kek = base64.b64decode(b64, validate=True)
    if len(kek) != 32:
        raise RuntimeError("MODEL-KEK must be 32 bytes")
    return kek


def unwrap_model_key(wrapped_b64: str, lic_id: str) -> bytes:
    """Recover the 32-byte model_key. Raises on wrong key / AAD / format (fail-closed)."""
    blob = base64.b64decode(wrapped_b64, validate=True)
    if len(blob) < _NONCE_LEN + 16:
        raise ValueError("wrapped blob too short")
    nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    aad = f"{lic_id}:model".encode()
    key = AESGCM(_model_kek()).decrypt(nonce, ct, aad)
    if len(key) != 32:
        raise ValueError("unwrapped model key must be 32 bytes")
    return key
