"""AES-256-GCM weight encryption. Wire format: nonce(12) || ciphertext+tag (raw bytes)."""
from __future__ import annotations
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TAG_LEN = 16

def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("model key must be 32 bytes")
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)  # aad None == b""
    return nonce + ct

def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag on wrong key / tamper."""
    if len(key) != 32:
        raise ValueError("model key must be 32 bytes")
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise ValueError("ciphertext too short")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, None)

def encrypt_file(src: Path, dst: Path, key: bytes) -> None:
    Path(dst).write_bytes(encrypt_bytes(Path(src).read_bytes(), key))

def decrypt_file_to(src_enc: Path, dst: Path, key: bytes) -> None:
    Path(dst).write_bytes(decrypt_bytes(Path(src_enc).read_bytes(), key))
