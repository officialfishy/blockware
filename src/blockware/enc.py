from __future__ import annotations

import base64, json, os
from dataclasses import dataclass
from typing import Any, Dict

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class EncBlob:
    kdf: str
    salt_b64: str
    nonce_b64: str
    ct_b64: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "kdf": self.kdf,
            "salt_b64": self.salt_b64,
            "nonce_b64": self.nonce_b64,
            "ct_b64": self.ct_b64,
        }


def _derive_key(password: str, salt: bytes) -> bytes:
    # 32-byte key for AES-256-GCM
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_json(password: str, data: Dict[str, Any]) -> Dict[str, Any]:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)

    pt = json.dumps(data).encode("utf-8")
    ct = aes.encrypt(nonce, pt, None)

    blob = EncBlob(
        kdf="scrypt(n=32768,r=8,p=1)",
        salt_b64=base64.b64encode(salt).decode(),
        nonce_b64=base64.b64encode(nonce).decode(),
        ct_b64=base64.b64encode(ct).decode(),
    )
    return {"encrypted": True, "enc": blob.to_dict()}


def decrypt_json(password: str, wrapped: Dict[str, Any]) -> Dict[str, Any]:
    if not wrapped.get("encrypted"):
        raise ValueError("File is not encrypted (missing encrypted=true).")

    enc = wrapped["enc"]
    salt = base64.b64decode(enc["salt_b64"])
    nonce = base64.b64decode(enc["nonce_b64"])
    ct = base64.b64decode(enc["ct_b64"])

    key = _derive_key(password, salt)
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))
