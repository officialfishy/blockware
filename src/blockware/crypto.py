from __future__ import annotations

from dataclasses import dataclass
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

SUPPORTED_ADDR_ALGOS = {"sha256", "sha3_256", "blake2b"}

@dataclass(frozen=True)
class Keypair:
    private_key_hex: str
    public_key_hex: str
    address: str
    algo: str

def _hash_bytes(algo: str, data: bytes) -> bytes:
    algo = algo.lower()
    if algo == "sha256":
        return hashlib.sha256(data).digest()
    if algo == "sha3_256":
        return hashlib.sha3_256(data).digest()
    if algo == "blake2b":
        return hashlib.blake2b(data, digest_size=32).digest()
    raise ValueError(f"Unsupported address algo: {algo}. Supported: {sorted(SUPPORTED_ADDR_ALGOS)}")

def _pubkey_bytes_uncompressed(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

def generate_keypair(addr_algo: str = "sha256") -> Keypair:
    addr_algo = addr_algo.lower()
    if addr_algo not in SUPPORTED_ADDR_ALGOS:
        raise ValueError(f"Unsupported address algo: {addr_algo}. Supported: {sorted(SUPPORTED_ADDR_ALGOS)}")

    priv = ec.generate_private_key(ec.SECP256K1())
    pub = priv.public_key()

    priv_int = priv.private_numbers().private_value
    priv_bytes = priv_int.to_bytes(32, "big")
    pub_bytes = _pubkey_bytes_uncompressed(pub)

    h = _hash_bytes(addr_algo, pub_bytes)
    addr = "bw_" + h[:20].hex()

    return Keypair(
        private_key_hex=priv_bytes.hex(),
        public_key_hex=pub_bytes.hex(),
        address=addr,
        algo=addr_algo,
    )
