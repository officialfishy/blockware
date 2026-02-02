from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import time
from typing import List, Optional

from .crypto import Keypair, generate_keypair

DEFAULT_DIR = Path.home() / ".blockware"
WALLETS_DIR = DEFAULT_DIR / "wallets"

@dataclass
class Wallet:
    name: str
    created_at: int
    algo: str
    keypairs: List[Keypair]
    threshold: int

    @property
    def n(self) -> int:
        return len(self.keypairs)

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "created_at": self.created_at,
            "algo": self.algo,
            "threshold": self.threshold,
            "n": self.n,
            "addresses": [kp.address for kp in self.keypairs],
            "keypairs": [
                {
                    "address": kp.address,
                    "public_key_hex": kp.public_key_hex,
                    "private_key_hex": kp.private_key_hex,
                }
                for kp in self.keypairs
            ],
        }

def ensure_dirs() -> None:
    WALLETS_DIR.mkdir(parents=True, exist_ok=True)

def wallet_path(name: str) -> Path:
    return WALLETS_DIR / f"{name}.json"

def create_wallet(
    n_signers: int,
    algo: str = "sha256",
    threshold: Optional[int] = None,
    name: Optional[str] = None,
) -> Wallet:
    if n_signers <= 0:
        raise ValueError("n_signers must be >= 1")

    if threshold is None:
        threshold = n_signers

    if threshold <= 0 or threshold > n_signers:
        raise ValueError("threshold must be between 1 and n_signers")

    ensure_dirs()

    if not name:
        name = f"wallet_{n_signers}s_{threshold}m_{int(time.time())}"

    keypairs: List[Keypair] = [generate_keypair(algo) for _ in range(n_signers)]
    return Wallet(
        name=name,
        created_at=int(time.time()),
        algo=algo,
        keypairs=keypairs,
        threshold=threshold,
    )

def save_wallet(wallet: Wallet) -> Path:
    ensure_dirs()
    path = wallet_path(wallet.name)
    if path.exists():
        raise FileExistsError(f"Wallet '{wallet.name}' already exists at {path}")

    path.write_text(json.dumps(wallet.to_json(), indent=2), encoding="utf-8")
    return path
