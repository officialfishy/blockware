from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import time
from typing import List, Optional, Dict, Any

from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes

from .crypto import Keypair
from .enc import encrypt_json, decrypt_json

DEFAULT_DIR = Path.home() / ".blockware"
WALLETS_DIR = DEFAULT_DIR / "wallets"


@dataclass
class Wallet:
    name: str
    created_at: int
    algo: str
    keypairs: List[Keypair]
    threshold: int
    mnemonic: Optional[str] = None  # only for seed wallets (store encrypted)

    @property
    def n(self) -> int:
        return len(self.keypairs)

    def to_json_plain(self) -> dict:
        # plaintext structure (we will encrypt before saving)
        return {
            "name": self.name,
            "created_at": self.created_at,
            "algo": self.algo,
            "threshold": self.threshold,
            "n": self.n,
            "mnemonic": self.mnemonic,
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


def _words_num(words: int) -> Bip39WordsNum:
    mapping = {
        12: Bip39WordsNum.WORDS_NUM_12,
        15: Bip39WordsNum.WORDS_NUM_15,
        18: Bip39WordsNum.WORDS_NUM_18,
        21: Bip39WordsNum.WORDS_NUM_21,
        24: Bip39WordsNum.WORDS_NUM_24,
    }
    if words not in mapping:
        raise ValueError("Mnemonic words must be one of: 12, 15, 18, 21, 24")
    return mapping[words]


def _derive_keypairs_from_mnemonic(mnemonic: str, n_signers: int, addr_algo: str) -> List[Keypair]:
    # Use BIP44 Ethereum coin path for deterministic keys.
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    # Ethereum derivation (secp256k1)
    bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    acc = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)

    keypairs: List[Keypair] = []
    for i in range(n_signers):
        node = acc.AddressIndex(i)
        priv_bytes = node.PrivateKey().Raw().ToBytes()
        pub_bytes = node.PublicKey().RawUncompressed().ToBytes()

        # address using your "bw_" + hash(pubkey) style (same as before)
        # do the hashing here (keeps compatibility with your earlier approach)
        from .crypto import SUPPORTED_ADDR_ALGOS, _hash_bytes  # type: ignore
        if addr_algo.lower() not in SUPPORTED_ADDR_ALGOS:
            raise ValueError(f"Unsupported algo: {addr_algo}")

        h = _hash_bytes(addr_algo.lower(), pub_bytes)
        addr = "bw_" + h[:20].hex()

        keypairs.append(
            Keypair(
                private_key_hex=priv_bytes.hex(),
                public_key_hex=pub_bytes.hex(),
                address=addr,
                algo=addr_algo.lower(),
            )
        )

    return keypairs


def create_seed_wallet(
    n_signers: int,
    mnemonic_words: int,
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
        name = f"seedwallet_{n_signers}s_{threshold}m_{int(time.time())}"

    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(_words_num(mnemonic_words))
    mnemonic_str = str(mnemonic)

    keypairs = _derive_keypairs_from_mnemonic(mnemonic_str, n_signers, algo)

    return Wallet(
        name=name,
        created_at=int(time.time()),
        algo=algo,
        keypairs=keypairs,
        threshold=threshold,
        mnemonic=mnemonic_str,
    )


def save_wallet_encrypted(wallet: Wallet, password: str) -> Path:
    ensure_dirs()
    path = wallet_path(wallet.name)
    if path.exists():
        raise FileExistsError(f"Wallet '{wallet.name}' already exists at {path}")

    wrapped = encrypt_json(password, wallet.to_json_plain())
    path.write_text(json.dumps(wrapped, indent=2), encoding="utf-8")
    return path


def load_wallet_encrypted(name: str, password: str) -> Wallet:
    path = wallet_path(name)
    if not path.exists():
        raise FileNotFoundError(f"No wallet named '{name}' at {path}")

    wrapped = json.loads(path.read_text(encoding="utf-8"))
    plain = decrypt_json(password, wrapped)

    from .crypto import Keypair
    keypairs = [
        Keypair(
            private_key_hex=k["private_key_hex"],
            public_key_hex=k["public_key_hex"],
            address=k["address"],
            algo=plain["algo"],
        )
        for k in plain["keypairs"]
    ]

    return Wallet(
        name=plain["name"],
        created_at=int(plain["created_at"]),
        algo=plain["algo"],
        threshold=int(plain["threshold"]),
        keypairs=keypairs,
        mnemonic=plain.get("mnemonic"),
    )
