# Blockware

A terminal-first wallet tool you can install from GitHub and use anywhere.

- 🔐 Encrypted wallet files (password protected)
- 🌱 Seed wallets (BIP39) with 12–24 word mnemonics
- 👥 Multi-signer wallets (m-of-n threshold)
- 🧾 Nice terminal output (tables)

> ⚠️ Security note: seed phrases and private keys are sensitive. Don’t paste them into chats, screenshots, or recordings.

---

## Install

### Recommended: `pipx` (best for CLI tools)
```bash
sudo apt install pipx
pipx ensurepath
# restart terminal after ensurepath (or run: source ~/.profile)

pipx install git+https://github.com/officialfishy/blockware.git
