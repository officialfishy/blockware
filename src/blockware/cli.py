from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .crypto import generate_keypair, SUPPORTED_ADDR_ALGOS
from .wallet import create_seed_wallet, save_wallet_encrypted, load_wallet_encrypted, DEFAULT_DIR, WALLETS_DIR

app = typer.Typer(no_args_is_help=True, add_completion=True)
create_app = typer.Typer(no_args_is_help=True)
wallet_app = typer.Typer(no_args_is_help=True)

app.add_typer(create_app, name="create")
app.add_typer(wallet_app, name="wallet")

console = Console()


@create_app.command("keypair")
def create_keypair(
    algo: str = typer.Argument("sha256", help="sha256 | sha3_256 | blake2b"),
    show_private: bool = typer.Option(False, "--show-private", help="Print private key in terminal"),
):
    algo = algo.lower()
    if algo not in SUPPORTED_ADDR_ALGOS:
        raise typer.BadParameter(f"Unsupported algo '{algo}'. Use: {', '.join(sorted(SUPPORTED_ADDR_ALGOS))}")

    kp = generate_keypair(algo)

    table = Table(title="Blockware Keypair")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Algo", kp.algo)
    table.add_row("Address", kp.address)
    table.add_row("Public Key (hex)", kp.public_key_hex)
    table.add_row("Private Key (hex)", kp.private_key_hex if show_private else "[dim]hidden (use --show-private)[/dim]")
    console.print(table)


@create_app.command("wallet")
def create_wallet_cmd(
    kind: str = typer.Argument(..., help="Wallet kind (e.g. normal)"),
    source: str = typer.Argument(..., help="Source type (e.g. seed)"),
    words: int = typer.Argument(..., help="Mnemonic words: 12/15/18/21/24"),
    n: int = typer.Option(1, "--signers", "-s", help="Number of derived keypairs/signers"),
    threshold: int = typer.Option(None, "--threshold", "-t", help="m-of-n required signatures (default: n)"),
    algo: str = typer.Option("sha256", "--algo", "-a", help="Address derivation algo"),
    name: str = typer.Option(None, "--name", help="Wallet name"),
    show_private: bool = typer.Option(False, "--show-private", help="Print private keys to terminal (dangerous)"),
):
    """
    Example:
      blockware create wallet normal seed 24 --signers 10 --threshold 3
    """
    kind = kind.lower()
    source = source.lower()
    algo = algo.lower()

    if kind != "normal":
        raise typer.BadParameter("Only 'normal' kind is supported in v0.2.0")
    if source != "seed":
        raise typer.BadParameter("Only 'seed' source is supported in v0.2.0")
    if algo not in SUPPORTED_ADDR_ALGOS:
        raise typer.BadParameter(f"Unsupported algo '{algo}'. Use: {', '.join(sorted(SUPPORTED_ADDR_ALGOS))}")

    pw1 = typer.prompt("Set wallet password", hide_input=True, confirmation_prompt=True)

    wallet = create_seed_wallet(n_signers=n, mnemonic_words=words, algo=algo, threshold=threshold, name=name)
    path = save_wallet_encrypted(wallet, pw1)

    console.print(Panel.fit(
        f"[bold green]Encrypted wallet created![/bold green]\n"
        f"Name: [bold]{wallet.name}[/bold]\n"
        f"Path: [bold]{path}[/bold]\n"
        f"Signers: {wallet.n}\n"
        f"Threshold: {wallet.threshold}-of-{wallet.n}\n"
        f"Algo: {wallet.algo}\n",
        title="Blockware",
    ))

    # Show mnemonic once (important!)
    console.print(Panel.fit(
        f"[bold yellow]WRITE THIS DOWN[/bold yellow]\n\n{wallet.mnemonic}",
        title="Seed Phrase (shown once)",
    ))

    table = Table(title="Derived Addresses (first 10)")
    table.add_column("#", justify="right")
    table.add_column("Address")
    table.add_column("Public Key (hex)")
    if show_private:
        table.add_column("Private Key (hex)")

        confirm = typer.prompt("Type YES to reveal private keys", default="NO")
        if confirm.strip().upper() != "YES":
            show_private = False

    for i, kp in enumerate(wallet.keypairs[:10], start=1):
        if show_private:
            table.add_row(str(i), kp.address, kp.public_key_hex, kp.private_key_hex)
        else:
            table.add_row(str(i), kp.address, kp.public_key_hex)

    if wallet.n > 10:
        table.add_row("…", f"[dim]+{wallet.n - 10} more[/dim]", "[dim](hidden)[/dim]" if not show_private else "[dim](hidden)[/dim]", "" if show_private else "")

    console.print(table)


@wallet_app.command("open")
def wallet_open(
    name: str = typer.Argument(..., help="Wallet name (filename without .json)"),
):
    """Decrypt and show wallet addresses (no privkeys)."""
    pw = typer.prompt("Wallet password", hide_input=True)
    wallet = load_wallet_encrypted(name, pw)

    table = Table(title=f"Wallet: {wallet.name} ({wallet.threshold}-of-{wallet.n})")
    table.add_column("#", justify="right")
    table.add_column("Address")
    table.add_column("Public Key (hex)")
    for i, kp in enumerate(wallet.keypairs[:20], start=1):
        table.add_row(str(i), kp.address, kp.public_key_hex)
    if wallet.n > 20:
        table.add_row("…", f"[dim]+{wallet.n - 20} more[/dim]", "[dim](hidden)[/dim]")
    console.print(table)


@app.command("where")
def where():
    console.print(f"[bold]Base dir:[/bold] {DEFAULT_DIR}")
    console.print(f"[bold]Wallets dir:[/bold] {WALLETS_DIR}")

def main():
    app()

if __name__ == "__main__":
    main()

