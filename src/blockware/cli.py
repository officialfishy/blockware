from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .crypto import generate_keypair, SUPPORTED_ADDR_ALGOS
from .wallet import create_wallet, save_wallet, DEFAULT_DIR, WALLETS_DIR

app = typer.Typer(no_args_is_help=True, add_completion=True)
create_app = typer.Typer(no_args_is_help=True)
app.add_typer(create_app, name="create")

console = Console()

@create_app.command("keypair")
def create_keypair(
    algo: str = typer.Argument("sha256", help="sha256 | sha3_256 | blake2b"),
    show_private: bool = typer.Option(False, "--show-private", help="Print private key"),
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
    n: int = typer.Argument(..., help="Number of signers (e.g. 50)"),
    threshold: int = typer.Option(None, "--threshold", "-t", help="m-of-n required (default: n)"),
    algo: str = typer.Option("sha256", "--algo", "-a", help="Address derivation algo"),
    name: str = typer.Option(None, "--name", "-n", help="Wallet name"),
):
    algo = algo.lower()
    if algo not in SUPPORTED_ADDR_ALGOS:
        raise typer.BadParameter(f"Unsupported algo '{algo}'. Use: {', '.join(sorted(SUPPORTED_ADDR_ALGOS))}")

    wallet = create_wallet(n_signers=n, algo=algo, threshold=threshold, name=name)
    path = save_wallet(wallet)

    console.print(Panel.fit(
        f"[bold green]Wallet created![/bold green]\n"
        f"Name: [bold]{wallet.name}[/bold]\n"
        f"Path: [bold]{path}[/bold]\n"
        f"Signers: {wallet.n}\n"
        f"Threshold: {wallet.threshold}-of-{wallet.n}\n"
        f"Algo: {wallet.algo}",
        title="Blockware",
    ))

    table = Table(title="Addresses (first 10)")
    table.add_column("#", justify="right")
    table.add_column("Address")
    for i, kp in enumerate(wallet.keypairs[:10], start=1):
        table.add_row(str(i), kp.address)
    if wallet.n > 10:
        table.add_row("…", f"[dim]+{wallet.n - 10} more[/dim]")
    console.print(table)

@app.command("where")
def where():
    console.print(f"[bold]Base dir:[/bold] {DEFAULT_DIR}")
    console.print(f"[bold]Wallets dir:[/bold] {WALLETS_DIR}")
