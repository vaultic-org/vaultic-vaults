"""
Watch Command - Monitor a vault for changes and automatically encrypt files.
"""

import typer
from rich import print
from typing import Optional

from core.vault.watcher import start_vault_watcher
from core.vault.manager import list_vaults

app = typer.Typer()


@app.callback(invoke_without_command=True)
def watch(
    vault_id: Optional[str] = typer.Argument(
        None, help="ID of the vault to watch (leave empty to select interactively)"
    ),
    passphrase: Optional[str] = typer.Option(
        None,
        "--passphrase",
        "-p",
        help="Vault passphrase (will prompt if not provided)",
    ),
):
    """
    Watch a vault for new files and encrypt them automatically.

    Files placed in the vault directory will be automatically encrypted,
    indexed, and stored via the configured storage provider.
    Stop with Ctrl+C.
    """
    try:
        vaults = list_vaults()

        if not vaults:
            print("[red]❌ No vaults found.[/red]")
            print("[blue]Create one first:[/blue] vaultic create -n <name> --linked")
            raise typer.Exit(code=1)

        if not vault_id:
            if len(vaults) == 1:
                vault_id = vaults[0]["id"]
                print(f"[green]Using vault: {vaults[0]['name']}[/green]")
            else:
                import questionary

                choices = [f"{v['name']} ({v['id']})" for v in vaults]
                answer = questionary.select(
                    "Select a vault to watch:",
                    choices=choices,
                    use_indicator=True,
                    style=questionary.Style(
                        [
                            ("selected", "fg:cyan bold"),
                            ("pointer", "fg:cyan bold"),
                            ("highlighted", "fg:cyan bold"),
                        ]
                    ),
                ).ask()

                if not answer:
                    raise ValueError("No vault selected")

                selected_name = answer.split(" (")[0]
                vault_id = answer.split("(")[1].rstrip(")")
                print(f"[green]Selected vault: {selected_name}[/green]")

        if passphrase is None:
            from core.utils.console import prompt_passphrase
            passphrase = prompt_passphrase("Enter vault passphrase")

        print("[green]Starting vault watcher...[/green]")
        start_vault_watcher(vault_id, passphrase)

    except KeyboardInterrupt:
        print("[yellow]🛑 Watcher stopped by user.[/yellow]")
    except Exception as e:
        print(f"[red]❌ Error starting watcher:[/red] {str(e)}")
        raise typer.Exit(code=1)
