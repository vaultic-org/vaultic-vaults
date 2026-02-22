import typer
import questionary
from rich import print
from typing import Optional

from core.vault.manager import create_vault
from core.utils.console import prompt_passphrase

app = typer.Typer()

_MODE_HELP = {
    "linked": "Linked – vault uses the default passphrase from VAULTIC_DEFAULT_PASSPHRASE in .env. Convenient for personal use on a trusted machine.",
    "independent": "Independent – vault uses its own passphrase, chosen right now. Stronger isolation; required if you want per-vault passwords.",
}


@app.callback(invoke_without_command=True)
def create_new_vault(
    name: Optional[str] = typer.Option(
        None, "--name", "-n", help="Name for the new vault"
    ),
    linked: bool = typer.Option(
        False, "--linked", "-l", help="Link vault to default passphrase (.env)"
    ),
    independent: bool = typer.Option(
        False, "--independent", "-i", help="Use a dedicated passphrase for this vault"
    ),
):
    """
    Create a new encrypted vault.

    If neither --linked nor --independent is given, an interactive prompt will guide you.
    """
    try:
        if linked and independent:
            print("[red]❌ Cannot use both --linked and --independent simultaneously.[/red]")
            raise typer.Exit(code=1)

        if not linked and not independent:
            print("[blue]Choose how this vault's passphrase will be managed:[/blue]")
            mode = questionary.select(
                "Passphrase mode:",
                choices=[
                    questionary.Choice(title=_MODE_HELP["linked"], value="linked"),
                    questionary.Choice(title=_MODE_HELP["independent"], value="independent"),
                ],
                use_indicator=True,
            ).ask()

            if not mode:
                print("[yellow]Vault creation cancelled.[/yellow]")
                raise typer.Exit(code=0)

            linked = mode == "linked"
            independent = mode == "independent"

        passphrase = None
        if independent:
            passphrase = prompt_passphrase("Enter new vault passphrase", confirm=True)

        print("[blue]🔐 Creating new vault...[/blue]")
        vault_id = create_vault(name=name, linked=linked, passphrase=passphrase)

        print(f"[green]✅ Vault created:[/green] .vaultic/{vault_id}")
        if linked:
            print("[dim]Vault uses the default passphrase from VAULTIC_DEFAULT_PASSPHRASE.[/dim]")
        else:
            print("[dim]Vault uses its own passphrase. Keep it safe – there is no recovery.[/dim]")

    except typer.Exit:
        raise
    except Exception as e:
        print(f"[red]❌ Failed to create vault:[/red] {str(e)}")
        raise typer.Exit(code=1)
