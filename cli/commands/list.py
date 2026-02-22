"""
List Command - List files and vaults in the system.
"""

import typer
from rich import print
from rich.table import Table
from rich.console import Console
from typing import Optional
import time

from core.vault.manager import list_vaults, get_vault_path
from core.encryption.service import EncryptionService
from core.vault.index_manager import VaultIndexManager

app = typer.Typer()


@app.command("vaults")
def list_vaults_cmd():
    """
    List all available vaults.

    Optionally prompts for a passphrase to show accurate file counts.
    Press Enter to skip passphrase and use cached metadata counts.
    """
    passphrase = None
    try:
        passphrase = input("🔑 Vault passphrase for accurate counts (Enter to skip): ") or None
        if passphrase is None:
            print("[yellow]Skipping index decryption. File counts may not be accurate.[/yellow]")
    except KeyboardInterrupt:
        print("\n[yellow]Passphrase input cancelled. Using metadata file counts.[/yellow]")
        passphrase = None

    vaults = list_vaults(passphrase=passphrase)

    if not vaults:
        print("[yellow]No vaults found.[/yellow]")
        print("[blue]Create one with:[/blue] vaultic create -n <name> --linked")
        return

    console = Console()
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Created")
    table.add_column("Files", justify="right")
    table.add_column("Status", justify="center")
    table.add_column("Path", style="dim")

    for vault in vaults:
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(vault["created_at"]))
        status = "[green]✓[/green]" if vault["decrypted"] else "[dim]-[/dim]"
        file_count = str(vault["file_count"])
        if not vault["decrypted"] and passphrase and vault["file_count"] == 0:
            file_count = "[yellow]" + file_count + "[/yellow]"

        table.add_row(
            vault["id"],
            vault.get("name", vault["id"]),
            created,
            file_count,
            status,
            vault["path"],
        )

    console.print(table)

    if passphrase:
        print("\n[green]✓[/green] = Index successfully decrypted")
        print("[dim]-[/dim] = Passphrase not verified, count from cached metadata")


@app.command("files")
def list_files_cmd(
    vault_id: str = typer.Argument(..., help="ID of the vault to list files from"),
    passphrase: Optional[str] = typer.Option(
        None, help="Vault passphrase (will be prompted if not provided)"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show internal paths and index details"
    ),
):
    """
    List all files in a vault with their metadata.

    The vault passphrase is required to decrypt the index.
    """
    vault_path = get_vault_path(vault_id)

    if not vault_path.exists():
        print(f"[red]❌ Vault not found: {vault_id}[/red]")
        raise typer.Exit(1)

    meta_path = vault_path / "keys" / "vault-meta.json"
    if not meta_path.exists():
        print(f"[red]❌ Metadata not found for vault: {vault_id}[/red]")
        raise typer.Exit(1)

    if verbose:
        print(f"[dim]Vault path: {vault_path}[/dim]")
        print(f"[dim]Metadata path: {meta_path}[/dim]")

    encrypted_dir = vault_path / "encrypted"
    encrypted_index_path = encrypted_dir / "index" / "index.json.enc"
    encrypted_hmac_path = encrypted_dir / "index" / "index.json.enc.hmac"
    legacy_index_path = encrypted_dir / "index.json"

    # Warn about legacy index without deleting it
    if legacy_index_path.exists():
        print(
            f"[yellow]⚠️ Legacy unencrypted index detected at {legacy_index_path}.[/yellow]"
        )
        print("[yellow]   Run 'vaultic watch' or 'vaultic backup' to migrate to an encrypted index.[/yellow]")

    if not encrypted_index_path.exists() or not encrypted_hmac_path.exists():
        print(f"[yellow]No encrypted index found for vault: {vault_id}[/yellow]")
        print(
            f"[blue]This vault appears to be empty. Add files with:[/blue] vaultic backup file <path> --vault {vault_id}"
        )
        raise typer.Exit(0)

    if verbose:
        print(f"[dim]Index size: {encrypted_index_path.stat().st_size} bytes[/dim]")

    if not passphrase:
        from core.utils.console import prompt_passphrase
        passphrase = prompt_passphrase("Enter vault passphrase")

    try:
        enc_service = EncryptionService(passphrase, meta_path)
        enc_service.verify_passphrase()
    except ValueError as e:
        print(f"[red]❌ Invalid passphrase: {str(e)}[/red]")
        raise typer.Exit(1)

    index_manager = VaultIndexManager(enc_service, vault_path)
    try:
        index = index_manager.load()
    except Exception as e:
        print(f"[red]❌ Error decrypting index: {str(e)}[/red]")
        if verbose:
            import traceback
            print(f"[dim]{traceback.format_exc()}[/dim]")
        print("[red]Vault may be empty or its index is damaged.[/red]")
        raise typer.Exit(1)

    files_found = len(index)

    if files_found == 0:
        print(f"[yellow]No files in vault: {vault_id}[/yellow]")
        print(f"[blue]Add files with:[/blue] vaultic backup file <path> --vault {vault_id}")
        return

    console = Console()
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Filename")
    table.add_column("Size", justify="right")
    table.add_column("Encrypted", justify="center")
    table.add_column("Added")

    for filepath, file_info in index.items():
        size = file_info.get("size", 0)
        if size > 1024 * 1024:
            size_str = f"{size / (1024 * 1024):.1f} MB"
        elif size > 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size:,} B"

        timestamp = file_info.get("added", 0)
        date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))

        table.add_row(filepath, size_str, "[green]✓[/green]", date_str)

    console.print(table)
    print(f"[green]Total: {files_found} file(s)[/green]")
