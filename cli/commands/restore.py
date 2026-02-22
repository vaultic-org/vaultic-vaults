"""
Restore Command - Retrieve and decrypt files from vaults.
"""

import typer
from pathlib import Path
from rich import print
from typing import Optional

from core.config import Config
from core.encryption.service import EncryptionService
from core.storage.factory import get_provider
from core.vault.index_manager import VaultIndexManager
from core.vault.manager import get_vault_path

app = typer.Typer()


@app.callback(invoke_without_command=True)
def restore(
    vault_id: str = typer.Argument(..., help="ID of the vault containing the file"),
    filepath: str = typer.Argument(
        ..., help="Path of the file to restore (as shown in 'vaultic list files')"
    ),
    output_dir: str = typer.Option(
        "./restored", help="Directory where to save the restored file"
    ),
    output_name: Optional[str] = typer.Option(
        None, help="Alternative filename for the restored file"
    ),
    provider: Optional[str] = typer.Option(
        None, help="Override storage provider defined in .env"
    ),
    passphrase: Optional[str] = typer.Option(
        None, help="Vault passphrase (will prompt if not provided)"
    ),
):
    """
    Restore a single file from a vault.
    """
    vault_path = get_vault_path(vault_id)
    if not vault_path.exists():
        print(f"[red]❌ Vault not found: {vault_id}[/red]")
        raise typer.Exit(code=1)

    meta_path = vault_path / "keys" / "vault-meta.json"
    if not meta_path.exists():
        print(f"[red]❌ Vault metadata not found for: {vault_id}[/red]")
        raise typer.Exit(code=1)

    if not passphrase:
        from core.utils.console import prompt_passphrase
        passphrase = prompt_passphrase("Enter vault passphrase")

    enc_service = EncryptionService(passphrase, meta_path)

    try:
        enc_service.verify_passphrase()
    except ValueError as e:
        print(f"[red]❌ Invalid passphrase: {str(e)}[/red]")
        raise typer.Exit(code=1)

    # Load index via VaultIndexManager (always uses encrypted/index/)
    index_manager = VaultIndexManager(enc_service, vault_path)
    try:
        index = index_manager.load()
    except Exception as e:
        print(f"[red]❌ Could not load vault index: {str(e)}[/red]")
        raise typer.Exit(code=1)

    if not index:
        print(f"[red]❌ No files found in vault: {vault_id}[/red]")
        print(f"[blue]Use 'vaultic list files {vault_id}' to verify.[/blue]")
        raise typer.Exit(code=1)

    if filepath not in index:
        total = len(index)
        preview = list(index.keys())[:5]
        available = "\n  • ".join(preview)
        suffix = f"\n  … and {total - 5} more" if total > 5 else ""
        print(f"[red]❌ File not found in vault:[/red] {filepath}")
        print(f"[yellow]Available files ({total} total):[/yellow]\n  • {available}{suffix}")
        print(f"[blue]Use 'vaultic list files {vault_id}' to see all files.[/blue]")
        raise typer.Exit(code=1)

    file_info = index[filepath]
    encrypted_filename = file_info.get("encrypted_filename", "")

    if not encrypted_filename:
        print(f"[red]❌ Encrypted filename missing in index for: {filepath}[/red]")
        raise typer.Exit(code=1)

    encrypted_dir = vault_path / "encrypted"
    encrypted_path = encrypted_dir / "content" / encrypted_filename
    hmac_path = encrypted_dir / "hmac" / (encrypted_filename + ".hmac")

    temp_dir = Path(".vaultic/temp")
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_encrypted = temp_dir / encrypted_filename
    temp_hmac = temp_dir / (encrypted_filename + ".hmac")

    provider_name = provider or Config.PROVIDER
    storage = get_provider(provider_name)

    try:
        if not encrypted_path.exists():
            print(f"[blue]☁️ Downloading from {provider_name}:[/blue] {filepath}")
            try:
                storage.download_file(encrypted_filename, temp_encrypted)
                encrypted_path = temp_encrypted
            except Exception as e:
                print(f"[red]❌ Failed to download file: {str(e)}[/red]")
                raise typer.Exit(code=1)

        if not hmac_path.exists():
            try:
                storage.download_file(encrypted_filename + ".hmac", temp_hmac)
                hmac_path = temp_hmac
            except Exception as e:
                print(f"[red]❌ Failed to download HMAC: {str(e)}[/red]")
                raise typer.Exit(code=1)

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        if output_name:
            final_path = output_path / output_name
        else:
            final_path = output_path / Path(filepath).name

        print(f"[yellow]🔓 Decrypting:[/yellow] {filepath}")
        enc_service.decrypt_file(str(encrypted_path), str(final_path))
        print(f"[green]✅ File restored to:[/green] {final_path}")

        index_manager.clear_cache()

    except typer.Exit:
        raise
    except Exception as e:
        print(f"[red]❌ Decryption failed: {str(e)}[/red]")
        raise typer.Exit(code=1)
    finally:
        if temp_encrypted.exists():
            temp_encrypted.unlink()
        if temp_hmac.exists():
            temp_hmac.unlink()
