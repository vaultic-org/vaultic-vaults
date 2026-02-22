"""
Backup Command - Encrypt and store files to a vault.
"""

import fnmatch
import typer
from pathlib import Path
from rich import print
from typing import Optional, List

from core.config import Config
from core.encryption.service import EncryptionService
from core.storage.factory import get_provider
from core.vault.manager import select_vault
from core.vault.index_manager import VaultIndexManager
from core.vault.file_handler import encrypt_and_store_file

app = typer.Typer()


def _get_passphrase(passphrase: Optional[str]) -> str:
    if passphrase:
        return passphrase
    from core.utils.console import prompt_passphrase
    return prompt_passphrase("Enter vault passphrase")


def _warn_source_deletion(source: Path) -> None:
    print(
        f"[yellow]⚠️  The original file will be securely deleted after encryption:[/yellow] {source}"
    )
    print("[dim]   Use --keep-source to retain the plaintext copy.[/dim]")


@app.command("file")
def backup_file(
    source: str = typer.Argument(..., help="Path to the file you want to back up"),
    vault_id: Optional[str] = typer.Option(
        None, "--vault", "-v", help="Specific vault to use"
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="Override storage provider"
    ),
    passphrase: Optional[str] = typer.Option(
        None, "--passphrase", help="Vault passphrase (will prompt if not provided)"
    ),
    keep_source: bool = typer.Option(
        False,
        "--keep-source",
        help="Keep the original plaintext file after encryption (default: securely delete it)",
    ),
):
    """
    Backup a single file to an encrypted vault.

    By default the original file is securely deleted after encryption.
    Use --keep-source to retain the plaintext copy.
    """
    try:
        source_path = Path(source).resolve()
        if not source_path.exists() or not source_path.is_file():
            print(f"[red]❌ Source file does not exist:[/red] {source}")
            raise typer.Exit(code=1)

        selected_vault_id, meta_path = select_vault(vault_id)
        passphrase = _get_passphrase(passphrase)

        enc_service = EncryptionService(passphrase, meta_path)
        try:
            enc_service.verify_passphrase()
        except ValueError as e:
            print(f"[red]❌ {str(e)}[/red]")
            raise typer.Exit(code=1)

        vault_dir = meta_path.parent.parent
        encrypted_dir = vault_dir / "encrypted"
        encrypted_dir.mkdir(parents=True, exist_ok=True)

        provider_name = provider or Config.PROVIDER
        storage = get_provider(provider_name)
        index_manager = VaultIndexManager(enc_service, vault_dir)

        filename = source_path.name
        rel_path = Path(filename)

        if not keep_source:
            _warn_source_deletion(source_path)

        print(f"[blue]🔐 Backing up to vault {selected_vault_id}:[/blue] {filename}")

        success = encrypt_and_store_file(
            source_path,
            rel_path,
            enc_service,
            encrypted_dir,
            storage,
            index_manager,
            keep_source=keep_source,
        )

        if success:
            print(f"[green]✅ File backed up successfully:[/green] {filename}")
        else:
            print(f"[red]❌ Failed to backup file:[/red] {filename}")
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        print(f"[red]❌ Error backing up file:[/red] {str(e)}")
        raise typer.Exit(code=1)


@app.command("dir")
def backup_dir(
    source: str = typer.Argument(..., help="Path to the directory you want to back up"),
    vault_id: Optional[str] = typer.Option(
        None, "--vault", "-v", help="Specific vault to use"
    ),
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="Override storage provider"
    ),
    passphrase: Optional[str] = typer.Option(
        None, "--passphrase", help="Vault passphrase (will prompt if not provided)"
    ),
    exclude: List[str] = typer.Option(
        [], "--exclude", "-e", help="Patterns to exclude (can be used multiple times)"
    ),
    recursive: bool = typer.Option(
        True, "--recursive/--no-recursive", help="Backup subdirectories recursively"
    ),
    keep_source: bool = typer.Option(
        False,
        "--keep-source",
        help="Keep original plaintext files after encryption (default: securely delete them)",
    ),
):
    """
    Backup a directory to an encrypted vault.

    By default all original files are securely deleted after encryption.
    Use --keep-source to retain plaintext copies.
    """
    try:
        source_dir = Path(source).resolve()
        if not source_dir.exists() or not source_dir.is_dir():
            print(f"[red]❌ Source directory does not exist:[/red] {source}")
            raise typer.Exit(code=1)

        selected_vault_id, meta_path = select_vault(vault_id)
        passphrase = _get_passphrase(passphrase)

        enc_service = EncryptionService(passphrase, meta_path)
        try:
            enc_service.verify_passphrase()
        except ValueError as e:
            print(f"[red]❌ {str(e)}[/red]")
            raise typer.Exit(code=1)

        vault_dir = meta_path.parent.parent
        encrypted_dir = vault_dir / "encrypted"
        encrypted_dir.mkdir(parents=True, exist_ok=True)

        provider_name = provider or Config.PROVIDER
        storage = get_provider(provider_name)
        index_manager = VaultIndexManager(enc_service, vault_dir)

        glob_pattern = "**/*" if recursive else "*"
        files = [f for f in source_dir.glob(glob_pattern) if f.is_file()]

        if exclude:
            for pat in exclude:
                files = [f for f in files if not fnmatch.fnmatch(str(f), pat)]

        total_files = len(files)
        if total_files == 0:
            print(f"[yellow]⚠️ No files found in directory:[/yellow] {source_dir}")
            raise typer.Exit(code=0)

        if not keep_source:
            print(
                f"[yellow]⚠️  {total_files} original file(s) will be securely deleted after encryption.[/yellow]"
            )
            print("[dim]   Use --keep-source to retain plaintext copies.[/dim]")

        print(f"[blue]🔐 Backing up {total_files} file(s) to vault {selected_vault_id}...[/blue]")

        successful = 0
        from tqdm import tqdm

        for file_path in tqdm(files, desc="Processing files"):
            try:
                rel_path = file_path.relative_to(source_dir)
                success = encrypt_and_store_file(
                    file_path,
                    rel_path,
                    enc_service,
                    encrypted_dir,
                    storage,
                    index_manager,
                    keep_source=keep_source,
                )
                if success:
                    successful += 1
            except Exception as e:
                print(f"[red]❌ Error processing {file_path}: {str(e)}[/red]")

        print(f"[green]✅ Directory backup complete:[/green] {successful}/{total_files} files processed")

        if successful < total_files:
            print(f"[yellow]⚠️ {total_files - successful} file(s) failed to process[/yellow]")
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        print(f"[red]❌ Error backing up directory:[/red] {str(e)}")
        raise typer.Exit(code=1)
