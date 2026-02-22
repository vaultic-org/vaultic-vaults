"""
Vault Manager - Core functionality for creating, selecting, and managing Vaultic vaults.
"""

import json
import uuid
import time
from rich import print
from pathlib import Path
from typing import Optional, Dict, List

from core.encryption.service import EncryptionService
from core.config import Config


def get_vaults_directory() -> Path:
    """Returns the base directory where vaults are stored."""
    return Path(".vaultic")


def get_vault_path(vault_id: str) -> Path:
    """Returns the path to a specific vault directory."""
    return get_vaults_directory() / vault_id


def create_vault(
    name: Optional[str] = None, linked: bool = False, passphrase: Optional[str] = None
) -> str:
    """
    Create a new encrypted vault with the specified parameters.
    """
    # Ensure base directories exist
    vault_root = get_vaults_directory()
    vault_root.mkdir(parents=True, exist_ok=True)

    if name:
        existing_vault_path = vault_root / name
        if existing_vault_path.exists():
            raise ValueError(f"A vault with the name '{name}' already exists. Please choose another name.")
    else:
        # Generate a unique vault ID if name is not provided
        name = f"vault-{int(time.time())}-{uuid.uuid4().hex[:8]}"

    vault_dir = vault_root / name
    vault_dir.mkdir(parents=True, exist_ok=True)

    keys_dir = vault_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    # Create metadata file
    meta_path = keys_dir / "vault-meta.json"

    # Create metadatas according to salt
    metadata = {
        "vault_id": name,
        "created_at": time.time(),
        "linked": linked,
        "file_count": 0,  # Initialize file count as metadata
        "config": {"backup_provider": Config.PROVIDER},
    }

    # Write init metadatas
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    # Init encryptonservice (will add salt to metadatas)
    enc_service = EncryptionService(passphrase or Config.DEFAULT_PASSPHRASE, meta_path)

    # Create folder structure
    (vault_dir / "encrypted").mkdir(parents=True, exist_ok=True)
    (vault_dir / "encrypted" / "content").mkdir(parents=True, exist_ok=True)
    (vault_dir / "encrypted" / "hmac").mkdir(parents=True, exist_ok=True)

    # Create file test for encryption
    enc_service.create_meta_test_file()

    # Create an encrypted index using VaultIndexManager
    from core.vault.index_manager import VaultIndexManager

    index_manager = VaultIndexManager(enc_service, vault_dir)
    index_manager.save(force=True)

    # Create README file
    readme_content = (
        f"# Vault: {name}\n\n"
        "This is a Vaultic encrypted vault. Place files here to encrypt them automatically.\n\n"
        "- Files will be encrypted with AES-256 and stored in the 'encrypted' directory\n"
        "- Original files will be securely deleted after encryption\n"
        "- Do not modify the 'keys' or 'encrypted' directories manually\n"
    )
    (vault_dir / "README.md").write_text(readme_content)

    return name


def list_vaults(passphrase: Optional[str] = None) -> List[Dict]:
    """
    List all available vaults with their metadata.

    Args:
        passphrase: Optional passphrase to decrypt encrypted indexes for accurate file counts

    Returns:
        List[Dict]: List of vault information dictionaries.
        Each dict contains an additional 'decrypted' boolean field indicating if the index was successfully decrypted.
    """
    import io
    import contextlib

    vaults = []
    vault_root = get_vaults_directory()

    if not vault_root.exists():
        return vaults

    for vault_dir in vault_root.iterdir():
            if not vault_dir.is_dir() or vault_dir.name.startswith("."):
                continue

            meta_path = vault_dir / "keys" / "vault-meta.json"
            if not meta_path.exists():
                continue

            try:
                with open(meta_path, "r") as f:
                    metadata = json.load(f)

                # Default file count is 0
                file_count = 0
                # Default decryption status is False
                decrypted = False

                # Define index paths
                encrypted_index_path = (
                    vault_dir / "encrypted" / "index" / "index.json.enc"
                )
                encrypted_hmac_path = (
                    vault_dir / "encrypted" / "index" / "index.json.enc.hmac"
                )

                # Try to get accurate file count from encrypted index if it exists and passphrase is provided
                if (
                    passphrase
                    and encrypted_index_path.exists()
                    and encrypted_hmac_path.exists()
                ):
                    try:
                        from core.encryption.service import EncryptionService
                        from core.vault.index_manager import VaultIndexManager

                        # Suppress verbose internal prints during silent verification
                        with contextlib.redirect_stdout(io.StringIO()):
                            enc_service = EncryptionService(passphrase, meta_path)
                            try:
                                enc_service.verify_passphrase()
                                index_manager = VaultIndexManager(enc_service, vault_dir)
                                index = index_manager.load()
                                file_count = len(index)
                                decrypted = True
                            except Exception:
                                pass
                    except Exception:
                        pass

                # If no file count from index, use metadata
                if file_count == 0:
                    file_count = metadata.get("file_count", 0)

                vaults.append(
                    {
                        "id": vault_dir.name,
                        "name": metadata.get("name", vault_dir.name),
                        "created_at": metadata.get("created_at", 0),
                        "linked": metadata.get("linked", False),
                        "file_count": file_count,
                        "decrypted": decrypted,
                        "path": str(vault_dir),
                        "meta_path": meta_path,
                    }
                )
            except Exception as e:
                print(
                    f"[yellow]⚠️ Error reading vault metadata for {vault_dir.name}: {str(e)}[/yellow]"
                )

    return vaults


def select_vault(vault_id: Optional[str] = None) -> tuple[str, Path]:
    """
    Select a vault to use.

    Args:
        vault_id: Optional ID of the vault to select

    Returns:
        tuple[str, Path]: Selected vault ID and metadata path
    """
    vaults_dir = Path(".vaultic")
    if not vaults_dir.exists():
        print("[red]❌ No vaults found. Please create a vault first.[/red]")
        raise ValueError("No vaults found")

    # Get list of vaults
    vaults = []
    for vault_dir in vaults_dir.iterdir():
        if vault_dir.is_dir():
            meta_path = vault_dir / "keys" / "vault-meta.json"
            if meta_path.exists():
                try:
                    with open(meta_path, "r") as f:
                        metadata = json.load(f)
                    vaults.append(
                        (vault_dir.name, metadata.get("name", vault_dir.name))
                    )
                except:
                    continue

    if not vaults:
        print("[red]❌ No valid vaults found. Please create a vault first.[/red]")
        raise ValueError("No valid vaults found")

    # If vault_id is provided, try to find it
    if vault_id:
        for v_id, v_name in vaults:
            if v_id == vault_id:
                return v_id, vaults_dir / v_id / "keys" / "vault-meta.json"
        print(f"[red]❌ Vault not found: {vault_id}[/red]")
        raise ValueError(f"Vault not found: {vault_id}")

    # If only one vault, use it
    if len(vaults) == 1:
        v_id, v_name = vaults[0]
        print(f"[green]Using vault: {v_name}[/green]")
        return v_id, vaults_dir / v_id / "keys" / "vault-meta.json"

    # Multiple vaults, use questionary
    import questionary

    choices = [f"{v_name} ({v_id})" for v_id, v_name in vaults]
    answer = questionary.select(
        "Select a vault:",
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

    # Extract vault ID from selection
    selected_name = answer.split(" (")[0]
    selected_id = answer.split("(")[1].rstrip(")")

    print(f"[green]Selected vault: {selected_name}[/green]")
    return selected_id, vaults_dir / selected_id / "keys" / "vault-meta.json"
