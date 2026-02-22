"""
File Handler - Manages the encryption, storage, and indexing of files in a vault.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional, Union, Tuple, Literal
from rich import print
import base64
import hmac
import re

from core.utils.security import secure_delete
from core.vault.index_manager import VaultIndexManager
from core.encryption.service import EncryptionService


# Duplicate file handling options
OVERWRITE = "overwrite"
RENAME = "rename"
SKIP = "skip"
FileAction = Literal["overwrite", "rename", "skip"]


def get_encrypted_filename(rel_path: Path, enc_service: EncryptionService) -> str:
    """
    Get the encrypted filename for a given relative path.

    Args:
        rel_path: Relative path of the file
        enc_service: Encryption service instance

    Returns:
        str: Encrypted filename
    """
    # Use the HMAC key to hash the original filename
    filename_hash = hmac.new(
        enc_service.hmac_key, str(rel_path).encode(), hashlib.sha256
    ).digest()
    # Convert to base64url without padding
    return base64.urlsafe_b64encode(filename_hash).decode().rstrip("=") + ".enc"


def _generate_unique_path(original_path: Path) -> Tuple[Path, str]:
    """
    Generate a unique path by adding a counter to the filename.
    
    Args:
        original_path: Original file path
        
    Returns:
        Tuple[Path, str]: Unique path and new relative filename
    """
    stem = original_path.stem
    suffix = original_path.suffix
    parent = original_path.parent
    
    # Check if stem already has a counter pattern like "filename_1"
    counter_match = re.search(r'(.+)_(\d+)$', stem)
    if counter_match:
        base_name = counter_match.group(1)
        counter = int(counter_match.group(2)) + 1
    else:
        base_name = stem
        counter = 1
    
    # Generate new filename
    new_filename = f"{base_name}_{counter}{suffix}"
    new_path = parent / new_filename
    
    return new_path, new_filename


def _ask_for_duplicate_action(file_path: str) -> FileAction:
    """
    Ask the user how to handle a duplicate file.
    
    Args:
        file_path: Path to the duplicate file
        
    Returns:
        FileAction: User's chosen action (overwrite, rename, skip)
    """
    from questionary import select
    
    print(f"[yellow]⚠️ File already exists in vault: {file_path}[/yellow]")
    
    try:
        action = select(
            "How would you like to handle this file?",
            choices=[
                {"name": "Rename (create a new version with incremented name)", "value": RENAME},
                {"name": "Overwrite (replace existing file)", "value": OVERWRITE},
                {"name": "Skip (ignore this file)", "value": SKIP},
            ]
        ).ask()
        
        return action or RENAME  # Default to RENAME if user cancels
    except Exception as e:
        print(f"[yellow]Error showing prompt: {e}. Using default action: Rename[/yellow]")
        return RENAME


def encrypt_and_store_file(
    src_path: Path,
    rel_path: Path,
    enc_service: EncryptionService,
    encrypted_dir: Path,
    provider,
    index_manager: VaultIndexManager,
    duplicate_action: Optional[FileAction] = None,
    keep_source: bool = False,
) -> Union[bool, str]:
    """
    Encrypt and store a file in the vault. If a file with the same name exists,
    gives user options to overwrite, rename, or skip.

    Args:
        src_path: Path to the source file
        rel_path: Relative path of the file in the vault
        enc_service: Encryption service instance
        encrypted_dir: Directory where encrypted files are stored
        provider: Storage provider instance
        index_manager: Index manager instance
        duplicate_action: How to handle duplicates (if None, will prompt)

    Returns:
        Union[bool, str]: True/encrypted filename if successful, False otherwise
    """
    try:
        # Check if file exists
        if not src_path.exists():
            print(f"[red]❌ File not found: {src_path}[/red]")
            return False

        # Check if file already exists in vault
        original_rel_path = rel_path
        file_info = index_manager.get_file_info(rel_path)
        
        if file_info:
            # Handle duplicate file
            if duplicate_action is None:
                # Ask user for action if not specified
                duplicate_action = _ask_for_duplicate_action(str(rel_path))
            
            if duplicate_action == SKIP:
                print(f"[blue]Skipping file: {rel_path}[/blue]")
                return True  # Return True to indicate successful handling
                
            elif duplicate_action == RENAME:
                # Generate a unique path
                new_path, new_filename = _generate_unique_path(rel_path)
                print(f"[blue]Creating version with unique name: {new_filename}[/blue]")
                rel_path = new_path
                
            elif duplicate_action == OVERWRITE:
                print(f"[blue]Overwriting existing file: {rel_path}[/blue]")
                # Continue with existing rel_path
                
                # If we're overwriting, we should remove the existing file from index
                try:
                    # Save current filename for deletion after encryption
                    old_filename = file_info.get("encrypted_filename")
                    old_enc_path = encrypted_dir / "content" / old_filename
                    old_hmac_path = encrypted_dir / "hmac" / f"{old_filename}.hmac"
                    
                    # Remove from index first
                    index_manager.remove_file(rel_path)
                except Exception as e:
                    print(f"[yellow]⚠️ Error preparing for overwrite: {e}[/yellow]")
        
        # Read file content
        try:
            content = src_path.read_bytes()
        except Exception as e:
            print(f"[red]❌ Error reading file {src_path}: {str(e)}[/red]")
            return False

        # Get encrypted filename
        encrypted_filename = get_encrypted_filename(rel_path, enc_service)

        # Create directories if they don't exist
        content_dir = encrypted_dir / "content"
        hmac_dir = encrypted_dir / "hmac"
        index_dir = encrypted_dir / "index"
        content_dir.mkdir(parents=True, exist_ok=True)
        hmac_dir.mkdir(parents=True, exist_ok=True)
        index_dir.mkdir(parents=True, exist_ok=True)

        # Create encrypted file path
        enc_path = content_dir / encrypted_filename
        hmac_path = hmac_dir / f"{encrypted_filename}.hmac"

        # Encrypt file
        try:
            enc_service.encrypt_file(str(src_path), str(enc_path), str(hmac_path))
            print(f"[green]✓ File encrypted successfully: {rel_path}[/green]")
            
            # If we're overwriting, delete the old encrypted files
            if duplicate_action == OVERWRITE and 'old_enc_path' in locals():
                try:
                    if old_enc_path.exists():
                        old_enc_path.unlink()
                    if old_hmac_path.exists():
                        old_hmac_path.unlink()
                except Exception as e:
                    print(f"[yellow]⚠️ Could not delete old encrypted files: {e}[/yellow]")
        except Exception as e:
            print(f"[red]❌ Error encrypting file {src_path}: {str(e)}[/red]")
            import traceback

            traceback.print_exc()
            return False

        # Update index with encrypted filename
        try:
            file_metadata = {
                "encrypted_filename": encrypted_filename,
                "size": len(content),
                "added": time.time(),
                "original_path": str(src_path),
            }
            
            if original_rel_path != rel_path:
                file_metadata["renamed_from"] = str(original_rel_path)
                
            index_manager.add_file(rel_path, file_metadata)
        except Exception as e:
            print(f"[red]❌ Error updating index for {rel_path}: {str(e)}[/red]")
            return False

        # Save index
        try:
            index_manager.save(force=True)
            print(f"[green]✓ Index updated for: {rel_path}[/green]")
        except Exception as e:
            print(f"[red]❌ Error saving index: {e}[/red]")
            return False

        # Securely delete original file unless keep_source is set
        if not keep_source:
            try:
                secure_delete(src_path)
                print(f"[green]✓ Original file securely deleted: {src_path}[/green]")
            except Exception as e:
                print(f"[yellow]⚠️ Could not delete original file: {e}[/yellow]")

        return encrypted_filename

    except Exception as e:
        import traceback

        print(f"[red]❌ Error encrypting file {src_path}: {str(e)}[/red]")
        traceback.print_exc()
        return False


def extract_file(
    rel_path: Path,
    enc_service: EncryptionService,
    encrypted_dir: Path,
    provider,
    index_manager: VaultIndexManager,
    output_dir: Optional[Path] = None,
    duplicate_action: Optional[FileAction] = None,
) -> Optional[Path]:
    """
    Extract and decrypt a file from the vault.

    Args:
        rel_path: Relative path of the file in the vault
        enc_service: Encryption service instance
        encrypted_dir: Directory where encrypted files are stored
        provider: Storage provider instance
        index_manager: Index manager instance
        output_dir: Optional directory to extract to (defaults to vault root)
        duplicate_action: How to handle duplicates (if None, will prompt)

    Returns:
        Optional[Path]: Path to the extracted file if successful, None otherwise
    """
    try:
        # Get encrypted filename from index
        file_info = index_manager.get_file_info(rel_path)
        if not file_info:
            print(f"[red]❌ File not found in index: {rel_path}[/red]")
            return None

        encrypted_filename = file_info.get("encrypted_filename")
        if not encrypted_filename:
            print(f"[red]❌ Missing encrypted filename in index for: {rel_path}[/red]")
            return None
            
        enc_path = encrypted_dir / "content" / encrypted_filename
        hmac_path = encrypted_dir / "hmac" / f"{encrypted_filename}.hmac"

        # Verify files exist
        if not enc_path.exists():
            print(f"[red]❌ Encrypted file not found: {enc_path}[/red]")
            return None
            
        if not hmac_path.exists():
            print(f"[red]❌ HMAC file not found: {hmac_path}[/red]")
            return None

        # Create output directory if needed
        if output_dir is None:
            output_dir = encrypted_dir.parent
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create output path
        output_path = output_dir / rel_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Check if output file already exists
        if output_path.exists():
            # Handle duplicate extraction
            if duplicate_action is None:
                # Ask user what to do
                from questionary import select
                
                print(f"[yellow]⚠️ File already exists at extraction path: {output_path}[/yellow]")
                
                try:
                    duplicate_action = select(
                        "How would you like to handle this extraction?",
                        choices=[
                            {"name": "Rename (extract to a new filename)", "value": RENAME},
                            {"name": "Overwrite (replace existing file)", "value": OVERWRITE},
                            {"name": "Skip (don't extract this file)", "value": SKIP},
                        ]
                    ).ask()
                    
                    if duplicate_action is None:
                        duplicate_action = RENAME  # Default if user cancels
                except Exception as e:
                    print(f"[yellow]Error showing prompt: {e}. Using default action: Rename[/yellow]")
                    duplicate_action = RENAME
            
            if duplicate_action == SKIP:
                print(f"[blue]Skipping extraction: {rel_path}[/blue]")
                return None
                
            elif duplicate_action == RENAME:
                # Generate unique name
                unique_path, unique_name = _generate_unique_path(output_path)
                print(f"[blue]Using unique name for extraction: {unique_name}[/blue]")
                output_path = unique_path
                
            elif duplicate_action == OVERWRITE:
                print(f"[blue]Overwriting existing file: {output_path}[/blue]")
                # Make sure we have write permission
                if not os.access(str(output_path.parent), os.W_OK):
                    print(f"[red]❌ No write permission for: {output_path.parent}[/red]")
                    return None

        # Decrypt file
        enc_service.decrypt_file(enc_path, output_path)
        print(f"[green]✓ File extracted successfully: {output_path}[/green]")

        return output_path

    except Exception as e:
        print(f"[red]❌ Error extracting file {rel_path}: {str(e)}[/red]")
        return None


def update_vault_file_count(vault_dir: Path, delta: int) -> None:
    """
    Update the file count in the vault metadata.

    Args:
        vault_dir: Path to the vault directory
        delta: Change in file count (positive for additions, negative for removals)
    """
    try:
        meta_path = vault_dir / "keys" / "vault-meta.json"
        if meta_path.exists():
            with open(meta_path, "r") as f:
                metadata = json.load(f)

            # Update file count, ensuring it doesn't go below 0
            current_count = metadata.get("file_count", 0)
            new_count = max(0, current_count + delta)
            metadata["file_count"] = new_count

            with open(meta_path, "w") as f:
                json.dump(metadata, f, indent=2)
    except Exception as e:
        print(
            f"[yellow]⚠️ Warning: Could not update file count in metadata: {e}[/yellow]"
        )