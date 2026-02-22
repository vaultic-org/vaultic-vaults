"""
Encryption Service - Provides secure file encryption and decryption using AES.
"""

import hashlib
import hmac
import json
import os
import base64
import zlib
import tarfile
import io
from typing import Dict
from pathlib import Path
from rich import print

from core.config import Config

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Get the pepper from environment variable or generate a secure default
# Each installation will have its own unique pepper for additional security
PEPPER = Config.VAULTIC_PEPPER.encode()

# Magic header for identifying Vaultic encrypted files
MAGIC_HEADER = b"VAULTICv1\n"

# Constants for the encrypted archive
ARCHIVE_FILENAME = "data.enc"
ARCHIVE_HMAC_FILENAME = "data.enc.hmac"


class EncryptionService:
    """
    EncryptionService handles file encryption and decryption using Fernet (AES-256) symmetric encryption,
    enhanced with compression and HMAC integrity checking.
    Keys are securely derived from passphrases using PBKDF2HMAC with an additional pepper.
    """

    def __init__(self, passphrase: str, meta_path: Path):
        """
        Initialize the encryption service with a passphrase and metadata file.
        """
        self.meta_path = Path(meta_path).expanduser()

        # Store the passphrase (keep as string for now)
        self.passphrase_str = passphrase
        self.meta = self._load_or_create_metadata()
        self.salt = self.meta["salt"]

        # Derive keys
        self.key = self._derive_key("ENCRYPT")
        self.hmac_key = self._derive_key("HMAC")
        self.fernet = Fernet(self.key)

        # Create a copy of the test content for verification
        self.test_content = b"vaultic-test"

        # For new vaults, create the test file
        if self._is_new:
            print("New vault detected, creating test file...")
            self.create_meta_test_file()

    def _secure_clear_passphrase(self):
        """
        Attempt to clear the passphrase from memory.
        This is not foolproof due to Python's memory management,
        but provides an additional security measure.
        """
        # Overwrite with random data before deletion
        if hasattr(self, "passphrase"):
            for i in range(len(self.passphrase)):
                self.passphrase = os.urandom(len(self.passphrase))
            del self.passphrase

    def _derive_key(self, purpose: str) -> bytes:
        """
        Derive a secure encryption key using PBKDF2HMAC with an additional pepper.
        """

        # Convert passphrase to bytes if it's a string
        if isinstance(self.passphrase_str, str):
            passphrase_bytes = self.passphrase_str.encode("utf-8")
        else:
            passphrase_bytes = self.passphrase_str

        # Convert salt to bytes
        salt = bytes.fromhex(self.salt)

        # Add the pepper
        peppered_passphrase = passphrase_bytes + PEPPER + purpose.encode()

        # Create KDF
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390_000,
            backend=default_backend(),
        )

        # Derive key
        derived_key = kdf.derive(peppered_passphrase)
        encoded_key = base64.urlsafe_b64encode(derived_key)

        return encoded_key

    def _save_metadata(self):
        """Save the current metadata to the metadata file."""
        self.meta_path.write_text(json.dumps(self.meta, indent=2))

    def encrypt_bytes(self, data: bytes, output_path: str, hmac_path: str) -> None:
        """
        Encrypt raw bytes, write to encrypted file, and write HMAC.

        Args:
            data (bytes): The data to encrypt
            output_path (str): Path to write the encrypted content
            hmac_path (str): Path to write the HMAC
        """
        # Compress data before encryption for better storage efficiency
        compressed_content = zlib.compress(data, level=9)

        # Encrypt the compressed data
        encrypted = self.fernet.encrypt(compressed_content)

        # Write encrypted data with magic header
        Path(output_path).write_bytes(MAGIC_HEADER + encrypted)

        # Generate and write HMAC for integrity verification
        tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()
        Path(hmac_path).write_bytes(tag)

    def encrypt_file(self, input_path: str, output_path: str, hmac_path: str):
        """
        Encrypt and compress a file, then write the result and its HMAC.

        Args:
            input_path (str): Path to the plaintext input file
            output_path (str): Path to save the encrypted file
            hmac_path (str): Path to save the HMAC file
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        hmac_path = Path(hmac_path)

        # Read the original file
        original_content = input_path.read_bytes()

        # Compress the content
        compressed_content = zlib.compress(original_content, level=9)

        # Encrypt the compressed content
        encrypted = self.fernet.encrypt(compressed_content)

        # Write encrypted data with magic header
        output_path.write_bytes(MAGIC_HEADER + encrypted)

        # Generate and write HMAC for integrity verification
        tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()
        hmac_path.write_bytes(tag)

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Decrypt and decompress a file after verifying its HMAC.

        Args:
            input_path (str): Path to the encrypted file
            output_path (str): Path to save the decrypted file

        Raises:
            ValueError: If HMAC integrity check fails or magic header is missing
        """
        input_path = Path(input_path)
        output_path = Path(output_path)

        # Determine the correct HMAC path
        input_path_str = str(input_path)
        if "/content/" in input_path_str or "\\content\\" in input_path_str:
            # Handle both Unix and Windows paths
            hmac_path_str = (
                input_path_str.replace("/content/", "/hmac/").replace(
                    "\\content\\", "\\hmac\\"
                )
                + ".hmac"
            )
            hmac_path = Path(hmac_path_str)
        else:
            # Fallback to the old behavior for backward compatibility
            hmac_path = input_path.with_suffix(input_path.suffix + ".hmac")

        # Read the encrypted file
        if not input_path.exists():
            raise ValueError(f"Encrypted file not found: {input_path}")

        encrypted = input_path.read_bytes()

        # Verify magic header to ensure this is a Vaultic encrypted file
        if not encrypted.startswith(MAGIC_HEADER):
            raise ValueError("Invalid or missing Vaultic magic header")

        # Remove magic header before decryption
        encrypted = encrypted[len(MAGIC_HEADER) :]

        # Verify file integrity with HMAC
        if not hmac_path.exists():
            raise ValueError("Missing HMAC file for integrity check")

        expected_tag = hmac_path.read_bytes()
        actual_tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()

        if not hmac.compare_digest(expected_tag, actual_tag):
            raise ValueError("HMAC mismatch: file integrity compromised")

        # Decrypt and decompress
        decrypted_compressed = self.fernet.decrypt(encrypted)
        original_content = zlib.decompress(decrypted_compressed)

        # Write the decrypted file
        output_path.write_bytes(original_content)

    def _load_or_create_metadata(self) -> dict:
        """
        Loads or creates metadata containing the salt.

        Returns:
            dict: Metadata with salt and version.
        """
        if self.meta_path.exists():
            print(f"Loading existing metadata from: {self.meta_path}")
            try:
                with open(self.meta_path, "r") as f:
                    metadata = json.load(f)

                # Check if salt exists
                if "salt" not in metadata:
                    print("WARNING: No salt found in metadata, adding it")
                    salt = os.urandom(16).hex()
                    metadata["salt"] = salt

                # Add pepper hash for security validation
                pepper_hash = hashlib.sha256(PEPPER).hexdigest()
                metadata["pepper_hash"] = pepper_hash

                # Save metadata
                with open(self.meta_path, "w") as f:
                    json.dump(metadata, f, indent=2)

                self._is_new = False
                return metadata
            except Exception as e:
                print(f"Error loading metadata: {str(e)}")

        # Create new metadata with random salt
        print("Creating new metadata")
        salt = os.urandom(16).hex()
        pepper_hash = hashlib.sha256(PEPPER).hexdigest()

        meta = {
            "salt": salt,
            "pepper_hash": pepper_hash,
            "version": 1,
            "created_at": __import__("time").time(),
        }

        self.meta_path.parent.mkdir(parents=True, exist_ok=True)
        self.meta_path.write_text(json.dumps(meta, indent=2))
        print(f"Created metadata with salt: {salt}")
        self._is_new = True
        return meta

    def create_meta_test_file(self):
        """Create an encrypted test file for passphrase validation."""
        test_path = self.meta_path.parent / ".meta-test"
        test_data = self.test_content
        print(f"Creating test file at: {test_path}")

        # Encrypt and store
        encrypted = self.fernet.encrypt(test_data)
        print(f"Encrypted test data: {encrypted[:20]}...")
        test_path.write_bytes(encrypted)
        print(f"Test file created with size: {len(encrypted)} bytes")

    def verify_passphrase(self, keep_passphrase: bool = False):
        """
        Verify the correctness of the passphrase.

        Args:
            keep_passphrase: If True, do not clear the passphrase after verification.
                             Useful for GUI sessions that need continued access.

        Raises:
            ValueError: If the passphrase is incorrect or metadata is corrupted
        """
        test_path = self.meta_path.parent / ".meta-test"
        print(f"Verifying passphrase using test file: [yellow]{test_path}[/yellow]")

        if not test_path.exists():
            print(f"[red]Test file not found at: {test_path}[/red]")
            raise ValueError("Missing .meta-test file for verification")

        try:
            encrypted = test_path.read_bytes()

            try:
                decrypted = self.fernet.decrypt(encrypted)

                if decrypted != self.test_content:
                    print(
                        f"[red]Content mismatch. Expected: {self.test_content}, Got: {decrypted}[/red]"
                    )
                    raise ValueError(
                        "Corrupted .meta-test file - content doesn't match"
                    )

                print("[green]✅ Passphrase verification successful![/green]")
            except Exception as e:
                print(f"Error during decryption: {str(e)}")
                raise

        except Exception as e:
            print(f"Exception during verification: {type(e).__name__}: {str(e)}")
            raise ValueError(f"Invalid passphrase or corrupted metadata: {str(e)}")

        if not keep_passphrase:
            self._secure_clear_passphrase()

    def create_encrypted_archive(
        self, files: Dict[str, bytes], output_path: Path
    ) -> None:
        """
        Create a single encrypted archive containing multiple files.

        Args:
            files: Dictionary mapping filenames to their content
            output_path: Path where to save the encrypted archive
        """
        # Create a tar archive in memory
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            for filename, content in files.items():
                # Create a file-like object for the content
                file_obj = io.BytesIO(content)
                # Add file to tar archive
                tarinfo = tarfile.TarInfo(name=filename)
                tarinfo.size = len(content)
                tar.addfile(tarinfo, file_obj)

        # Get the compressed tar data
        compressed_data = tar_buffer.getvalue()

        # Encrypt the compressed data
        encrypted = self.fernet.encrypt(compressed_data)

        # Write encrypted data with magic header
        output_path.write_bytes(MAGIC_HEADER + encrypted)

        # Generate and write HMAC
        hmac_path = output_path.with_suffix(output_path.suffix + ".hmac")
        tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()
        hmac_path.write_bytes(tag)

    def extract_from_archive(self, archive_path: Path) -> Dict[str, bytes]:
        """
        Extract files from an encrypted archive.

        Args:
            archive_path: Path to the encrypted archive

        Returns:
            Dictionary mapping filenames to their content
        """
        # Read the encrypted file
        if not archive_path.exists():
            raise ValueError(f"Encrypted archive not found: {archive_path}")

        encrypted = archive_path.read_bytes()

        # Verify magic header
        if not encrypted.startswith(MAGIC_HEADER):
            raise ValueError("Invalid or missing Vaultic magic header")

        # Remove magic header
        encrypted = encrypted[len(MAGIC_HEADER) :]

        # Verify HMAC
        hmac_path = archive_path.with_suffix(archive_path.suffix + ".hmac")
        if not hmac_path.exists():
            raise ValueError("Missing HMAC file for integrity check")

        expected_tag = hmac_path.read_bytes()
        actual_tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_tag, actual_tag):
            raise ValueError("HMAC integrity check failed")

        # Decrypt the data
        decrypted = self.fernet.decrypt(encrypted)

        # Extract files from tar archive
        files = {}
        with tarfile.open(fileobj=io.BytesIO(decrypted), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile():
                    files[member.name] = tar.extractfile(member).read()

        return files

    def create_file_hmac(self, file_path: Path) -> bytes:
        """
        Create HMAC for a file.

        Args:
            file_path: Path to the file

        Returns:
            bytes: HMAC value
        """
        # Read file content
        with open(file_path, "rb") as f:
            content = f.read()

        # Create HMAC
        h = hmac.new(self.key, content, hashlib.sha256)
        return h.digest()

    def verify_file_hmac(self, file_path: Path, hmac_value: bytes) -> bool:
        """
        Verify HMAC for a file.

        Args:
            file_path: Path to the file
            hmac_value: HMAC value to verify against

        Returns:
            bool: True if HMAC is valid
        """
        expected_hmac = self.create_file_hmac(file_path)
        return hmac.compare_digest(expected_hmac, hmac_value)

    def decrypt_bytes(self, input_path: str, hmac_path: str) -> bytes:
        """
        Decrypt and decompress a file after verifying its HMAC, returning the decrypted bytes.

        Args:
            input_path (str): Path to the encrypted file
            hmac_path (str): Path to the HMAC file

        Returns:
            bytes: The decrypted and decompressed data

        Raises:
            ValueError: If HMAC integrity check fails or magic header is missing
        """
        input_path = Path(input_path)
        hmac_path = Path(hmac_path)

        # Read the encrypted file
        if not input_path.exists():
            raise ValueError(f"Encrypted file not found: {input_path}")

        encrypted = input_path.read_bytes()

        # Verify magic header to ensure this is a Vaultic encrypted file
        if not encrypted.startswith(MAGIC_HEADER):
            raise ValueError("Invalid or missing Vaultic magic header")

        # Remove magic header before decryption
        encrypted = encrypted[len(MAGIC_HEADER) :]

        # Verify file integrity with HMAC
        if not hmac_path.exists():
            raise ValueError("Missing HMAC file for integrity check")

        expected_tag = hmac_path.read_bytes()
        actual_tag = hmac.new(self.hmac_key, encrypted, hashlib.sha256).digest()

        if not hmac.compare_digest(expected_tag, actual_tag):
            raise ValueError("HMAC mismatch: file integrity compromised")

        # Decrypt and decompress
        decrypted_compressed = self.fernet.decrypt(encrypted)
        original_content = zlib.decompress(decrypted_compressed)

        return original_content
