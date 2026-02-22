import shutil
from pathlib import Path
from rich import print

from core.storage.base import StorageProvider


class LocalStorage(StorageProvider):
    """
    Local storage provider – stores encrypted files in a local directory.
    Useful for testing without any cloud credentials.
    """

    def __init__(self, root: Path = Path("./local_storage")):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def upload_file(self, local_path: Path, remote_path: str) -> None:
        dest = self.root / remote_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local_path, dest)
        print(f"[dim]↪ Stored locally: {remote_path}[/dim]")

    def download_file(self, remote_path: str, local_path: Path) -> None:
        src = self.root / remote_path
        if not src.exists():
            raise FileNotFoundError(f"File not found in local storage: {remote_path}")
        local_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, local_path)

    def list_files(self) -> list[str]:
        return [
            str(p.relative_to(self.root))
            for p in self.root.rglob("*")
            if p.is_file()
        ]
