from core.storage.local import LocalStorage
from core.storage.mock import MockLocalProvider


def get_provider(name: str):
    """
    Return a storage provider instance by name.

    Supported providers:
      - local  : stores files in ./local_storage/ (no credentials needed)
      - mock   : stores files in ./mock_remote/ (development/testing)
      - google_drive / backblaze : not yet implemented; falls back with a clear error
    """
    if name in ("local",):
        return LocalStorage()
    if name in ("mock", "mock_local"):
        return MockLocalProvider()
    raise ValueError(
        f"Provider '{name}' is not yet configured.\n"
        "  → Set PROVIDER=local in your .env for local testing.\n"
        "  → Set PROVIDER=mock for in-memory dev testing.\n"
        "  → For google_drive or backblaze, add the required credentials to .env."
    )
