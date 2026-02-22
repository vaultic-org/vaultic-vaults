from getpass import getpass
from rich.console import Console
from rich import print

console = Console(force_terminal=True, color_system="truecolor", stderr=True)


def prompt_passphrase(prompt: str = "Enter passphrase", confirm: bool = False) -> str:
    """
    Securely prompt for a passphrase and enforce that it is not empty.
    If confirm=True, asks for confirmation and loops until both entries match.

    Raises SystemExit if the user cancels (Ctrl+C).
    """
    while True:
        try:
            passphrase = getpass(f"🔑 {prompt}: ")
        except KeyboardInterrupt:
            print("\n[yellow]Passphrase input cancelled.[/yellow]")
            raise SystemExit(1)

        if not passphrase:
            print("[red]❌ Passphrase cannot be empty. Please try again.[/red]")
            continue

        if not confirm:
            return passphrase

        try:
            confirmation = getpass("🔑 Confirm passphrase: ")
        except KeyboardInterrupt:
            print("\n[yellow]Passphrase input cancelled.[/yellow]")
            raise SystemExit(1)

        if passphrase == confirmation:
            return passphrase

        print("[red]❌ Passphrases don't match. Try again.[/red]")
