import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure common local binary locations are available to subprocess-based tools.
for _bin_dir in (os.path.expanduser("~/.local/bin"), "/opt/homebrew/bin", "/usr/local/bin"):
    if os.path.isdir(_bin_dir) and _bin_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{_bin_dir}:{os.environ.get('PATH', '')}"

from dotenv import load_dotenv
load_dotenv()

from agent.core import Agent
from agent.llm import get_model
from utils.display import (
    print_banner,
    print_error,
    print_info,
    print_warning,
    get_user_input,
    console,
)


def check_env():
    key = os.getenv("OPENROUTER_API_KEY")
    if not key or key == "your_openrouter_api_key_here":
        print_error("OPENROUTER_API_KEY not configured.")
        print_info("Copy .env.example to .env and add your OpenRouter API key:")
        console.print("  cp .env.example .env", style="bold white")
        console.print("  # Then edit .env and set OPENROUTER_API_KEY", style="dim")
        return False
    return True


def main():
    print_banner()

    if not check_env():
        sys.exit(1)

    model = get_model()
    print_info(f"Using model: {model}")
    print_info("Tools available: full recon suite + on-demand scanners (trufflehog, gitleaks, aquatone, testssl, naabu, waybackurls, arjun, wfuzz, semgrep)")
    print_warning("Only scan websites you own or have explicit permission to test.")
    console.print()
    console.print("[dim]Type your task below. Examples:[/dim]")
    console.print("[dim]  • Scan https://example.com for vulnerabilities[/dim]")
    console.print("[dim]  • I'm at a coffee shop in Shibuya, Tokyo. Find CCTV cameras around me.[/dim]")
    console.print("[dim]  • Type 'reset' to clear conversation, 'exit' to quit.[/dim]")
    console.print()

    agent = Agent()

    while True:
        try:
            user_input = get_user_input()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold cyan]Goodbye![/bold cyan]")
            break

        if not user_input.strip():
            continue

        cmd = user_input.strip().lower()
        if cmd in ("exit", "quit", "q"):
            console.print("[bold cyan]Goodbye![/bold cyan]")
            break
        elif cmd == "reset":
            agent.reset()
            print_info("Conversation reset. Starting fresh.")
            continue

        try:
            agent.run(user_input)
        except KeyboardInterrupt:
            print_warning("Interrupted. You can continue with a new task or type 'exit'.")
        except Exception as e:
            print_error(f"Unexpected error: {str(e)}")


if __name__ == "__main__":
    main()
