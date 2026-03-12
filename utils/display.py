import sys
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.text import Text
from rich.live import Live

console = Console()


def print_banner():
    banner = Text()
    banner.append("╔══════════════════════════════════════════╗\n", style="bold cyan")
    banner.append("║       AI RECON & VULNERABILITY AGENT     ║\n", style="bold cyan")
    banner.append("║   Autonomous Security Research Assistant  ║\n", style="bold cyan")
    banner.append("╚══════════════════════════════════════════╝", style="bold cyan")
    console.print(banner)
    console.print()


def print_tool_call(tool_name, args_summary):
    console.print(f"[bold yellow]⚡ Tool: [/bold yellow][yellow]{tool_name}[/yellow]")
    console.print(f"[dim yellow]   Args: {args_summary}[/dim yellow]")


def print_tool_result(result, max_lines=50):
    lines = result.strip().split("\n")
    if len(lines) > max_lines:
        truncated = "\n".join(lines[:max_lines])
        truncated += f"\n... ({len(lines) - max_lines} more lines truncated)"
    else:
        truncated = result.strip()
    console.print(Panel(truncated, title="[green]Tool Output[/green]", border_style="green", expand=False))


def print_agent_message(text):
    console.print()
    md = Markdown(text)
    console.print(Panel(md, title="[bold blue]Agent Report[/bold blue]", border_style="blue"))
    console.print()


def print_error(text):
    console.print(f"[bold red]❌ Error: {text}[/bold red]")


def print_info(text):
    console.print(f"[bold green]ℹ {text}[/bold green]")


def print_warning(text):
    console.print(f"[bold yellow]⚠ {text}[/bold yellow]")


def get_user_input():
    console.print()
    return console.input("[bold magenta]🔍 Enter your task > [/bold magenta]")


def confirm_command(command):
    console.print(f"[bold red]⚠ Agent wants to run:[/bold red] [white]{command}[/white]")
    response = console.input("[bold red]Allow? (y/n) > [/bold red]").strip().lower()
    return response in ("y", "yes")


# --- Streaming helpers ---

class StreamPrinter:
    """Prints streamed text token-by-token with a label prefix."""

    def __init__(self, label, style):
        self.label = label
        self.style = style
        self.started = False
        self.buffer = ""

    def start(self):
        console.print(f"[{self.style}]{self.label}[/{self.style}]", end="")
        self.started = True

    def write(self, text):
        if not self.started:
            self.start()
        # Write raw text character by character for streaming effect
        sys.stdout.write(text)
        sys.stdout.flush()
        self.buffer += text

    def end(self):
        if self.started:
            sys.stdout.write("\n")
            sys.stdout.flush()
        self.started = False
        content = self.buffer
        self.buffer = ""
        return content


def create_thinking_stream():
    """Create a stream printer for agent thinking/reasoning."""
    return StreamPrinter("🧠 Thinking: ", "dim cyan")


def create_response_stream():
    """Create a stream printer for agent final response."""
    return StreamPrinter("\n📋 ", "bold blue")


def print_step_header(iteration, max_iter):
    console.print(f"\n[bold white on blue] Step {iteration}/{max_iter} [/bold white on blue]")
