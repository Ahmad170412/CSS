import typer
from pathlib import Path
from rich.console import Console

from css.engine import Sultanate

app = typer.Typer(
    name="css",
    help="Cyber Sultanate System - Autonomous Penetration Testing",
    no_args_is_help=True,
)
console = Console()


@app.command()
def run(
    target: str = typer.Argument(..., help="Target: domain, IP, or URL"),
    model: str = typer.Option("llama3.2:3b", "--model", "-m", help="Ollama model name"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed LLM responses"),
    output: Path = typer.Option(None, "--output", "-o", help="Save report to file (JSON or .txt)"),
    skip_raider: bool = typer.Option(False, "--skip-raider", help="Skip the exploitation phase"),
    max_workers: int = typer.Option(4, "--max-workers", "-w", help="Max parallel tool executions"),
):
    try:
        sultanate = Sultanate(target=target, model=model, verbose=verbose)
        sultanate.config.skip_raider = skip_raider
        sultanate.config.max_workers = max_workers
        sultanate.execute()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/]")
        raise typer.Exit(1)
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[bold red]Execution failed:[/] {e}")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        raise typer.Exit(1)

    if output:
        output = Path(output)
        try:
            if output.suffix.lower() == ".json":
                report = sultanate.get_json_report()
            else:
                report = sultanate.state.final_report
            output.write_text(report)
            console.print(f"[green]Report saved to {output}[/]")
        except Exception as e:
            console.print(f"[red]Failed to save report:[/] {e}")
            raise typer.Exit(1)


@app.command()
def list_models():
    """List available Ollama models."""
    import httpx
    try:
        resp = httpx.get("http://localhost:11434/api/tags", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        console.print("[bold]Available Ollama models:[/]")
        for m in data.get("models", []):
            name = m.get("name", "?")
            size = m.get("size", 0)
            size_gb = size / 1e9
            console.print(f"  {name} ({size_gb:.1f} GB)")
    except httpx.ConnectError:
        console.print("[red]Cannot connect to Ollama. Is it running?[/]")
        console.print("  Start with: [bold]ollama serve[/]")
    except httpx.TimeoutException:
        console.print("[red]Timeout connecting to Ollama[/]")
    except Exception as e:
        console.print(f"[red]Error fetching models:[/] {e}")


@app.command()
def version():
    """Show version info."""
    from css import __version__
    console.print(f"Cyber Sultanate System v{__version__}")


@app.command()
def doctor():
    """Check if required tools are installed."""
    import shutil
    tools = [
        ("nmap", "Port scanning"),
        ("gobuster", "Directory enumeration"),
        ("dnsrecon", "DNS enumeration"),
        ("whois", "WHOIS lookup"),
        ("searchsploit", "Exploit database search"),
        ("nikto", "Web vulnerability scanning"),
        ("sqlmap", "SQL injection exploitation"),
        ("hydra", "Brute force attacks"),
        ("msfconsole", "Metasploit exploitation"),
        ("shodan", "Shodan search (optional)"),
    ]
    console.print("[bold]Tool availability check:[/]")
    all_ok = True
    for tool, desc in tools:
        found = shutil.which(tool) is not None
        status = "[green]OK[/]" if found else "[red]MISSING[/]"
        console.print(f"  {tool:15} {status}  {desc}")
        if not found:
            all_ok = False
    # Check Ollama
    try:
        import httpx
        resp = httpx.get("http://localhost:11434/api/tags", timeout=3)
        if resp.status_code == 200:
            console.print(f"  {'ollama':15} [green]OK[/]  Local LLM server")
        else:
            console.print(f"  {'ollama':15} [red]MISSING[/]  Local LLM server (ollama serve)")
            all_ok = False
    except Exception:
        console.print(f"  {'ollama':15} [red]MISSING[/]  Local LLM server (ollama serve)")
        all_ok = False

    if all_ok:
        console.print("\n[green]All required tools available![/]")
    else:
        console.print("\n[yellow]Some tools are missing. Install them for full functionality.[/]")
        raise typer.Exit(1)
