#!/usr/bin/env python3
"""
Suika Hunter v2.0 - Next Gen Bug Bounty Tool
Async, modular, AI-powered vulnerability scanner
"""

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from suika_hub.core.config import AuthConfig, ScanConfig
from suika_hub.core.engine import SuikaEngine
from suika_hub.modules import (
    APIFuzzer,
    AuthBypassScanner,
    FileUploadScanner,
    IDORScanner,
    ReconScanner,
    RedStormScanner,
    SSRFScanner,
)

app = typer.Typer(add_completion=False)
console = Console()


def banner():
    console.print(Panel.fit(
        "[bold red]"
        "  ___       _ _           _  _          _           \n"
        " / __|_  _ (_) |____ _   | || |_  _ _ _| |_ ___ _ _ \n"
        " \\__ \\ || | | / / _` |  | __ | || | ' \\  _/ -_) '_|\n"
        " |___/\\_,_|_|_\\_\\__,_|  |_||_|\\_,_|_||_\\__\\___|_|  \n"
        "[/bold red]\n"
        "[dim]v2.0 - Async | Modular | AI-Powered | 7 Modules[/dim]",
        border_style="red",
    ))


def build_engine() -> SuikaEngine:
    """Build engine with all modules registered"""
    engine = SuikaEngine()
    engine.register(RedStormScanner)
    engine.register(IDORScanner)
    engine.register(ReconScanner)
    engine.register(APIFuzzer)
    engine.register(AuthBypassScanner)
    engine.register(FileUploadScanner)
    engine.register(SSRFScanner)
    return engine


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target URL or domain"),
    module: str = typer.Option(..., "--module", "-m", help="Modules: redstorm,idor,recon,api,auth,upload,ssrf (comma-separated)"),
    cookie: str | None = typer.Option(None, "--cookie", help="Session cookie: 'key=val; key2=val2'"),
    har: str | None = typer.Option(None, "--har", help="HAR file path to import session"),
    session: str | None = typer.Option(None, "--session", help="Session JSON from capture server"),
    delay: float = typer.Option(1.5, "--delay", "-d", help="Delay between requests (seconds)"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Max concurrent requests"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout (seconds)"),
    output: str = typer.Option("reports", "--output", "-o", help="Output directory"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    browser: bool = typer.Option(False, "--browser", "-b", help="Use browser for Cloudflare bypass"),
):
    """Run vulnerability scan against target"""
    banner()

    # Parse cookies
    cookies = {}
    headers = {}

    if cookie:
        for item in cookie.split(";"):
            if "=" in item:
                k, v = item.strip().split("=", 1)
                cookies[k] = v

    # Import from HAR file
    if har:
        try:
            from suika_hub.core.har_parser import HARParser
            parser = HARParser(har)
            session_data = parser.get_session_info()
            cookies.update(session_data.get("cookies", {}))
            headers.update(session_data.get("headers", {}))
            console.print(f"[green]Imported from HAR: {len(cookies)} cookies, {len(headers)} headers[/green]")
        except Exception as e:
            console.print(f"[red]HAR import failed: {e}[/red]")

    # Import from session file (from capture server)
    if session:
        try:
            import json
            from pathlib import Path
            session_data = json.loads(Path(session).read_text())
            cookies.update(session_data.get("cookies", {}))
            headers.update(session_data.get("headers", {}))
            console.print(f"[green]Imported session: {len(cookies)} cookies[/green]")
        except Exception as e:
            console.print(f"[red]Session import failed: {e}[/red]")

    # Build config
    config = ScanConfig(
        target=target,
        modules=[m.strip() for m in module.split(",")],
        auth=AuthConfig(cookies=cookies, headers=headers),
        delay=delay,
        concurrency=concurrency,
        timeout=timeout,
        use_browser=browser,
        output_dir=output,
        verbose=verbose,
    )

    # Build engine and run
    engine = build_engine()
    asyncio.run(engine.run(config))


@app.command()
def modules():
    """List available modules"""
    banner()

    table = Table(title="Available Modules", border_style="red")
    table.add_column("Alias", style="cyan", width=12)
    table.add_column("Module", style="dim", width=20)
    table.add_column("Description")

    mods = [
        ("redstorm", "redstorm_scanner", "RedStorm platform (leaderboard IDOR, program enum, endpoint testing)"),
        ("idor", "idor_scanner", "Generic IDOR with pattern detection + baseline comparison"),
        ("recon", "recon_scanner", "Subdomain enum + endpoint discovery + tech fingerprinting"),
        ("api", "api_fuzzer", "SQLi, NoSQL injection, XSS, boundary testing"),
        ("auth", "auth_bypass", "Auth bypass, privilege escalation, method tampering, mass assignment"),
        ("upload", "upload_scanner", "File upload bypass: double ext, null byte, polyglot, content-type"),
        ("ssrf", "ssrf_scanner", "SSRF: internal access, cloud metadata, protocol smuggling, bypass"),
    ]

    for alias, name, desc in mods:
        table.add_row(alias, name, desc)

    console.print(table)
    console.print("\n[dim]Combine: --module redstorm,idor,auth,ssrf[/dim]")
    console.print("[dim]All:     --module redstorm,idor,recon,api,auth,upload,ssrf[/dim]")


@app.command()
def recommend(
    target: str = typer.Option("redstorm", "--target", "-t", help="Target profile: redstorm, web, api"),
    time_budget: int = typer.Option(300, "--time", help="Time budget in seconds"),
):
    """AI-powered module recommendation based on target profile"""
    banner()

    from suika_hub.core.decision_engine import DecisionEngine

    engine = DecisionEngine()

    if target == "redstorm":
        recommendations = engine.recommend_for_redstorm()
    else:
        from suika_hub.core.decision_engine import TargetProfile
        profile = TargetProfile(domain=target)
        recommendations = engine.recommend_modules(profile, time_budget)

    table = Table(title="Recommended Scan Strategy", border_style="red")
    table.add_column("#", style="dim", width=3)
    table.add_column("Module", style="cyan", width=18)
    table.add_column("Score", justify="right", width=7)
    table.add_column("Time", justify="right", width=6)
    table.add_column("Reason")

    for i, rec in enumerate(recommendations, 1):
        table.add_row(
            str(i),
            rec["module"].replace("_scanner", ""),
            f"{rec['score']:.2f}",
            f"{rec['time_estimate']}s",
            rec.get("notes", rec["reason"]),
        )

    console.print(table)

    # Generate command
    module_list = ",".join(r["module"].replace("_scanner", "").replace("_fuzzer", "").replace("_bypass", "") for r in recommendations)
    total_time = sum(r["time_estimate"] for r in recommendations)
    console.print("\n[bold]Suggested command:[/bold]")
    console.print(f"  suika-hub scan -t https://www.redstorm.io -m {module_list} --cookie 'session=xxx'")
    console.print(f"\n[dim]Estimated time: {total_time}s ({total_time//60}m {total_time%60}s)[/dim]")


@app.command()
def server(
    host: str = typer.Option("127.0.0.1", "--host", help="Server host"),
    port: int = typer.Option(9999, "--port", "-p", help="Server port"),
):
    """Start capture server (receives data from browser extension)"""
    banner()
    from suika_hub.server import run_server
    run_server(host=host, port=port)


@app.command()
def import_har(
    har_file: str = typer.Argument(..., help="Path to HAR file"),
    domain: str | None = typer.Option(None, "--domain", help="Filter by domain"),
):
    """Import and analyze a HAR file"""
    banner()

    from suika_hub.core.har_parser import HARParser

    try:
        parser = HARParser(har_file)
        info = parser.get_session_info(domain)

        console.print("\n[bold]HAR Analysis:[/bold]")
        console.print(f"  Cookies: {len(info['cookies'])}")
        console.print(f"  Auth headers: {len(info['headers'])}")
        console.print(f"  Endpoints: {len(info['endpoints'])}")

        patterns = info.get("patterns", {})
        console.print(f"  API bases: {patterns.get('api_bases', [])}")
        console.print(f"  ID patterns: {patterns.get('id_patterns', [])[:5]}")
        console.print(f"  Methods: {patterns.get('methods', [])}")

        console.print("\n[bold]Top Endpoints:[/bold]")
        for ep in info["endpoints"][:20]:
            status_color = "green" if ep["status"] == 200 else "yellow" if ep["status"] < 400 else "red"
            console.print(f"  [{status_color}]{ep['status']}[/{status_color}] {ep['method']:6} {ep['path']}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
