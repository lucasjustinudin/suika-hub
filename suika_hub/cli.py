#!/usr/bin/env python3
"""
suika-hub - modular web security scanning toolkit
Async, modular, AI-powered vulnerability scanner
"""

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from suika_hub._version import __version__
from suika_hub.core.config import AuthConfig, ScanConfig
from suika_hub.core.engine import SuikaEngine
from suika_hub.modules import (
    APIFuzzer,
    AuthBypassScanner,
    FileUploadScanner,
    GraphQLScanner,
    IDORScanner,
    JWTScanner,
    ReconScanner,
    SSRFScanner,
)

app = typer.Typer(add_completion=False)
console = Console()


def banner():
    console.print(
        Panel.fit(
            "[bold red]"
            "  ___       _ _           _  _          _           \n"
            " / __|_  _ (_) |____ _   | || |_  _ _ _| |_ ___ _ _ \n"
            " \\__ \\ || | | / / _` |  | __ | || | ' \\  _/ -_) '_|\n"
            " |___/\\_,_|_|_\\_\\__,_|  |_||_|\\_,_|_||_\\__\\___|_|  \n"
            "[/bold red]\n"
            f"[dim]v{__version__} - Async | Modular | Extensible[/dim]",
            border_style="red",
        )
    )


def build_engine() -> SuikaEngine:
    """Build engine with all modules registered"""
    engine = SuikaEngine()
    engine.register(IDORScanner)
    engine.register(ReconScanner)
    engine.register(APIFuzzer)
    engine.register(AuthBypassScanner)
    engine.register(FileUploadScanner)
    engine.register(SSRFScanner)
    engine.register(GraphQLScanner)
    engine.register(JWTScanner)
    return engine


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target URL or domain"),
    module: str = typer.Option(
        ...,
        "--module",
        "-m",
        help="Modules: idor,recon,api,auth,upload,ssrf,graphql,jwt (comma-separated)",
    ),
    cookie: str | None = typer.Option(None, "--cookie", help="Session cookie: 'key=val; key2=val2'"),
    har: str | None = typer.Option(None, "--har", help="HAR file path to import session"),
    session: str | None = typer.Option(None, "--session", help="Session JSON from capture server"),
    jwt: str | None = typer.Option(None, "--jwt", help="JWT to test (jwt module)"),
    graphql_endpoint: str | None = typer.Option(
        None, "--graphql-endpoint", help="Explicit GraphQL endpoint (graphql module)"
    ),
    proxies: str | None = typer.Option(None, "--proxies", help="Comma-separated proxy list to rotate"),
    rate_limit: float = typer.Option(5.0, "--rate-limit", help="Max requests/second per host (0 disables)"),
    delay: float = typer.Option(1.5, "--delay", "-d", help="Delay between requests (seconds)"),
    concurrency: int = typer.Option(5, "--concurrency", "-c", help="Max concurrent requests"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout (seconds)"),
    proxy: str | None = typer.Option(None, "--proxy", help="Single upstream proxy"),
    output: str = typer.Option("reports", "--output", "-o", help="Output directory"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    browser: bool = typer.Option(False, "--browser", "-b", help="Use browser for Cloudflare bypass"),
    plugin: list[str] = typer.Option(
        [],
        "--plugin",
        help="Load plugin from a .py file or directory (repeatable)",
    ),
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
    extra: dict = {}
    if jwt:
        extra["jwt"] = jwt
    if graphql_endpoint:
        extra["graphql_endpoints"] = [graphql_endpoint]

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
        proxy=proxy,
        proxies=[p.strip() for p in proxies.split(",") if p.strip()] if proxies else [],
        rate_limit=rate_limit,
        extra=extra,
    )

    # Build engine, load any plugins, then run
    engine = build_engine()
    _load_plugins(engine, plugin)
    asyncio.run(engine.run(config))


def _load_plugins(engine: SuikaEngine, paths: list[str] | None = None) -> None:
    """Discover and register plugins, reporting anything that failed to load.

    Failures are printed rather than raised: a broken third-party plugin must
    not prevent a scan from running with the built-in modules.
    """
    from suika_hub.core.plugins import load_and_register

    result = load_and_register(engine, paths=list(paths or []))

    for cls in result.loaded:
        console.print(f"[green]Plugin loaded:[/green] {cls.name} ({cls.__name__})")
    for name, message in result.errors:
        console.print(f"[yellow]Plugin skipped[/yellow] {name}: {message}")


@app.command()
def modules():
    """List available modules"""
    banner()

    table = Table(title="Available Modules", border_style="red")
    table.add_column("Alias", style="cyan", width=14)
    table.add_column("Module", style="dim", width=20)
    table.add_column("Description")

    # Introspected from the engine rather than hardcoded, so this listing cannot
    # drift away from what is actually registered.
    engine = build_engine()
    rows = []
    for name, instance in engine.modules.items():
        alias = name.replace("_scanner", "").replace("_fuzzer", "").replace("_bypass", "")
        rows.append((alias, name, instance.description))
    rows.sort()

    for alias, name, desc in rows:
        table.add_row(alias, name, desc)

    console.print(table)
    aliases = ",".join(a for a, _, _ in rows)
    console.print(f"\n[dim]Combine: --module {aliases}[/dim]")


@app.command()
def recommend(
    target: str = typer.Option(
        "nodejs",
        "--target",
        "-t",
        help="Target profile: nodejs, python, php, java, spa",
    ),
    time_budget: int = typer.Option(300, "--time", help="Time budget in seconds"),
):
    """AI-powered module recommendation based on target profile"""
    banner()

    from suika_hub.core.decision_engine import DecisionEngine

    engine = DecisionEngine()

    recommendations = engine.recommend_for_profile(target)
    if not recommendations:
        # Unknown profile name: treat the value as a bare domain and score it
        # with the default stack assumptions rather than erroring out.
        from suika_hub.core.decision_engine import TargetProfile

        recommendations = engine.recommend_modules(TargetProfile(domain=target), time_budget)

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
    module_list = ",".join(
        r["module"].replace("_scanner", "").replace("_fuzzer", "").replace("_bypass", "") for r in recommendations
    )
    total_time = sum(r["time_estimate"] for r in recommendations)
    console.print("\n[bold]Suggested command:[/bold]")
    console.print(f"  suika-hub scan -t https://example.com -m {module_list} --cookie 'session=xxx'")
    console.print(f"\n[dim]Estimated time: {total_time}s ({total_time // 60}m {total_time % 60}s)[/dim]")


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
