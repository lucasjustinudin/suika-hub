"""
Suika Hunter v2 - Local Capture Server
Receives session data from browser extension
Serves as bridge between extension and scanner
"""

import json
from datetime import datetime
from pathlib import Path

from aiohttp import web
from rich.console import Console

console = Console()

# Storage
SESSION_DIR = Path("sessions")
SESSION_DIR.mkdir(exist_ok=True)

captured_sessions: dict[str, dict] = {}
captured_requests: list = []


async def health(request):
    """Health check endpoint"""
    return web.json_response({"status": "ok", "version": "2.0.0"})


async def capture(request):
    """Receive captured data from extension"""
    data = await request.json()
    event_type = data.get("type")
    payload = data.get("data", {})

    if event_type == "cookie":
        domain = payload.get("domain", "unknown").lstrip(".")
        if domain not in captured_sessions:
            captured_sessions[domain] = {"cookies": {}, "headers": {}, "endpoints": []}
        captured_sessions[domain]["cookies"][payload["name"]] = payload["value"]
        console.print(f"  [dim]Cookie: {payload['name']}={payload['value'][:20]}... ({domain})[/dim]")

    elif event_type == "request":
        captured_requests.append(payload)
        # Extract domain
        from urllib.parse import urlparse
        parsed = urlparse(payload.get("url", ""))
        domain = parsed.netloc
        if domain and domain not in captured_sessions:
            captured_sessions[domain] = {"cookies": {}, "headers": {}, "endpoints": []}
        if domain:
            captured_sessions[domain]["endpoints"].append({
                "method": payload.get("method"),
                "path": parsed.path,
                "params": payload.get("params", {}),
            })

    return web.json_response({"ok": True})


async def receive_session(request):
    """Receive full session export from extension"""
    session = await request.json()
    domain = session.get("domain", "unknown")

    # Store in memory
    captured_sessions[domain] = {
        "cookies": session.get("cookies", {}),
        "headers": session.get("headers", {}),
        "endpoints": session.get("endpoints", []),
        "requests": session.get("requests", []),
        "exported_at": session.get("exported_at"),
    }

    # Save to file
    filename = SESSION_DIR / f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filename.write_text(json.dumps(session, indent=2))

    console.print(f"\n[bold green]Session received: {domain}[/bold green]")
    console.print(f"  Cookies: {len(session.get('cookies', {}))}")
    console.print(f"  Headers: {len(session.get('headers', {}))}")
    console.print(f"  Endpoints: {len(session.get('endpoints', []))}")
    console.print(f"  Saved: {filename}")
    console.print("  [cyan]Ready to scan! Run:[/cyan]")
    console.print(f"  suika-hub scan -t https://{domain} -m redstorm --session {filename}\n")

    return web.json_response({
        "ok": True,
        "message": f"Session saved: {filename}",
        "cookies": len(session.get("cookies", {})),
    })


async def get_session(request):
    """Get captured session for a domain"""
    domain = request.match_info.get("domain")
    if domain in captured_sessions:
        return web.json_response(captured_sessions[domain])
    return web.json_response({"error": "No session for domain"}, status=404)


async def list_sessions(request):
    """List all captured sessions"""
    sessions = []
    for domain, data in captured_sessions.items():
        sessions.append({
            "domain": domain,
            "cookies": len(data.get("cookies", {})),
            "headers": len(data.get("headers", {})),
            "endpoints": len(data.get("endpoints", [])),
        })
    return web.json_response({"sessions": sessions})


async def trigger_scan(request):
    """Trigger scan from extension (auto-scan on session export)"""
    data = await request.json()
    domain = data.get("domain")
    modules = data.get("modules", ["redstorm"])

    if domain not in captured_sessions:
        return web.json_response({"error": "No session captured for domain"}, status=400)

    session = captured_sessions[domain]

    from suika_hub.core.config import AuthConfig, ScanConfig
    from suika_hub.core.engine import SuikaEngine
    from suika_hub.modules import APIFuzzer, AuthBypassScanner, IDORScanner, ReconScanner, RedStormScanner

    config = ScanConfig(
        target=f"https://{domain}",
        modules=modules,
        auth=AuthConfig(
            cookies=session.get("cookies", {}),
            headers=session.get("headers", {}),
        ),
        delay=1.5,
        concurrency=3,
    )

    engine = SuikaEngine()
    engine.register(RedStormScanner)
    engine.register(IDORScanner)
    engine.register(ReconScanner)
    engine.register(APIFuzzer)
    engine.register(AuthBypassScanner)

    # Run scan async
    results = await engine.run(config)

    return web.json_response({
        "ok": True,
        "findings": len(results.get("findings", [])),
        "results": results,
    })


def create_app():
    """Create aiohttp app"""
    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_post("/capture", capture)
    app.router.add_post("/session", receive_session)
    app.router.add_get("/session/{domain}", get_session)
    app.router.add_get("/sessions", list_sessions)
    app.router.add_post("/scan", trigger_scan)
    return app


def run_server(host: str = "127.0.0.1", port: int = 9999):
    """Start the capture server"""
    console.print("\n[bold red]Suika Hunter v2 - Capture Server[/bold red]")
    console.print(f"[dim]Listening on {host}:{port}[/dim]")
    console.print("[dim]Waiting for browser extension data...[/dim]\n")
    console.print("[bold]Endpoints:[/bold]")
    console.print("  GET  /health          - Health check")
    console.print("  POST /capture         - Receive live captures")
    console.print("  POST /session         - Receive full session export")
    console.print("  GET  /session/{domain} - Get session for domain")
    console.print("  GET  /sessions        - List all sessions")
    console.print("  POST /scan            - Trigger scan with captured session")
    console.print()

    app = create_app()
    web.run_app(app, host=host, port=port, print=None)


if __name__ == "__main__":
    run_server()
