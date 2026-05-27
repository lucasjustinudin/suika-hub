"""Async scan engine - orchestrates modules"""
import asyncio
import time
from typing import Dict, List, Type
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from core.config import ScanConfig
from core.http import AsyncClient
from core.module import BaseModule, Finding
from core.reporter import Reporter

console = Console()


class SuikaEngine:
    """Main async scan engine"""

    def __init__(self):
        self.modules: Dict[str, BaseModule] = {}
        self.aliases: Dict[str, str] = {}

    def register(self, module_class: Type[BaseModule]):
        """Register a module class"""
        instance = module_class()
        self.modules[instance.name] = instance
        # Auto alias: "redstorm_scanner" -> "redstorm"
        short = instance.name.replace("_scanner", "").replace("_module", "")
        self.aliases[short] = instance.name
        self.aliases[instance.name] = instance.name

    def resolve(self, name: str) -> BaseModule:
        """Resolve module by name or alias"""
        real_name = self.aliases.get(name)
        if real_name:
            return self.modules.get(real_name)
        return None

    async def run(self, config: ScanConfig) -> Dict:
        """Run scan with given config"""
        start_time = time.time()

        console.print(Panel.fit(
            f"[bold red]SUIKA HUNTER v2.0[/bold red]\n"
            f"Target: [cyan]{config.target}[/cyan]\n"
            f"Modules: [green]{', '.join(config.modules)}[/green]\n"
            f"Concurrency: {config.concurrency} | Delay: {config.delay}s",
            title="Scan Started",
            border_style="red",
        ))

        # Build HTTP client
        async with AsyncClient(
            cookies=config.auth.cookies,
            headers=config.auth.headers,
            proxy=config.proxy,
            timeout=config.timeout,
            concurrency=config.concurrency,
            delay=config.delay,
        ) as client:
            all_findings: List[Finding] = []
            modules_run = []

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                for module_name in config.modules:
                    module = self.resolve(module_name)
                    if not module:
                        console.print(f"[yellow]Module not found: {module_name}[/yellow]")
                        console.print(f"  Available: {', '.join(self.aliases.keys())}")
                        continue

                    task = progress.add_task(f"[cyan]{module.name}[/cyan]", total=None)
                    module.reset()

                    try:
                        findings = await module.execute(config.target, client, config.model_dump())
                        all_findings.extend(findings)
                        modules_run.append(module.name)
                        progress.update(task, completed=True)
                    except Exception as e:
                        console.print(f"[red]Error in {module.name}: {e}[/red]")

        elapsed = time.time() - start_time

        # Results
        result = {
            "target": config.target,
            "modules_executed": modules_run,
            "findings": all_findings,
            "stats": {
                "duration_seconds": round(elapsed, 2),
                "total_findings": len(all_findings),
                "by_severity": self._count_severity(all_findings),
            },
        }

        # Print summary
        self._print_summary(result)

        # Save report
        reporter = Reporter(config.output_dir)
        reporter.save(result)

        return result

    def _count_severity(self, findings: List[Finding]) -> Dict[str, int]:
        counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _print_summary(self, result: Dict):
        """Print rich summary table"""
        console.print()

        table = Table(title="Scan Results", border_style="red")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        severity_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
        for sev, count in result["stats"]["by_severity"].items():
            color = severity_colors.get(sev, "white")
            table.add_row(f"[{color}]{sev}[/{color}]", str(count))

        console.print(table)
        console.print(f"\n[bold]Duration:[/bold] {result['stats']['duration_seconds']}s")
        console.print(f"[bold]Total findings:[/bold] {result['stats']['total_findings']}")

        # Print top findings
        if result["findings"]:
            console.print("\n[bold red]Top Findings:[/bold red]")
            for i, f in enumerate(result["findings"][:10], 1):
                sev = f.get("severity", "INFO")
                color = severity_colors.get(sev, "white")
                console.print(f"  {i}. [{color}][{sev}][/{color}] {f.get('title', 'No title')}")
                if f.get("url"):
                    console.print(f"     [dim]{f['url']}[/dim]")
