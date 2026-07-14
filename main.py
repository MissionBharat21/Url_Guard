"""
main.py
=======
Command-line entry point for URL Guard.

Usage:
    python main.py https://example.com          # scan a single URL
    python main.py example.com                  # scheme auto-added
    python main.py urls.txt                      # batch scan a file
    python main.py https://example.com --json    # also export JSON
    python main.py https://example.com --html    # also export HTML
"""

import argparse
import sys
from pathlib import Path
from typing import List

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from config import Config
from utils import setup_logger
from scanner import URLGuardScanner, InvalidURLError
from report import ReportGenerator

console = Console()
logger = setup_logger(__name__)


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="url_guard",
        description="URL Guard - Advanced Terminal URL Security Scanner",
    )
    parser.add_argument(
        "target",
        help="A URL to scan, or a path to a .txt file containing one URL per line.",
    )
    parser.add_argument(
        "--json", action="store_true", help="Export the report as JSON to reports/."
    )
    parser.add_argument(
        "--html", action="store_true", help="Export the report as HTML to reports/."
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Suppress the full terminal report (summary only)."
    )
    return parser


def read_urls_from_file(path: Path) -> List[str]:
    """Read non-empty, non-comment lines from a batch file."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def scan_one(url: str, export_json: bool, export_html: bool, quiet: bool) -> None:
    """Scan a single URL and render/export its report."""
    try:
        scanner = URLGuardScanner(url)
    except InvalidURLError as exc:
        console.print(f"[bold red]✖ {exc}[/bold red]")
        return

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(description=f"Scanning {scanner.url} ...", total=None)
            result = scanner.scan()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        return
    except Exception as exc:
        logger.error(f"Unhandled error scanning {url}: {exc}")
        console.print(f"[bold red]✖ Unexpected error scanning {url}: {exc}[/bold red]")
        return

    reporter = ReportGenerator(result)

    if quiet:
        reporter.print_summary_panel()
    else:
        reporter.print_full_report()

    if export_json:
        path = reporter.export_json()
        console.print(f"[green]JSON report saved:[/green] {path}")

    if export_html:
        path = reporter.export_html()
        console.print(f"[green]HTML report saved:[/green] {path}")


def main() -> None:
    """CLI entry point."""
    Config.ensure_directories()
    parser = build_arg_parser()
    args = parser.parse_args()

    target_path = Path(args.target)

    try:
        if target_path.suffix.lower() == ".txt" and target_path.exists():
            urls = read_urls_from_file(target_path)
            if not urls:
                console.print("[yellow]No URLs found in the supplied file.[/yellow]")
                sys.exit(1)
            console.print(f"[cyan]Batch scanning {len(urls)} URL(s)...[/cyan]\n")
            for idx, url in enumerate(urls, start=1):
                console.rule(f"[bold]URL {idx}/{len(urls)}[/bold]")
                scan_one(url, args.json, args.html, args.quiet)
        else:
            scan_one(args.target, args.json, args.html, args.quiet)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user. Exiting.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        logger.error(f"Fatal error: {exc}")
        console.print(f"[bold red]Fatal error: {exc}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
