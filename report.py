"""
report.py
=========
Terminal UI rendering (Rich panels/tables) and report export to
JSON and HTML. Consumes the aggregated scan result dictionary
produced by scanner.py.
"""

import html as html_lib
from pathlib import Path
from typing import Any, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from config import Config
from utils import save_json, timestamp_slug, safe_filename_from_url

console = Console()


class ReportGenerator:
    """Renders scan results to the terminal and exports them to disk."""

    def __init__(self, scan_result: Dict[str, Any]) -> None:
        """
        Args:
            scan_result: The full result dict returned by
                scanner.URLGuardScanner.scan().
        """
        self.result = scan_result

    # ------------------------------------------------------------------
    # Terminal rendering
    # ------------------------------------------------------------------

    def _verdict_style(self, verdict: str) -> str:
        return {
            "LOW RISK": "bold green",
            "MEDIUM RISK": "bold yellow",
            "HIGH RISK": "bold red",
            "CRITICAL RISK": "bold white on red",
        }.get(verdict, "bold white")

    def print_summary_panel(self) -> None:
        """Print the top-level risk score / verdict panel."""
        score = self.result["risk"]["score"]
        verdict = self.result["risk"]["verdict"]
        style = self._verdict_style(verdict)

        body = Text()
        body.append(f"URL: {self.result['original_url']}\n", style="cyan")
        body.append(f"Final URL: {self.result['redirects']['final_url']}\n", style="cyan")
        body.append(f"\nRisk Score: {score}/100\n", style=style)
        body.append(f"Verdict: {verdict}", style=style)

        console.print(Panel(body, title="🛡  URL Guard - Scan Summary", box=box.ROUNDED))

    def print_redirect_table(self) -> None:
        """Print the redirect chain as a table."""
        redirects = self.result["redirects"]
        table = Table(title="Redirect Chain", box=box.SIMPLE_HEAVY)
        table.add_column("#", justify="right")
        table.add_column("URL", overflow="fold")
        table.add_column("Status")

        for idx, hop in enumerate(redirects["chain"], start=1):
            table.add_row(str(idx), hop["url"], str(hop["status_code"]))

        console.print(table)

        if redirects.get("loop_detected"):
            console.print("[bold red]⚠ Redirect loop detected![/bold red]")
        if redirects.get("domain_changed"):
            console.print("[bold yellow]⚠ Final domain differs from original.[/bold yellow]")
        if redirects.get("shortener_used"):
            console.print("[bold yellow]ℹ URL shortener detected and expanded.[/bold yellow]")
        if redirects.get("error"):
            console.print(f"[red]Redirect error: {redirects['error']}[/red]")

    def print_ssl_panel(self) -> None:
        """Print HTTPS/SSL certificate details."""
        ssl_info = self.result["ssl"]
        table = Table(box=box.SIMPLE)
        table.add_column("Field")
        table.add_column("Value", overflow="fold")

        table.add_row("HTTPS Enabled", "✅ Yes" if ssl_info.get("https_enabled") else "❌ No")
        table.add_row("Certificate Valid", "✅ Yes" if ssl_info.get("valid") else "❌ No")
        table.add_row("Self-Signed", "⚠ Yes" if ssl_info.get("self_signed") else "No")
        table.add_row("Issuer", str(ssl_info.get("issuer") or "N/A"))
        table.add_row("Expires", str(ssl_info.get("not_after") or "N/A"))
        table.add_row("Days Remaining", str(ssl_info.get("days_remaining")
                                             if ssl_info.get("days_remaining") is not None else "N/A"))
        if ssl_info.get("error"):
            table.add_row("Error", str(ssl_info["error"]))

        console.print(Panel(table, title="🔒 HTTPS / SSL Inspection", box=box.ROUNDED))

    def print_dns_panel(self) -> None:
        """Print DNS record results."""
        dns_info = self.result["dns"]
        table = Table(box=box.SIMPLE)
        table.add_column("Record Type")
        table.add_column("Values", overflow="fold")

        for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR"]:
            values = dns_info.get(record_type) or []
            table.add_row(record_type, ", ".join(values) if values else "—")

        console.print(Panel(table, title="🌐 DNS Analysis", box=box.ROUNDED))

    def print_whois_panel(self) -> None:
        """Print WHOIS registration details."""
        whois_info = self.result["whois"]
        table = Table(box=box.SIMPLE)
        table.add_column("Field")
        table.add_column("Value", overflow="fold")

        table.add_row("Registrar", str(whois_info.get("registrar") or "N/A"))
        table.add_row("Created", str(whois_info.get("creation_date") or "N/A"))
        table.add_row("Expires", str(whois_info.get("expiration_date") or "N/A"))
        table.add_row("Updated", str(whois_info.get("updated_date") or "N/A"))
        table.add_row("Name Servers", ", ".join(whois_info.get("name_servers") or []) or "N/A")
        table.add_row("Country", str(whois_info.get("country") or "N/A"))
        table.add_row("Organization", str(whois_info.get("organization") or "N/A"))

        if whois_info.get("is_newly_registered"):
            table.add_row(
                "Domain Age",
                f"⚠ {whois_info.get('domain_age_days')} days (newly registered)",
            )
        elif whois_info.get("domain_age_days") is not None:
            table.add_row("Domain Age", f"{whois_info['domain_age_days']} days")

        if whois_info.get("error"):
            table.add_row("Error", str(whois_info["error"]))

        console.print(Panel(table, title="📋 WHOIS Lookup", box=box.ROUNDED))

    def print_geoip_panel(self) -> None:
        """Print IP/GeoIP details."""
        geo = self.result["geoip"]
        table = Table(box=box.SIMPLE)
        table.add_column("Field")
        table.add_column("Value", overflow="fold")

        table.add_row("IPv4", str(self.result["ip_info"].get("ipv4") or "N/A"))
        table.add_row("IPv6", str(self.result["ip_info"].get("ipv6") or "N/A"))
        if geo:
            table.add_row("ASN", str(geo.get("asn") or "N/A"))
            table.add_row("ISP / Org", str(geo.get("isp") or geo.get("org") or "N/A"))
            table.add_row("Country", str(geo.get("country") or "N/A"))
            table.add_row("Region", str(geo.get("region") or "N/A"))
            table.add_row("City", str(geo.get("city") or "N/A"))
            table.add_row("Latitude", str(geo.get("latitude") or "N/A"))
            table.add_row("Longitude", str(geo.get("longitude") or "N/A"))

        console.print(Panel(table, title="📍 IP Information", box=box.ROUNDED))

    def print_heuristics_panel(self) -> None:
        """Print triggered phishing heuristic flags."""
        flags = self.result["heuristics"]["flags"]
        if not flags:
            console.print(Panel("[green]No suspicious heuristics triggered.[/green]",
                                 title="🕵 Phishing Heuristics", box=box.ROUNDED))
            return

        table = Table(box=box.SIMPLE)
        table.add_column("Flag")
        table.add_column("Description", overflow="fold")
        table.add_column("Weight", justify="right")

        for flag in flags:
            table.add_row(flag["name"], flag["description"], f"+{flag['weight']}")

        console.print(Panel(table, title="🕵 Phishing Heuristics", box=box.ROUNDED))

    def print_reputation_panel(self) -> None:
        """Print VirusTotal reputation results."""
        vt = self.result.get("virustotal", {})
        table = Table(box=box.SIMPLE)
        table.add_column("Field")
        table.add_column("Value")

        if not vt.get("available"):
            table.add_row("Status", vt.get("error") or "Not available")
        else:
            table.add_row("Malicious", str(vt.get("malicious", 0)))
            table.add_row("Suspicious", str(vt.get("suspicious", 0)))
            table.add_row("Harmless", str(vt.get("harmless", 0)))
            table.add_row("Undetected", str(vt.get("undetected", 0)))
            table.add_row("Total Engines", str(vt.get("total_engines", 0)))
            table.add_row("Permalink", str(vt.get("permalink") or "N/A"))

        console.print(Panel(table, title="🧪 Reputation Check (VirusTotal)", box=box.ROUNDED))

    def print_full_report(self) -> None:
        """Render the entire report to the terminal, section by section."""
        self.print_summary_panel()
        self.print_redirect_table()
        self.print_ssl_panel()
        self.print_dns_panel()
        self.print_whois_panel()
        self.print_geoip_panel()
        self.print_heuristics_panel()
        self.print_reputation_panel()

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self) -> Path:
        """Write the full scan result to reports/ as JSON."""
        Config.ensure_directories()
        filename = f"{safe_filename_from_url(self.result['original_url'])}_{timestamp_slug()}.json"
        path = Config.REPORTS_DIR / filename
        save_json(path, self.result)
        return path

    def export_html(self) -> Path:
        """Write a simple, self-contained HTML report to reports/."""
        Config.ensure_directories()
        filename = f"{safe_filename_from_url(self.result['original_url'])}_{timestamp_slug()}.html"
        path = Config.REPORTS_DIR / filename

        score = self.result["risk"]["score"]
        verdict = self.result["risk"]["verdict"]
        verdict_color = {
            "LOW RISK": "#2e7d32",
            "MEDIUM RISK": "#f9a825",
            "HIGH RISK": "#c62828",
            "CRITICAL RISK": "#7f0000",
        }.get(verdict, "#333")

        def esc(value: Any) -> str:
            return html_lib.escape(str(value)) if value is not None else "N/A"

        flags_html = "".join(
            f"<tr><td>{esc(f['name'])}</td><td>{esc(f['description'])}</td>"
            f"<td>+{esc(f['weight'])}</td></tr>"
            for f in self.result["heuristics"]["flags"]
        ) or "<tr><td colspan='3'>No suspicious heuristics triggered.</td></tr>"

        redirect_html = "".join(
            f"<tr><td>{i + 1}</td><td>{esc(hop['url'])}</td><td>{esc(hop['status_code'])}</td></tr>"
            for i, hop in enumerate(self.result["redirects"]["chain"])
        )

        dns_html = "".join(
            f"<tr><td>{rtype}</td><td>{esc(', '.join(self.result['dns'].get(rtype) or []) or '—')}</td></tr>"
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR"]
        )

        whois = self.result["whois"]
        geo = self.result["geoip"]
        ssl_info = self.result["ssl"]
        vt = self.result.get("virustotal", {})

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>URL Guard Report - {esc(self.result['original_url'])}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#0f1117; color:#e6e6e6; padding:2rem; }}
  h1, h2 {{ color:#ffffff; }}
  .verdict {{ display:inline-block; padding:0.5rem 1rem; border-radius:6px; background:{verdict_color}; color:white; font-weight:bold; }}
  table {{ width:100%; border-collapse: collapse; margin-bottom: 2rem; }}
  th, td {{ text-align:left; padding:0.5rem; border-bottom:1px solid #333; word-break: break-all; }}
  th {{ background:#1b1e27; }}
  .section {{ background:#161923; padding:1.5rem; border-radius:8px; margin-bottom:1.5rem; }}
</style>
</head>
<body>
  <h1>🛡 URL Guard Security Report</h1>
  <div class="section">
    <p><strong>Original URL:</strong> {esc(self.result['original_url'])}</p>
    <p><strong>Final URL:</strong> {esc(self.result['redirects']['final_url'])}</p>
    <p><strong>Risk Score:</strong> {esc(score)}/100</p>
    <p><strong>Verdict:</strong> <span class="verdict">{esc(verdict)}</span></p>
    <p><strong>Scan Time:</strong> {esc(self.result['scan_time'])}</p>
  </div>

  <div class="section">
    <h2>Redirect Chain</h2>
    <table><tr><th>#</th><th>URL</th><th>Status</th></tr>{redirect_html}</table>
  </div>

  <div class="section">
    <h2>HTTPS / SSL</h2>
    <table>
      <tr><th>HTTPS Enabled</th><td>{esc(ssl_info.get('https_enabled'))}</td></tr>
      <tr><th>Certificate Valid</th><td>{esc(ssl_info.get('valid'))}</td></tr>
      <tr><th>Self-Signed</th><td>{esc(ssl_info.get('self_signed'))}</td></tr>
      <tr><th>Issuer</th><td>{esc(ssl_info.get('issuer'))}</td></tr>
      <tr><th>Expires</th><td>{esc(ssl_info.get('not_after'))}</td></tr>
      <tr><th>Days Remaining</th><td>{esc(ssl_info.get('days_remaining'))}</td></tr>
    </table>
  </div>

  <div class="section">
    <h2>DNS Records</h2>
    <table><tr><th>Type</th><th>Values</th></tr>{dns_html}</table>
  </div>

  <div class="section">
    <h2>WHOIS</h2>
    <table>
      <tr><th>Registrar</th><td>{esc(whois.get('registrar'))}</td></tr>
      <tr><th>Created</th><td>{esc(whois.get('creation_date'))}</td></tr>
      <tr><th>Expires</th><td>{esc(whois.get('expiration_date'))}</td></tr>
      <tr><th>Name Servers</th><td>{esc(', '.join(whois.get('name_servers') or []))}</td></tr>
      <tr><th>Country</th><td>{esc(whois.get('country'))}</td></tr>
      <tr><th>Organization</th><td>{esc(whois.get('organization'))}</td></tr>
      <tr><th>Domain Age (days)</th><td>{esc(whois.get('domain_age_days'))}</td></tr>
    </table>
  </div>

  <div class="section">
    <h2>IP / GeoIP</h2>
    <table>
      <tr><th>IPv4</th><td>{esc(self.result['ip_info'].get('ipv4'))}</td></tr>
      <tr><th>IPv6</th><td>{esc(self.result['ip_info'].get('ipv6'))}</td></tr>
      <tr><th>ASN</th><td>{esc(geo.get('asn'))}</td></tr>
      <tr><th>ISP</th><td>{esc(geo.get('isp'))}</td></tr>
      <tr><th>Country</th><td>{esc(geo.get('country'))}</td></tr>
      <tr><th>Region</th><td>{esc(geo.get('region'))}</td></tr>
      <tr><th>City</th><td>{esc(geo.get('city'))}</td></tr>
    </table>
  </div>

  <div class="section">
    <h2>Phishing Heuristics</h2>
    <table><tr><th>Flag</th><th>Description</th><th>Weight</th></tr>{flags_html}</table>
  </div>

  <div class="section">
    <h2>Reputation (VirusTotal)</h2>
    <table>
      <tr><th>Malicious</th><td>{esc(vt.get('malicious', 0))}</td></tr>
      <tr><th>Suspicious</th><td>{esc(vt.get('suspicious', 0))}</td></tr>
      <tr><th>Harmless</th><td>{esc(vt.get('harmless', 0))}</td></tr>
      <tr><th>Permalink</th><td>{esc(vt.get('permalink'))}</td></tr>
    </table>
  </div>
</body>
</html>"""

        path.write_text(html_doc, encoding="utf-8")
        return path
