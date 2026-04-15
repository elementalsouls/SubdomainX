"""
SubdomainX - Main orchestrator and CLI.
Coordinates passive, active, and resolution phases.
"""

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Set, Dict, Optional

import aiohttp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.text import Text
from rich import box

from . import __version__
from .passive import FREE_SOURCES, API_SOURCES
from .active import WildcardDetector, ZoneTransfer, DNSBruteForcer, PermutationScanner, RecursiveEnumerator
from .resolver import SubdomainResolver, SubdomainInfo

console = Console()

BANNER = r"""
   ___       _       _                       _       __  __
  / __\_   _| |__   | |__   ___  _ __ ___   (_)_ __ \ \/ /
 /__\// | | | '_ \  | '_ \ / _ \| '_ ` _ \ | | '_ \ \  /
/ \/  \ |_| | |_) | | | | | (_) | | | | | || | | | |/  \
\_____/\__,_|_.__/  |_| |_|\___/|_| |_| |_|/ |_| |_/_/\_\
                                          |__/
      SubdomainX v{version} — Comprehensive Subdomain Enumeration
"""

DEFAULT_WORDLIST = Path(__file__).parent.parent / "wordlists" / "subdomains.txt"


class SubdomainX:
    """Main orchestrator for subdomain enumeration."""

    def __init__(self, config: argparse.Namespace):
        self.domain = config.domain.lower().strip().lstrip("*.")
        self.config = config
        self.all_subdomains: Set[str] = set()
        self.resolved_info: Dict[str, SubdomainInfo] = {}
        self.source_counts: Dict[str, int] = {}
        self.start_time = 0.0

    async def run(self):
        """Execute the full enumeration pipeline."""
        self.start_time = time.time()

        console.print(BANNER.format(version=__version__), style="bold cyan")
        console.print(Panel(
            f"[bold white]Target:[/] [green]{self.domain}[/]\n"
            f"[bold white]Threads:[/] [green]{self.config.concurrency}[/]\n"
            f"[bold white]Brute Force:[/] [green]{'Enabled' if not self.config.no_bruteforce else 'Disabled'}[/]\n"
            f"[bold white]Permutations:[/] [green]{'Enabled' if self.config.permutations else 'Disabled'}[/]\n"
            f"[bold white]Recursive:[/] [green]{'Enabled' if self.config.recursive else 'Disabled'}[/]\n"
            f"[bold white]HTTP Probe:[/] [green]{'Enabled' if self.config.probe else 'Disabled'}[/]\n"
            f"[bold white]Takeover Check:[/] [green]{'Enabled' if self.config.probe else 'Disabled'}[/]\n"
            f"[bold white]Mode:[/] [green]{'DEEP' if getattr(self.config, 'deep', False) else 'Standard'}[/]",
            title="[bold]Configuration[/]",
            border_style="blue"
        ))

        # Phase 1: Passive Enumeration
        await self._passive_phase()

        # Phase 2: Zone Transfer
        await self._zone_transfer_phase()

        # Phase 3: DNS Brute Force
        if not self.config.no_bruteforce:
            await self._bruteforce_phase()

        # Phase 4: Permutation Scanning
        if self.config.permutations:
            await self._permutation_phase()

        # Phase 5: Recursive Enumeration
        if self.config.recursive:
            await self._recursive_phase()

        # Phase 6: Resolve & Probe
        if self.config.probe:
            await self._resolve_phase()

        # Results
        self._print_results()

        # Save output
        if self.config.output:
            self._save_results()

        elapsed = time.time() - self.start_time
        console.print(f"\n[bold green]✓ Completed in {elapsed:.1f}s — {len(self.all_subdomains)} unique subdomains found[/]")

    async def _passive_phase(self):
        """Run all passive enumeration sources concurrently."""
        console.print("\n[bold yellow]▶ Phase 1: Passive Enumeration[/]")

        api_keys = self._load_api_keys()
        resolver = aiohttp.resolver.ThreadedResolver()
        connector = aiohttp.TCPConnector(limit=50, ssl=False, resolver=resolver)

        async with aiohttp.ClientSession(connector=connector) as session:
            # Create source instances
            sources = []
            for SourceClass in FREE_SOURCES:
                sources.append(SourceClass(self.domain, session))

            # Add API sources if keys available
            for name, SourceClass in API_SOURCES.items():
                key = api_keys.get(name)
                if key:
                    if name == "censys":
                        parts = key.split(":")
                        if len(parts) == 2:
                            sources.append(SourceClass(self.domain, session, api_id=parts[0], api_secret=parts[1]))
                    else:
                        sources.append(SourceClass(self.domain, session, api_key=key))

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Querying {len(sources)} sources...", total=len(sources)
                )

                # Run all sources concurrently
                async def run_source(source):
                    try:
                        results = await source.enumerate()
                        count = len(results)
                        self.source_counts[source.name] = count
                        self.all_subdomains.update(results)
                        if count > 0:
                            progress.console.print(
                                f"  [green]✓[/] {source.name}: [bold]{count}[/] subdomains"
                            )
                        else:
                            err = getattr(source, '_last_error', None)
                            if err:
                                progress.console.print(
                                    f"  [red]✗ {source.name}: {err[:80]}[/]"
                                )
                            else:
                                progress.console.print(
                                    f"  [dim]○ {source.name}: 0 subdomains[/]"
                                )
                    except Exception as e:
                        progress.console.print(
                            f"  [red]✗ {source.name}: {type(e).__name__}: {str(e)[:60]}[/]"
                        )
                    finally:
                        progress.advance(task)

                await asyncio.gather(*[run_source(s) for s in sources])

        console.print(f"  [bold]→ Passive total: {len(self.all_subdomains)} unique subdomains[/]")

    async def _zone_transfer_phase(self):
        """Attempt DNS zone transfers."""
        console.print("\n[bold yellow]▶ Phase 2: Zone Transfer[/]")
        zt = ZoneTransfer(self.domain)
        try:
            results = await zt.enumerate()
            if results:
                self.all_subdomains.update(results)
                console.print(f"  [green]✓ Zone transfer found {len(results)} subdomains![/]")
            else:
                console.print("  [dim]○ Zone transfer not allowed (expected)[/]")
        except Exception:
            console.print("  [dim]○ Zone transfer failed (expected)[/]")

    async def _bruteforce_phase(self):
        """DNS brute force with wordlist."""
        console.print("\n[bold yellow]▶ Phase 3: DNS Brute Force[/]")

        wordlist = self.config.wordlist or str(DEFAULT_WORDLIST)
        if not Path(wordlist).exists():
            console.print(f"  [red]✗ Wordlist not found: {wordlist}[/]")
            return

        # Count words
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            word_count = sum(1 for line in f if line.strip() and not line.startswith("#"))

        console.print(f"  [dim]Using wordlist: {wordlist} ({word_count:,} words)[/]")

        # Wildcard detection
        console.print("  [dim]Checking for wildcard DNS...[/]")
        wc = WildcardDetector(self.domain)
        has_wildcard, wc_ips = await wc.detect()
        if has_wildcard:
            console.print(f"  [yellow]⚠ Wildcard detected: {', '.join(wc_ips)} — filtering enabled[/]")
        else:
            console.print("  [dim]○ No wildcard DNS detected[/]")

        found_count = [0]
        total_checked = [0]

        def on_found(sub):
            found_count[0] += 1

        bruter = DNSBruteForcer(
            self.domain, wordlist, wc,
            concurrency=self.config.concurrency,
            callback=on_found
        )

        # Load words to track progress
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            total_words = sum(1 for line in f if line.strip() and not line.startswith("#"))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[green]{task.fields[found]}[/] found"),
            console=console,
            refresh_per_second=4,
        ) as progress:
            task = progress.add_task(
                "[cyan]Brute forcing...", total=total_words, found=0
            )

            # Override callback to update progress live
            original_brute = bruter.brute_force

            async def brute_with_progress():
                words = bruter._load_wordlist()
                if not words:
                    return bruter.results
                semaphore = asyncio.Semaphore(bruter.concurrency)
                batch_size = 500
                for i in range(0, len(words), batch_size):
                    batch_words = words[i : i + batch_size]
                    tasks_batch = [bruter._resolve_one(w, semaphore) for w in batch_words]
                    results = await asyncio.gather(*tasks_batch, return_exceptions=True)
                    for result in results:
                        if isinstance(result, str) and result:
                            bruter.results.add(result)
                            console.print(f"    [green]+[/] {result}")
                    progress.update(task, advance=len(batch_words), found=len(bruter.results))
                return bruter.results

            results = await brute_with_progress()

        before = len(self.all_subdomains)
        self.all_subdomains.update(results)
        new = len(self.all_subdomains) - before
        console.print(f"  [bold]→ Brute force: {len(results)} resolved, {new} new unique[/]")

    async def _permutation_phase(self):
        """Permutation / alteration scanning."""
        console.print("\n[bold yellow]▶ Phase 4: Permutation Scanning[/]")

        wc = WildcardDetector(self.domain)
        await wc.detect()

        scanner = PermutationScanner(
            self.domain, self.all_subdomains.copy(), wc,
            concurrency=self.config.concurrency
        )

        perms = scanner._generate_permutations()
        console.print(f"  [dim]Generated {len(perms):,} permutations from {len(self.all_subdomains)} discovered subdomains[/]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[green]{task.fields[found]}[/] found"),
            console=console,
            refresh_per_second=4,
        ) as progress:
            task = progress.add_task(
                "[cyan]Scanning permutations...", total=len(perms), found=0
            )

            perm_list = list(perms)
            semaphore = asyncio.Semaphore(scanner.concurrency)
            batch_size = 500
            for i in range(0, len(perm_list), batch_size):
                batch = perm_list[i : i + batch_size]
                tasks_batch = [scanner._resolve_one(p, semaphore) for p in batch]
                results_batch = await asyncio.gather(*tasks_batch, return_exceptions=True)
                for result in results_batch:
                    if isinstance(result, str) and result:
                        scanner.results.add(result)
                        console.print(f"    [green]+[/] {result}")
                progress.update(task, advance=len(batch), found=len(scanner.results))

            results = scanner.results

        before = len(self.all_subdomains)
        self.all_subdomains.update(results)
        new = len(self.all_subdomains) - before
        console.print(f"  [bold]→ Permutations: {len(results)} resolved, {new} new unique[/]")

    async def _recursive_phase(self):
        """Recursive subdomain enumeration."""
        console.print("\n[bold yellow]▶ Phase 5: Recursive Enumeration[/]")

        wordlist = self.config.wordlist or str(DEFAULT_WORDLIST)
        wc = WildcardDetector(self.domain)
        await wc.detect()

        recursive = RecursiveEnumerator(
            self.domain, self.all_subdomains.copy(), wordlist, wc,
            concurrency=self.config.concurrency,
            max_depth=self.config.recursive_depth,
        )

        # Identify candidates for recursive enumeration
        candidates = set()
        for sub in self.all_subdomains:
            prefix = sub.replace(f".{self.domain}", "")
            parts = prefix.split(".")
            if len(parts) == 1 and parts[0]:
                candidates.add(sub)

        small_words = recursive._load_small_wordlist()
        total_checks = len(candidates) * len(small_words)
        console.print(f"  [dim]Recursing into {len(candidates)} subdomains × {len(small_words)} words = {total_checks:,} checks[/]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[green]{task.fields[found]}[/] found"),
            console=console,
            refresh_per_second=4,
        ) as progress:
            task = progress.add_task(
                "[cyan]Recursive enumeration...", total=total_checks, found=0
            )

            for base_sub in candidates:
                sub_wc = WildcardDetector(base_sub)
                await sub_wc.detect()

                semaphore = asyncio.Semaphore(recursive.concurrency)
                batch_size = 200
                for i in range(0, len(small_words), batch_size):
                    batch = small_words[i : i + batch_size]
                    tasks_batch = [recursive._resolve(f"{w}.{base_sub}", sub_wc, semaphore) for w in batch]
                    results_batch = await asyncio.gather(*tasks_batch, return_exceptions=True)
                    for result in results_batch:
                        if isinstance(result, str) and result:
                            recursive.results.add(result)
                            console.print(f"    [green]+[/] {result}")
                    progress.update(task, advance=len(batch), found=len(recursive.results))

            results = recursive.results

        before = len(self.all_subdomains)
        self.all_subdomains.update(results)
        new = len(self.all_subdomains) - before
        console.print(f"  [bold]→ Recursive: {len(results)} resolved, {new} new unique[/]")

    async def _resolve_phase(self):
        """Resolve all found subdomains and probe HTTP."""
        console.print("\n[bold yellow]▶ Phase 6: DNS Resolution & HTTP Probing[/]")

        resolver = SubdomainResolver(
            concurrency=min(self.config.concurrency, 100),
            check_http=self.config.probe,
            check_takeover=True
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Resolving {len(self.all_subdomains)} subdomains...",
                total=len(self.all_subdomains)
            )

            # Resolve in batches to show progress
            subs_list = list(self.all_subdomains)
            batch_size = 50
            for i in range(0, len(subs_list), batch_size):
                batch = set(subs_list[i : i + batch_size])
                results = await resolver.resolve_all(batch)
                self.resolved_info.update(results)
                progress.advance(task, len(batch))

        alive = sum(1 for info in self.resolved_info.values() if info.is_alive)
        takeovers = sum(1 for info in self.resolved_info.values() if info.takeover_vulnerable)
        console.print(f"  [bold]→ {alive} alive hosts out of {len(self.all_subdomains)} subdomains[/]")
        if takeovers:
            console.print(f"  [bold red]⚠ {takeovers} potential subdomain takeover(s) detected![/]")

    def _print_results(self):
        """Print final results."""
        console.print(f"\n{'─' * 70}")
        console.print(Panel(
            f"[bold green]{len(self.all_subdomains)}[/bold green] unique subdomains found for [bold]{self.domain}[/bold]",
            title="[bold]Results[/]",
            border_style="green"
        ))

        # Source breakdown
        if self.source_counts:
            table = Table(title="Source Breakdown", box=box.SIMPLE)
            table.add_column("Source", style="cyan")
            table.add_column("Count", style="green", justify="right")
            for source, count in sorted(self.source_counts.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    table.add_row(source, str(count))
            console.print(table)

        # Detailed results if resolved
        if self.resolved_info:
            # Takeover alerts first
            takeover_subs = {sub: info for sub, info in self.resolved_info.items() if info.takeover_vulnerable}
            if takeover_subs:
                console.print()
                console.print(Panel(
                    "[bold red]SUBDOMAIN TAKEOVER CANDIDATES[/]",
                    border_style="red"
                ))
                for sub in sorted(takeover_subs.keys()):
                    info = takeover_subs[sub]
                    console.print(f"  [bold red]⚠ {info.subdomain}[/] → CNAME: {', '.join(info.cnames)} → [yellow]{info.takeover_service}[/]")

            table = Table(title="Resolved Subdomains", box=box.SIMPLE, show_lines=False)
            table.add_column("Subdomain", style="cyan", no_wrap=True)
            table.add_column("IPs", style="white")
            table.add_column("Status", style="yellow")
            table.add_column("Tech", style="magenta", max_width=20)
            table.add_column("Title", style="dim", max_width=35)

            for sub in sorted(self.resolved_info.keys()):
                info = self.resolved_info[sub]
                if info.is_alive:
                    style = "bold red" if info.takeover_vulnerable else None
                    table.add_row(
                        ("⚠ " if info.takeover_vulnerable else "") + info.subdomain,
                        ", ".join(info.ips[:3]) if info.ips else (", ".join(info.cnames[:2]) if info.cnames else ""),
                        info.status_str,
                        ", ".join(info.technologies[:3]) if info.technologies else "",
                        info.title or "",
                        style=style,
                    )
            console.print(table)
        else:
            # Just print the list
            for sub in sorted(self.all_subdomains):
                console.print(f"  {sub}")

    def _save_results(self):
        """Save results to file."""
        output_path = self.config.output
        ext = Path(output_path).suffix.lower()

        if ext == ".json":
            data = {
                "domain": self.domain,
                "total": len(self.all_subdomains),
                "subdomains": sorted(self.all_subdomains),
                "sources": self.source_counts,
            }
            if self.resolved_info:
                data["resolved"] = {
                    sub: {
                        "ips": info.ips,
                        "ipv6s": info.ipv6s,
                        "cnames": info.cnames,
                        "http_status": info.http_status,
                        "https_status": info.https_status,
                        "title": info.title,
                        "server": info.http_server,
                        "technologies": info.technologies,
                        "takeover_vulnerable": info.takeover_vulnerable,
                        "takeover_service": info.takeover_service,
                        "alive": info.is_alive,
                    }
                    for sub, info in sorted(self.resolved_info.items())
                }
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)

        elif ext == ".csv":
            import csv
            with open(output_path, "w", newline="") as f:
                writer = csv.writer(f)
                if self.resolved_info:
                    writer.writerow(["Subdomain", "IPs", "IPv6s", "CNAMEs", "HTTP", "HTTPS", "Title", "Server", "Technologies", "Takeover", "TakeoverService", "Alive"])
                    for sub in sorted(self.resolved_info.keys()):
                        info = self.resolved_info[sub]
                        writer.writerow([
                            info.subdomain,
                            "|".join(info.ips),
                            "|".join(info.ipv6s),
                            "|".join(info.cnames),
                            info.http_status or "",
                            info.https_status or "",
                            info.title or "",
                            info.http_server or "",
                            "|".join(info.technologies),
                            info.takeover_vulnerable,
                            info.takeover_service or "",
                            info.is_alive,
                        ])
                else:
                    writer.writerow(["Subdomain"])
                    for sub in sorted(self.all_subdomains):
                        writer.writerow([sub])
        else:
            # Plain text
            with open(output_path, "w") as f:
                for sub in sorted(self.all_subdomains):
                    f.write(sub + "\n")

        console.print(f"\n[bold green]✓ Results saved to {output_path}[/]")

    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from config file or environment variables."""
        keys = {}
        # Check environment variables
        env_map = {
            "virustotal": "VIRUSTOTAL_API_KEY",
            "securitytrails": "SECURITYTRAILS_API_KEY",
            "shodan": "SHODAN_API_KEY",
            "censys": "CENSYS_API_KEY",  # format: id:secret
            "binaryedge": "BINARYEDGE_API_KEY",
            "chaos": "CHAOS_API_KEY",
            "bevigil": "BEVIGIL_API_KEY",
            "whoisxmlapi": "WHOISXMLAPI_KEY",
            "zoomeye": "ZOOMEYE_API_KEY",
        }
        for source, env_var in env_map.items():
            val = os.environ.get(env_var, "")
            if val:
                keys[source] = val

        # Check config file
        config_path = Path.home() / ".subdomainx" / "config.json"
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = json.load(f)
                    for source, key in config.get("api_keys", {}).items():
                        if key and source not in keys:
                            keys[source] = key
            except Exception:
                pass

        if keys:
            console.print(f"  [dim]Loaded API keys: {', '.join(keys.keys())}[/]")

        return keys


def main():
    parser = argparse.ArgumentParser(
        prog="subdomainx",
        description="SubdomainX — Comprehensive Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m subdomainx example.com
  python -m subdomainx example.com -o results.txt
  python -m subdomainx example.com --probe --permutations --recursive -o results.json
  python -m subdomainx example.com --deep -o results.json
  python -m subdomainx example.com --no-bruteforce --probe -o results.csv
  python -m subdomainx example.com -w custom_wordlist.txt -t 1000

API Keys (set via environment variables or ~/.subdomainx/config.json):
  VIRUSTOTAL_API_KEY, SECURITYTRAILS_API_KEY, SHODAN_API_KEY,
  CENSYS_API_KEY (format: id:secret), BINARYEDGE_API_KEY, CHAOS_API_KEY,
  BEVIGIL_API_KEY, WHOISXMLAPI_KEY, ZOOMEYE_API_KEY
        """,
    )

    parser.add_argument("domain", help="Target domain to enumerate subdomains for")
    parser.add_argument("-o", "--output", help="Output file path (.txt, .json, or .csv)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist for brute forcing")
    parser.add_argument("-t", "--concurrency", type=int, default=500,
                        help="Concurrent DNS queries (default: 500)")
    parser.add_argument("--no-bruteforce", action="store_true",
                        help="Skip DNS brute forcing (passive only)")
    parser.add_argument("--permutations", action="store_true",
                        help="Enable permutation/alteration scanning")
    parser.add_argument("--recursive", action="store_true",
                        help="Enable recursive subdomain enumeration")
    parser.add_argument("--recursive-depth", type=int, default=2,
                        help="Recursion depth (default: 2)")
    parser.add_argument("--probe", action="store_true",
                        help="Probe HTTP/HTTPS and resolve DNS for all results")
    parser.add_argument("--all", action="store_true",
                        help="Enable all techniques (permutations + recursive + probe)")
    parser.add_argument("--deep", action="store_true",
                        help="Deep mode: all techniques + higher concurrency + expanded sources")
    parser.add_argument("-v", "--version", action="version",
                        version=f"SubdomainX {__version__}")

    args = parser.parse_args()

    # --all enables everything
    if args.all:
        args.permutations = True
        args.recursive = True
        args.probe = True

    # --deep enables everything + cranks up settings
    if args.deep:
        args.permutations = True
        args.recursive = True
        args.probe = True
        args.recursive_depth = max(args.recursive_depth, 3)
        if args.concurrency == 500:  # Only override if user didn't set it
            args.concurrency = 1000

    # Validate domain
    domain = args.domain.lower().strip()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).hostname or domain
    domain = domain.lstrip("*.")
    args.domain = domain

    # Run
    tool = SubdomainX(args)

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(tool.run())


if __name__ == "__main__":
    main()
