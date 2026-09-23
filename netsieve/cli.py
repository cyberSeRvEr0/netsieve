import click
import textwrap
from rich.console import Console
from rich.text import Text

console = Console()

def show_banner():
    BANNER = textwrap.dedent(r"""
        _   __ ______ ______ _____  ____ ______ _    __ ______
       / | / // ____//_  __// ___//  _// ____// |  / // ____/
      /  |/ // __/    / /   \__ \ / / / __/   | | / // __/
     / /|  // /___   / /   ___/ // / / /___   | |/ // /___
    /_/ |_//_____/  /_/   /____//___//_____/  |___//_____/
    """).strip()

    console.print(Text(BANNER, style="bold cyan"))
    console.print(Text("  Passive network capture | Payload decode | Attacker trace", style="dim"))
    console.print()   

@click.group()
@click.version_option()
def _cli():
    """NetSieve — Passive network capture, payload decoding, and attacker tracing."""
    pass

@_cli.command()
@click.option("--interface", "-i", default=None, help="Network interface to listen on (e.g. eth0, wlan0). Default: auto-detect.")
@click.option("--duration", "-d", default=None, type=int, help="How long to capture, in seconds. Example: -d 30 captures for 30 seconds. Default: runs until Ctrl+C.")
@click.option("--output", "-o", default="~/captures", help="Folder where captured results are saved. Example: -o ~/my-captures")
def capture(interface, duration, output):
    """Passively capture network packets, decode payloads into plain text, and save them to files.

    Watches the network and logs every packet that passes through.
    Each conversation (flow) is saved as a .txt file in the output folder.
    Payloads are decoded so you can read them without Wireshark.
    """
    console.print(f"[bold cyan]NetSieve[/] — capturing on {interface or 'auto'} for {duration or '∞'}s")
    console.print(f"[dim]Output: {output} | Ctrl+C to stop[/]")

@_cli.command()
@click.option("--interface", "-i", default=None, help="Network interface to watch (e.g. eth0, wlan0). Default: auto-detect.")
@click.option("--duration", "-d", default=None, type=int, help="How long to watch, in seconds. Example: -d 60 watches for 60 seconds. Default: runs until Ctrl+C.")
def detect(interface, duration):
    """Watch the network in real-time and print an alert the moment an attack pattern is detected.

    Scans every incoming packet for known threat signatures:
    SQL injection, XSS, path traversal, command injection, SSRF.
    When a match is found, it prints the attacker IP, the threat type,
    and a snippet of the malicious data. At the end it lists all
    attacking IPs so you can trace them.
    """
    from netsieve.detect import run_detect
    run_detect(interface=interface, duration=duration)

@_cli.command()
@click.argument("ip")
def trace(ip):
    """Trace an IP address — reverse DNS, GeoIP, threat intel, and network route.

    Takes an IP address and looks up:
    - Reverse DNS (what hostname it resolves to)
    - GeoIP (country, city, ISP, organization)
    - Threat intelligence (AbuseIPDB abuse score and report count)
    - Traceroute (the network path from you to that IP)

    Example: netsieve trace 203.0.113.44
    """
    from netsieve.trace import trace_ip
    trace_ip(ip)

@_cli.command()
@click.argument("ip")
@click.option("--output", "-o", default=None, help="File to save the report to. Example: -o evidence.txt. Default: netsieve_report_<ip>.txt")
def report(ip, output):
    """Generate a forensic report file for an IP address.

    Creates a plain-text report containing:
    - IP identification (reverse DNS, GeoIP, ISP)
    - Threat intelligence (AbuseIPDB score)
    - Network route (traceroute)
    - Recommendations for the security team

    The file is ready to share with a security team or law enforcement.

    Example: netsieve report 203.0.113.44 -o evidence.txt
    """
    from netsieve.report import generate_report
    path = generate_report(ip, output=output)
    console.print(f"[green]✓ Report saved: {path}[/]")

@_cli.command()
@click.argument("ip")
def block(ip):
    """Block an IP address — all traffic from it will be dropped.

    Adds the IP to your firewall (iptables). The attacker can no longer
    reach this machine. The block persists in ~/.netsieve_blocked.json
    and is restored automatically on next run.

    Example: sudo netsieve block 203.0.113.44
    """
    from netsieve.block import block_ip
    block_ip(ip)

@_cli.command()
@click.argument("ip")
def unblock(ip):
    """Unblock a previously blocked IP address.

    Removes the IP from your firewall and the blocklist.

    Example: sudo netsieve unblock 203.0.113.44
    """
    from netsieve.block import unblock_ip
    unblock_ip(ip)

@_cli.command(name="list")
def list_blocked():
    """Show all currently blocked IP addresses."""
    from netsieve.block import list_blocked as _list
    _list()

@_cli.command()
def restore():
    """Restore all blocked IPs from the blocklist (useful after reboot).

    Reads ~/.netsieve_blocked.json and re-applies all blocks to iptables.
    Run this after a reboot to re-apply your blocks.

    Example: sudo netsieve restore
    """
    from netsieve.block import restore_blocked
    restore_blocked()   
    
def main():
    show_banner()
    _cli()

if __name__ == "__main__":
    main()   
