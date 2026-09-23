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
def setup():
    """Install all required system dependencies (iptables, traceroute).

    Checks for and installs any missing system packages automatically.
    Run this once after installing netsieve.

    Example: sudo netsieve setup
    """
    import shutil
    import subprocess
    console.print(Text("\n  Checking system dependencies...\n", style="bold"))
    deps = {
        "iptables": "sudo apt install iptables -y",
        "traceroute": "sudo apt install traceroute -y",
    }
    for name, install_cmd in deps.items():
        if shutil.which(name):
            console.print(Text(f"  \u2713 {name} \u2014 already installed", style="green"))
        else:
            console.print(Text(f"  \u2717 {name} \u2014 installing...", style="yellow"))
            r = subprocess.run(install_cmd, shell=True)
            if r.returncode == 0:
                console.print(Text(f"  \u2713 {name} \u2014 installed", style="green"))
            else:
                console.print(Text(f"  \u2717 {name} \u2014 FAILED", style="red"))
    console.print(Text("\n  All dependencies ready.", style="bold green"))
    console.print()

@_cli.command()
@click.option("--interface", "-i", default=None, help="Network interface to listen on (e.g. eth0, wlan0). Default: auto-detect.")
@click.option("--duration", "-d", default=None, type=int, help="How long to capture, in seconds. Example: -d 30 captures for 30 seconds. Default: runs until Ctrl+C.")
@click.option("--output", "-o", default="~/captures", help="Folder where captured results are saved. Example: -o ~/my-captures")
def capture(interface, duration, output):
    """Passively capture network packets, decode payloads into plain text, and save them to files.

    Watches the network and logs every packet that passes through.
    Each conversation (flow) is saved as a .txt file in the output folder.
    Payloads are decoded so you can read them without Wireshark.

    Example: sudo netsieve capture -i eth0 -d 60
    """
    from netsieve.capture import NetSieve
    ns = NetSieve(interface=interface, output_dir=output)
    ns.run(duration=duration)

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

    Example: sudo netsieve detect -d 30
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
    console.print(f"[green]\u2713 Report saved: {path}[/]")

@_cli.command()
@click.argument("ip")
def block(ip):
    """Block an IP address — all traffic from it will be dropped.

    Adds the IP to your firewall (iptables). The attacker can no longer
    reach this machine. The block persists in ~/.netsieve_blocked.json
    and can be restored after reboot with 'netsieve restore'.

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
    """Show all currently blocked IP addresses.

    Reads ~/.netsieve_blocked.json and prints the list.

    Example: netsieve list
    """
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
