import click
import os
import json
import textwrap
from rich.console import Console
from rich.text import Text
from netsieve import __version__   

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
@click.version_option(version=__version__, prog_name="netsieve")
def _cli():
    """NetSieve — Passive network capture, payload decoding, and attacker tracing."""
    pass   

@_cli.command()
def setup():
    """Install required system dependencies (iptables and traceroute).

    Checks for and installs any missing system packages automatically.
    Run this once after installing netsieve.

    Example: sudo netsieve setup
    """
    import shutil
    import subprocess
    from netsieve.config import DEFAULTS, _config_path
    console.print(Text("\n  Checking system dependencies...\n", style="bold"))

    failed = []
    package_manager = shutil.which("apt-get")
    for name in ("iptables", "traceroute"):
        if shutil.which(name):
            console.print(Text(f"  \u2713 {name} \u2014 already installed", style="green"))
        else:
            if not package_manager:
                console.print(Text(f"  \u2717 {name} \u2014 apt-get is unavailable", style="red"))
                failed.append(name)
                continue
            console.print(Text(f"  Installing {name}...", style="yellow"))
            command = [package_manager, "install", "-y", name]
            if os.geteuid() != 0:
                command.insert(0, "sudo")
                command.insert(1, "-A")
            r = subprocess.run(command, check=False)
            if r.returncode == 0 and shutil.which(name):
                console.print(Text(f"  \u2713 {name} \u2014 installed", style="green"))
            else:
                console.print(Text(f"  \u2717 {name} \u2014 FAILED", style="red"))
                failed.append(name)

    # Create symlink so 'sudo netsieve' works
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        user_home = pwd.getpwnam(sudo_user).pw_dir
    else:
        user_home = os.path.expanduser("~")

    netsieve_bin = os.path.join(user_home, ".local", "bin", "netsieve")
    link_path = "/usr/local/bin/netsieve"
    if os.path.exists(netsieve_bin) and not os.path.lexists(link_path):
        try:
            subprocess.run(["ln", "-s", netsieve_bin, link_path], capture_output=True, text=True, check=True)
            console.print(Text(f"  \u2713 symlinked to {link_path} (sudo now works)", style="green"))
        except (OSError, subprocess.CalledProcessError) as error:
            detail = getattr(error, "stderr", None) or str(error)
            failed.append(f"netsieve symlink: {detail.strip()}")

    # Auto-create config file with defaults if it doesn't exist
    config_path = _config_path()
    if not config_path.exists():
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(DEFAULTS, indent=2))
        console.print(Text(f"  \u2713 config created: {config_path}", style="green"))
        console.print(Text(f"    Edit it to change defaults (webhook, auto_block, etc.)", style="dim"))
    else:
        console.print(Text(f"  \u2713 config exists: {config_path}", style="green"))   
    if failed:
        raise click.ClickException(f"Setup incomplete: {'; '.join(failed)}")
    console.print(Text("\n  All dependencies ready.", style="bold green"))
    console.print()   

@_cli.command()   
@click.option("--interface", "-i", default=None, help="Network interface (e.g. eth0, wlan0). Default: auto.")
@click.option("--duration", "-d", default=None, type=click.IntRange(min=1), help="Seconds to capture. Default: runs until Ctrl+C.")
@click.option("--output", "-o", default=None, help="Folder to save .txt files. Default: config or ~/captures/")
@click.option("--min-payload-size", type=click.IntRange(min=0), default=None, help="Minimum payload size in bytes.")
@click.option("--save-pcap/--no-save-pcap", default=None, help="Save raw PCAP files (default: config setting).")
def capture(interface, duration, output, min_payload_size, save_pcap):
    """Capture all network traffic, decode payloads, save as readable .txt files.

    Each directional TCP/UDP flow (including source and destination ports)
    is saved as a separate file.
    Files are organized by date: ~/captures/2026-09-24/

    After it finishes, check results:
      ls ~/captures/2026-09-24/
      cat ~/captures/2026-09-24/*_TCP.txt

    Examples:
      sudo netsieve capture -d 30              Capture for 30 seconds
      sudo netsieve capture -i eth0 -d 60      Capture on eth0 for 60 seconds
      sudo netsieve capture -o ~/evidence/     Save to a custom folder
    """
    from netsieve.capture import NetSieve
    from netsieve.config import load_config
    config = load_config()
    ns = NetSieve(
        interface=interface if interface is not None else config["interface"],
        output_dir=output if output is not None else config["output_dir"],
        min_payload_size=(
            min_payload_size if min_payload_size is not None else config["min_payload_size"]
        ),
        save_pcap=save_pcap if save_pcap is not None else config["save_pcap"],
        save_protocols=config["save_protocols"],
    )
    ns.run(duration=duration)

@_cli.command()
@click.option("--interface", "-i", default=None, help="Network interface to watch. Default: auto.")
@click.option("--duration", "-d", type=click.IntRange(min=1), default=None, help="Seconds to watch.")
@click.option("--webhook", "-w", default=None, help="Webhook URL for alerts.")
@click.option("--auto-block/--no-auto-block", default=None, help="Enable or disable auto-blocking.")
@click.option("--threshold", default=None, type=click.IntRange(min=1), help="Alert count before auto-block.")
def detect(interface, duration, webhook, auto_block, threshold):
    """Watch for incoming attacks in real-time. Print alert + send notification.

    Scans every packet for: SQL injection, XSS, path traversal,
    command injection, SSRF. When found, prints the attacker IP and
    threat type to the terminal. If -w is set, also sends a push
    notification to your phone.

    Typical workflow:
      1. sudo netsieve detect -d 30          Watch for 30s
         → [ALERT] From: 203.0.113.44  Threat: SQL injection
      2. netsieve trace 203.0.113.44         Identify the attacker
      3. sudo netsieve block 203.0.113.44    Cut them off

    Run forever in background (no terminal needed):
      sudo netsieve service -w "https://ntfy.sh/your-topic"

    Examples:
      sudo netsieve detect                   Watch until Ctrl+C
      sudo netsieve detect -d 60             Watch for 60 seconds
      sudo netsieve detect -w "https://ntfy.sh/my-app"   + phone alerts
      sudo netsieve detect --auto-block --threshold 3    Auto-block after 3 alerts
    """
    from netsieve.detect import run_detect
    run_detect(interface=interface, duration=duration, webhook_url=webhook,
               auto_block=auto_block, auto_block_threshold=threshold)    

@_cli.command()
@click.argument("ip")
def trace(ip):
    """Identify an IP — reverse DNS, GeoIP, threat intel, network route.

    Tells you WHO the attacker is:
      - Reverse DNS (hostname)
      - Country, city, ISP, organization
      - Abuse score (0-100) from AbuseIPDB
      - Full network route (traceroute)

    After tracing, next steps:
      netsieve report <ip>       Save forensic evidence
      sudo netsieve block <ip>   Cut them off

    Examples:
      netsieve trace 203.0.113.44
      netsieve trace 8.8.8.8
    """
    from netsieve.trace import trace_ip
    trace_ip(ip)

@_cli.command()
@click.argument("ip")
@click.option("--shodan-key", default=None, help="Shodan API key for deep lookup")
def identify(ip, shodan_key):
    """Deep IP identification: ASN, VPN/Tor detection, Shodan, passive DNS, WHOIS.

    Goes beyond basic trace to determine if the attacker is hiding
    behind a VPN, proxy, or Tor exit node.

    Examples:
      netsieve identify 185.220.101.1
      netsieve identify 203.0.113.44 --shodan-key YOUR_KEY
    """
    from netsieve.identify import identify_ip
    from netsieve.config import load_config
    config = load_config()
    identify_ip(ip, shodan_key=shodan_key if shodan_key is not None else config["shodan_key"])

@_cli.command()
@click.argument("ip")
@click.option("--output", "-o", default=None, help="File to save report to. Default: netsieve_report_<ip>.txt")
def report(ip, output):
    """Generate a forensic report file for an IP.

    Creates a plain-text file with:
      - IP identification (DNS, GeoIP, ISP)
      - Threat intelligence (AbuseIPDB score)
      - Network route (traceroute)
      - Recommendations for security team / law enforcement

    The file is ready to share with a CISO, SOC team, or LE.

    After generating, check it:
      cat netsieve_report_203.0.113.44.txt

    Examples:
      netsieve report 203.0.113.44
      netsieve report 203.0.113.44 -o evidence_2026.txt
    """
    from netsieve.report import generate_report
    path = generate_report(ip, output=output)
    console.print(f"[green]\u2713 Report saved: {path}[/]")

@_cli.command()
@click.argument("ip")
def block(ip):
    """Block an IP — all traffic from it is dropped immediately.

    Adds the IP to iptables (INPUT chain, DROP). The attacker
    can no longer reach this machine. The block is saved to
    ~/.netsieve_blocked.json so it survives reboots.

    After blocking, verify:
      netsieve list                    See all blocked IPs
      cat ~/.netsieve_blocked.json     Raw blocklist

    After a reboot, re-apply:
      sudo netsieve restore

    To remove the block later:
      sudo netsieve unblock <ip>

    Examples:
      sudo netsieve block 203.0.113.44
    """
    from netsieve.block import block_ip
    if not block_ip(ip):
        raise click.ClickException(f"Failed to block {ip}.")

@_cli.command()
@click.argument("ip")
def unblock(ip):
    """Remove a blocked IP — traffic from it is allowed again.

    Removes the IP from iptables and from ~/.netsieve_blocked.json.

    Before unblocking, check who's blocked:
      netsieve list

    Examples:
      sudo netsieve unblock 203.0.113.44
    """
    from netsieve.block import unblock_ip
    if not unblock_ip(ip):
        raise click.ClickException(f"Failed to unblock {ip}.")

@_cli.command(name="list")
def list_blocked():
    """Show all currently blocked IPs.

    Reads ~/.netsieve_blocked.json and prints the list.
    No sudo needed.

    If you want to unblock one:
      sudo netsieve unblock <ip>

    If you want to clear all:
      sudo netsieve unblock <ip>   (repeat for each)

    Example:
      netsieve list
    """
    from netsieve.block import list_blocked as _list
    _list()

@_cli.command()
def restore():
    """Re-apply all blocked IPs after a reboot.

    iptables rules are lost when the machine reboots. This command
    reads ~/.netsieve_blocked.json and re-adds all rules to iptables.

    Run this after every reboot:
      sudo netsieve restore

    Or set it to auto-run via the service:
      sudo netsieve service

    Example:
      sudo netsieve restore
    """
    from netsieve.block import restore_blocked
    if not restore_blocked():
        raise click.ClickException("One or more block rules could not be restored.")

@_cli.command()
@click.option("--webhook", "-w", default=None, help="Webhook URL for phone alerts")
@click.option("--interface", "-i", default=None, help="Network interface")
def service(webhook, interface):
    """Install NetSieve as a background service (runs forever, survives reboot).

    After running this, detect runs in the background 24/7.
    You don't need to keep a terminal open.

    Manage it with:
      sudo systemctl start netsieve       Start watching
      sudo systemctl stop netsieve        Stop watching
      sudo systemctl status netsieve      Check if running
      sudo systemctl restart netsieve     Restart (after config change)
      sudo systemctl enable netsieve      Auto-start on boot (default)
      sudo systemctl disable netsieve     Don't auto-start on boot
      journalctl -u netsieve -f           Watch live logs in terminal
      journalctl -u netsieve --since today  See today's logs

    To remove the service completely:
      sudo netsieve service-remove

    Examples:
      sudo netsieve service
      sudo netsieve service -w "https://ntfy.sh/my-topic"
      sudo netsieve service -i eth0 -w "https://hooks.slack.com/services/XXX"
    """
    import pwd
    import subprocess
    import shutil

    if os.geteuid() != 0:
        raise click.ClickException("Run 'netsieve service' with sudo to install a system service.")
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        account = pwd.getpwnam(sudo_user)
        user_home = account.pw_dir
        service_user = account.pw_name
    else:
        user_home = os.path.expanduser("~")
        service_user = "root"

    netsieve_path = shutil.which("netsieve")
    if not netsieve_path:
        raise click.ClickException("Could not find the netsieve executable in PATH.")

    def quote_systemd_arg(value):
        value = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
        return f'"{value}"'

    command = [netsieve_path, "detect"]
    if interface:
        command.extend(["--interface", interface])
    if webhook:
        command.extend(["--webhook", webhook])
    exec_start = " ".join(quote_systemd_arg(arg) for arg in command)

    service_content = f"""[Unit]
Description=NetSieve - Network attack detection service
After=network.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=always
RestartSec=5
User={service_user}
Environment=HOME={quote_systemd_arg(user_home)}
Environment=PYTHONUNBUFFERED=1
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
"""

    service_path = "/etc/systemd/system/netsieve.service"
    try:
        with open(service_path, "w", encoding="utf-8") as f:
            f.write(service_content)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, check=True)
        subprocess.run(
            ["systemctl", "enable", "--now", "netsieve"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None) or str(error)
        raise click.ClickException(f"Failed to install/start the service: {detail.strip()}") from error

    console.print(Text("\n  \u2713 NetSieve service installed and started.", style="bold green"))
    console.print(Text("\n  Manage it with:", style="bold"))
    console.print(Text("    sudo systemctl start netsieve       (start)", style="cyan"))
    console.print(Text("    sudo systemctl stop netsieve        (stop)", style="cyan"))
    console.print(Text("    sudo systemctl status netsieve      (check)", style="cyan"))
    console.print(Text("    journalctl -u netsieve -f           (live logs)", style="cyan"))
    console.print(Text("    sudo netsieve service-remove        (remove)", style="cyan"))
    console.print()

@_cli.command(name="service-remove")
def service_remove():
    """Remove the NetSieve background service completely.

    Stops the service, disables auto-start on boot, deletes the
    service file. After this, netsieve is no longer running in
    the background.

    Your blocklist (~/.netsieve_blocked.json) is NOT deleted.
    Your captures (~/.captures/) are NOT deleted.

    After removing, if you want to run detect manually again:
      sudo netsieve detect -d 30

    Example:
      sudo netsieve service-remove
    """
    import subprocess

    if os.geteuid() != 0:
        raise click.ClickException("Run 'netsieve service-remove' with sudo.")

    service_path = "/etc/systemd/system/netsieve.service"
    try:
        if os.path.exists(service_path):
            if subprocess.run(["systemctl", "is-active", "--quiet", "netsieve"]).returncode == 0:
                subprocess.run(["systemctl", "stop", "netsieve"], capture_output=True, text=True, check=True)
            if subprocess.run(["systemctl", "is-enabled", "--quiet", "netsieve"]).returncode == 0:
                subprocess.run(["systemctl", "disable", "netsieve"], capture_output=True, text=True, check=True)
            os.remove(service_path)
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None) or str(error)
        raise click.ClickException(f"Failed to remove the service: {detail.strip()}") from error

    console.print(Text("\n  \u2713 NetSieve service removed.", style="bold green"))
    console.print(Text("  Run 'sudo netsieve detect' to watch manually.", style="dim"))
    console.print()

def main():
    show_banner()
    _cli()

if __name__ == "__main__":
    main()   