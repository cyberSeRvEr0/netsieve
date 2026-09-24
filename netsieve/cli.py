import click
import os
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

    # Create symlink so 'sudo netsieve' works
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        user_home = pwd.getpwnam(sudo_user).pw_dir
    else:
        user_home = os.path.expanduser("~")

    netsieve_bin = os.path.join(user_home, ".local", "bin", "netsieve")
    link_path = "/usr/local/bin/netsieve"
    if os.path.exists(netsieve_bin) and not os.path.exists(link_path):
        subprocess.run(["ln", "-s", netsieve_bin, link_path], capture_output=True)
        console.print(Text(f"  \u2713 symlinked to {link_path} (sudo now works)", style="green"))

    console.print(Text("\n  All dependencies ready.", style="bold green"))
    console.print()   

@_cli.command()
@click.option("--interface", "-i", default=None, help="Network interface (e.g. eth0, wlan0). Default: auto.")
@click.option("--duration", "-d", default=None, type=int, help="Seconds to capture. Default: runs until Ctrl+C.")
@click.option("--output", "-o", default="~/captures", help="Folder to save .txt files. Default: ~/captures/")
def capture(interface, duration, output):
    """Capture all network traffic, decode payloads, save as readable .txt files.

    Every conversation (flow) between two IPs is saved as a separate file.
    Files are organized by date: ~/captures/2026-09-24/

    After it finishes, check results:
      ls ~/captures/2026-09-24/
      cat ~/captures/2026-09-24/10_0_0_1_to_93_184_216_34_TCP_443.txt

    Examples:
      sudo netsieve capture -d 30              Capture for 30 seconds
      sudo netsieve capture -i eth0 -d 60      Capture on eth0 for 60 seconds
      sudo netsieve capture -o ~/evidence/     Save to a custom folder
    """
    from netsieve.capture import NetSieve
    ns = NetSieve(interface=interface, output_dir=output)
    ns.run(duration=duration)

@_cli.command()
@click.option("--interface", "-i", default=None, help="Network interface to watch. Default: auto.")
@click.option("--duration", "-d", default=None, type=int, help="Seconds to watch. Default: runs until Ctrl+C.")
@click.option("--webhook", "-w", default=None, help="URL to send alerts (Slack, Discord, ntfy.sh).")
def detect(interface, duration, webhook):
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
      sudo systemctl status netsieve         Check if running
      sudo systemctl stop netsieve           Stop it
      journalctl -u netsieve -f              Watch live logs

    Examples:
      sudo netsieve detect                   Watch until Ctrl+C
      sudo netsieve detect -d 60             Watch for 60 seconds
      sudo netsieve detect -w "https://ntfy.sh/my-app"   + phone alerts
    """
    from netsieve.detect import run_detect
    run_detect(interface=interface, duration=duration, webhook_url=webhook)   

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
    block_ip(ip)

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
    unblock_ip(ip)

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
    restore_blocked()      

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

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        user_home = pwd.getpwnam(sudo_user).pw_dir
    else:
        user_home = os.path.expanduser("~")

    netsieve_path = "/usr/local/bin/netsieve"   
    webhook_flag = f' -w "{webhook}"' if webhook else ""
    iface_flag = f' -i {interface}' if interface else ""

    service_content = f"""[Unit]
Description=NetSieve - Network attack detection service
After=network.target

[Service]
Type=simple
ExecStart={netsieve_path} detect{webhook_flag}{iface_flag}
Restart=always
RestartSec=5
User={sudo_user or "root"}

[Install]
WantedBy=multi-user.target
"""

    service_path = "/etc/systemd/system/netsieve.service"
    with open(service_path, "w") as f:
        f.write(service_content)

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    subprocess.run(["systemctl", "enable", "netsieve"], capture_output=True)
    subprocess.run(["systemctl", "start", "netsieve"], capture_output=True)

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

    subprocess.run(["systemctl", "stop", "netsieve"], capture_output=True)
    subprocess.run(["systemctl", "disable", "netsieve"], capture_output=True)

    service_path = "/etc/systemd/system/netsieve.service"
    if os.path.exists(service_path):
        os.remove(service_path)

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

    console.print(Text("\n  \u2713 NetSieve service removed.", style="bold green"))
    console.print(Text("  Run 'sudo netsieve detect' to watch manually.", style="dim"))
    console.print()

def main():
    show_banner()
    _cli()

if __name__ == "__main__":
    main()   