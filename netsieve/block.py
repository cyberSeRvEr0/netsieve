import subprocess
import json
from pathlib import Path
from rich.console import Console
from rich.text import Text

console = Console()

BLOCKLIST_FILE = Path.home() / ".netsieve_blocked.json"

def _load_blocked():
    if BLOCKLIST_FILE.exists():
        return json.loads(BLOCKLIST_FILE.read_text())
    return []

def _save_blocked(blocked):
    BLOCKLIST_FILE.write_text(json.dumps(blocked, indent=2))

def block_ip(ip):
    blocked = _load_blocked()
    if ip in blocked:
        console.print(Text(f"  {ip} is already blocked.", style="yellow"))
        return

    r = subprocess.run(
        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        console.print(Text(f"  Failed: {r.stderr.strip()}", style="red"))
        return

    blocked.append(ip)
    _save_blocked(blocked)
    console.print(Text(f"  ✓ {ip} is now blocked. All traffic from this IP will be dropped.", style="green"))

def unblock_ip(ip):
    blocked = _load_blocked()
    if ip not in blocked:
        console.print(Text(f"  {ip} is not in the blocklist.", style="yellow"))
        return

    r = subprocess.run(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        console.print(Text(f"  Warning: {r.stderr.strip()}", style="yellow"))

    blocked.remove(ip)
    _save_blocked(blocked)
    console.print(Text(f"  ✓ {ip} has been unblocked.", style="green"))

def list_blocked():
    blocked = _load_blocked()
    if not blocked:
        console.print(Text("  No IPs currently blocked.", style="dim"))
        return
    console.print(Text(f"  Blocked IPs ({len(blocked)}):", style="bold"))
    for ip in blocked:
        console.print(Text(f"    {ip}", style="red"))

def restore_blocked():
    blocked = _load_blocked()
    for ip in blocked:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
    if blocked:
        console.print(Text(f"  Restored {len(blocked)} block(s) from blocklist.", style="green"))   