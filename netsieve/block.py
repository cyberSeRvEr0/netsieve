import subprocess
import json
import ipaddress
from pathlib import Path
from rich.console import Console
from rich.text import Text

console = Console()

import os
import pwd

def _get_home():
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()

BLOCKLIST_FILE = _get_home() / ".netsieve_blocked.json"   

def _validated_ip(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        console.print(Text(f"  Invalid IP address: {ip}", style="red"))
        return None
    return str(address), "ip6tables" if address.version == 6 else "iptables"

def _load_blocked():
    if BLOCKLIST_FILE.exists():
        return json.loads(BLOCKLIST_FILE.read_text())
    return []

def _save_blocked(blocked):
    BLOCKLIST_FILE.write_text(json.dumps(blocked, indent=2))

def block_ip(ip):
    validated = _validated_ip(ip)
    if not validated:
        return False
    ip, firewall = validated
    blocked = _load_blocked()
    check = subprocess.run(
        [firewall, "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    if check.returncode == 0:
        if ip not in blocked:
            blocked.append(ip)
            try:
                _save_blocked(blocked)
            except OSError as error:
                console.print(Text(f"  Rule exists, but blocklist could not be saved: {error}", style="red"))
                return False
        console.print(Text(f"  {ip} is already blocked.", style="yellow"))
        return True

    r = subprocess.run(
        [firewall, "-A", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        console.print(Text(f"  Failed: {r.stderr.strip()}", style="red"))
        return False

    if ip not in blocked:
        blocked.append(ip)
    try:
        _save_blocked(blocked)
    except OSError as error:
        console.print(Text(f"  Firewall rule added, but blocklist could not be saved: {error}", style="red"))
        return False
    console.print(Text(f"  ✓ {ip} is now blocked. All traffic from this IP will be dropped.", style="green"))
    return True

def unblock_ip(ip):
    validated = _validated_ip(ip)
    if not validated:
        return False
    ip, firewall = validated
    blocked = _load_blocked()
    if ip not in blocked:
        console.print(Text(f"  {ip} is not in the blocklist.", style="yellow"))
        return False

    while True:
        check = subprocess.run(
            [firewall, "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if check.returncode != 0:
            if any(message in (check.stderr or "").lower() for message in (
                "permission denied", "operation not permitted", "must be root"
            )):
                console.print(Text(f"  Failed: {check.stderr.strip()}", style="red"))
                return False
            break
        result = subprocess.run(
            [firewall, "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            console.print(Text(f"  Failed: {result.stderr.strip()}", style="red"))
            return False

    blocked.remove(ip)
    try:
        _save_blocked(blocked)
    except OSError as error:
        console.print(Text(f"  Firewall rule removed, but blocklist could not be saved: {error}", style="red"))
        return False
    console.print(Text(f"  ✓ {ip} has been unblocked.", style="green"))
    return True

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
    restored = 0
    failures = []
    for ip in blocked:
        validated = _validated_ip(ip)
        if not validated:
            failures.append(ip)
            continue
        canonical_ip, firewall = validated
        check = subprocess.run(
            [firewall, "-C", "INPUT", "-s", canonical_ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if check.returncode == 0:
            restored += 1
            continue
        result = subprocess.run(
            [firewall, "-A", "INPUT", "-s", canonical_ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            restored += 1
        else:
            failures.append(f"{ip}: {result.stderr.strip()}")
    if failures:
        console.print(Text(f"  Failed to restore: {'; '.join(failures)}", style="red"))
    if restored:
        console.print(Text(f"  Restored/verified {restored} block(s) from blocklist.", style="green"))
    return not failures