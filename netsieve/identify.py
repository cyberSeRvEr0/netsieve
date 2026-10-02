import requests
import socket
import re
from rich.console import Console
from rich.panel import Panel

console = Console()

def _asn_lookup(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = r.json()
        if data.get("status") == "success":
            asn = data.get("as", "")
            org = data.get("org", "")
            m = re.match(r"(AS\d+)\s+(.*)", org)
            if m:
                return {"asn": m.group(1), "name": m.group(2)}
            return {"asn": asn, "name": org}
        return None
    except:
        return None   

def _vpn_check(ip):
    """Check against VPNBlocklist (free JSON)."""
    try:
        r = requests.get("https://raw.githubusercontent.com/PH0SPh0X/VPN-Blocklist/master/data/vpn_cidr.json", timeout=10)
        cidrs = r.json()
        import ipaddress
        target = ipaddress.ip_address(ip)
        for cidr in cidrs:
            if target in ipaddress.ip_network(cidr, strict=False):
                return True
    except:
        pass
    return False

def _tor_exit_check(ip):
    try:
        r = requests.get("https://check.torproject.org/exit-addresses", timeout=5)
        return ip in r.text
    except:
        return False

def _shodan_lookup(ip, api_key=None):
    if not api_key:
        return None
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=10
        )
        data = r.json()
        if "error" in data:
            return None
        ports = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        os_info = data.get("os", "")
        return {
            "ports": ports[:10],
            "hostnames": hostnames[:5],
            "os": os_info,
        }
    except:
        return None

def _passive_dns(ip):
    try:
        r = requests.get(
            f"https://api.mnemonic.no/pdns/v3/records?domain={ip}&limit=10",
            timeout=5
        )
        data = r.json()
        return data.get("records", [])
    except:
        return []

def _whois(ip):
    try:
        import whois
        w = whois.whois(ip)
        return {
            "created": str(w.get("creation_date", "Unknown")),
            "org": w.get("org", "Unknown"),
            "registrar": w.get("registrar", "Unknown"),
        }
    except:
        return None

def identify_ip(ip, shodan_key=None):
    console.print(f"\n[bold cyan]IDENTIFYING {ip}[/]\n")

    # ASN
    asn_info = _asn_lookup(ip)
    if asn_info:
        console.print(f"  ASN:          {asn_info['asn']} ({asn_info['name']})")

    # VPN / Tor
    is_vpn = _vpn_check(ip)
    is_tor = _tor_exit_check(ip)
    if is_tor:
        console.print(f"  Type:         [bold red]TOR EXIT NODE[/]")
    elif is_vpn:
        console.print(f"  Type:         [bold yellow]VPN / Proxy[/]")
    else:
        console.print(f"  Type:         [green]Direct / Datacenter[/]")

    # Shodan
    shodan = _shodan_lookup(ip, shodan_key)
    if shodan:
        console.print(f"\n  [bold]Shodan:[/]")
        console.print(f"    Ports:      {shodan['ports']}")
        console.print(f"    Hostnames:  {shodan['hostnames']}")
        if shodan['os']:
            console.print(f"    OS:         {shodan['os']}")

    # Passive DNS
    pdns = _passive_dns(ip)
    if pdns:
        console.print(f"\n  [bold]Passive DNS:[/] {len(pdns)} historical record(s)")
        for rec in pdns[:5]:
            console.print(f"    {rec.get('type', '?')}  {rec.get('data', '?')}  ({rec.get('first', '?')})")

    # WHOIS
    whois = _whois(ip)
    if whois:
        console.print(f"\n  [bold]WHOIS:[/]")
        console.print(f"    Created:    {whois['created']}")
        console.print(f"    Org:        {whois['org']}")

    # Verdict
    if is_tor:
        verdict = "Attacker is behind Tor. Real IP unobtainable without ISP/legal action."
        style = "red"
    elif is_vpn:
        provider = asn_info['name'] if asn_info else "unknown"
        verdict = f"Attacker is behind a VPN ({provider}). Real IP requires ISP cooperation."
        style = "yellow"
    else:
        verdict = "IP appears to be a direct or datacenter address. Full trace available."
        style = "green"

    console.print()
    console.print(Panel(f"[bold]VERDICT:[/] {verdict}", border_style=style))   