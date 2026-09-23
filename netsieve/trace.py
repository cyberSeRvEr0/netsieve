import socket
import subprocess
import requests
from rich.console import Console
from rich.panel import Panel

console = Console()

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def geoip_lookup(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
            }
    except:
        pass
    return None

def threat_intel_check(ip):
    try:
        r = requests.get(
            "https://www.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Accept": "application/json"},
            timeout=10
        )
        data = r.json()
        if data.get("data"):
            return {
                "score": data["data"].get("abuseConfidenceScore", 0),
                "reports": data["data"].get("totalReports", 0),
            }
    except:
        pass
    return None

def traceroute(ip):
    try:
        r = subprocess.run(["traceroute", "-m", "20", ip], capture_output=True, text=True, timeout=30)
        return r.stdout
    except:
        return "traceroute not available"

def trace_ip(ip):
    console.print(f"\n[bold cyan]TRACING {ip}[/]\n")

    rdns = reverse_dns(ip)
    console.print(f"  Reverse DNS:  {rdns or 'None'}")

    geo = geoip_lookup(ip)
    if geo:
        console.print(f"  Country:      {geo['country']}")
        console.print(f"  City:         {geo['city']}")
        console.print(f"  ISP:          {geo['isp']}")
        console.print(f"  Organization: {geo['org']}")
    else:
        console.print(f"  GeoIP:        Unavailable")

    console.print(f"\n  [bold]Threat Intelligence:[/]")
    intel = threat_intel_check(ip)
    if intel:
        score = intel["score"]
        style = "red" if score > 50 else "yellow" if score > 20 else "green"
        console.print(f"    AbuseIPDB: Score {score}/100 | Reports: {intel['reports']}")
    else:
        console.print(f"    No reports found.")

    console.print(f"\n  [bold]Route:[/]")
    route = traceroute(ip)
    for line in route.strip().splitlines()[:15]:
        console.print(f"    [dim]{line}[/]")

    if geo:
        verdict = f"Source: {geo['city']}, {geo['country']} | ISP: {geo['isp']}"
    else:
        verdict = "Source: Unknown"

    if intel and intel["score"] > 50:
        console.print(Panel(f"[bold red]HIGH RISK[/] — {verdict}", border_style="red"))
    else:
        console.print(Panel(f"[bold yellow]REVIEW[/] — {verdict}", border_style="yellow"))   