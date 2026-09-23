import time
from rich.console import Console
from rich.text import Text
from netsieve.flags import check_payload

console = Console()

def run_detect(interface=None, duration=None):
    console.print(Text("  Watching for incoming attacks...", style="bold yellow"))
    console.print(Text("  Ctrl+C to stop.\n", style="dim"))

    try:
        from scapy.all import sniff, IP, TCP, UDP, Raw
    except ImportError:
        console.print("[red]scapy not installed. Run: pip install scapy[/]")
        return

    alerts = []

    def handle_packet(pkt):
        if IP not in pkt or Raw not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Only care about INCOMING (dst is our IP)
        # We check all for simplicity

        raw = pkt[Raw].load
        if len(raw) < 20:
            return

        try:
            text = raw.decode("utf-8", errors="ignore")
        except:
            return

        threats = check_payload(text)
        if threats:
            port = ""
            if TCP in pkt:
                port = f":{pkt[TCP].dport}"
            elif UDP in pkt:
                port = f":{pkt[UDP].dport}"

            alert = {
                "time": time.strftime("%H:%M:%S"),
                "src": src_ip,
                "dst": dst_ip,
                "port": port,
                "threats": threats,
                "snippet": text[:80],
            }
            alerts.append(alert)

            # Print alert immediately
            console.print()
            console.print(Text(f"  [ALERT] {alert['time']}", style="bold red"))
            console.print(Text(f"    From: {src_ip}{port} → {dst_ip}", style="red"))
            console.print(Text(f"    Threat: {', '.join(threats)}", style="bold red"))
            console.print(Text(f"    Data: {alert['snippet']}", style="dim"))
            console.print()

    try:
        if duration:
            sniff(iface=interface, timeout=duration, prn=handle_packet, store=0)     
        else:
            sniff(iface=interface, prn=handle_packet, store=0)   
    except KeyboardInterrupt:
        pass

    # Summary
    console.print()
    if alerts:
        unique_ips = set(a["src"] for a in alerts)
        console.print(Text(f"  Total alerts: {len(alerts)}", style="bold"))
        console.print(Text(f"  Attacking IPs: {', '.join(unique_ips)}", style="bold red"))
        console.print()
        console.print(Text("  Now trace them:", style="bold cyan"))
        for ip in unique_ips:
            console.print(Text(f"    netsieve trace {ip}", style="cyan"))
    else:
        console.print(Text("  No attacks detected.", style="green"))   