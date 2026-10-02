import time
from rich.console import Console
from rich.text import Text
from netsieve.flags import check_payload
from netsieve.webhook import send_webhook, format_alert

console = Console()

def run_detect(interface=None, duration=None, webhook_url=None, auto_block=False, auto_block_threshold=3):
    console.print(Text("  Watching for incoming attacks...", style="bold yellow"))
    console.print(Text("  Ctrl+C to stop.\n", style="dim"))

    try:
        from scapy.all import sniff, IP, TCP, UDP, Raw
    except ImportError:
        console.print("[red]scapy not installed. Run: pip install scapy[/]")
        return

    alerts = []
    seen = set() 

    from collections import Counter
    ip_alert_count = Counter()
    from netsieve.anomaly import AnomalyDetector
    anomaly = AnomalyDetector()     

    def handle_packet(pkt):
        if IP not in pkt or Raw not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        raw = pkt[Raw].load
        if len(raw) < 20:
            return

        try:
            text = raw.decode("utf-8", errors="ignore")
        except:
            return

        # Skip binary/encrypted payloads — only check readable text
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t ')
        if len(text) == 0 or printable / len(text) < 0.8:
            return   

        threats = check_payload(text)
        if threats:
            dedup_key = (src_ip, dst_ip, tuple(threats))
            if dedup_key in seen:
                return
            seen.add(dedup_key)   
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

            # Anomaly detection
            port_num = port.replace(":", "") if port else None
            if port_num:
                anomaly.record(src_ip, int(port_num))
            anomaly_flags = anomaly.check(src_ip)
            if anomaly_flags:
                alert["threats"].extend(anomaly_flags)

            # Auto-block
            ip_alert_count[src_ip] += 1
            if auto_block and ip_alert_count[src_ip] >= auto_block_threshold:
                from netsieve.block import block_ip
                console.print(Text(f"  [AUTO-BLOCK] {src_ip} exceeded threshold. Blocking.", style="bold red"))
                block_ip(src_ip)
                ip_alert_count[src_ip] = 0   
                
            console.print()
            console.print(Text(f"  [ALERT] {alert['time']}", style="bold red"))
            console.print(Text(f"    From: {src_ip}{port} → {dst_ip}", style="red"))
            console.print(Text(f"    Threat: {', '.join(threats)}", style="bold red"))
            console.print(Text(f"    Data: {alert['snippet']}", style="dim"))
            console.print()

            if webhook_url:
                title, msg = format_alert(alert)
                send_webhook(webhook_url, title, msg)

    try:
        if duration:
            sniff(iface=interface, timeout=duration, prn=handle_packet, store=0)
        else:
            sniff(iface=interface, prn=handle_packet, store=0)
    except KeyboardInterrupt:
        pass

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