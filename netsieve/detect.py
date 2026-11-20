import time
from collections import Counter

from rich.console import Console
from rich.text import Text

from netsieve.config import load_config
from netsieve.flags import check_payload
from netsieve.webhook import format_alert, send_webhook

console = Console()


def run_detect(interface=None, duration=None, webhook_url=None, auto_block=None, auto_block_threshold=None):
    if duration is not None and duration < 1:
        raise ValueError("duration must be a positive number of seconds")
    config = load_config()
    interface = interface if interface is not None else config["interface"]
    webhook_url = webhook_url if webhook_url is not None else config["webhook"]
    auto_block = auto_block if auto_block is not None else config["auto_block"]
    auto_block_threshold = (
        auto_block_threshold
        if auto_block_threshold is not None
        else config["auto_block_threshold"]
    )
    if not isinstance(auto_block_threshold, int) or auto_block_threshold < 1:
        raise ValueError("auto_block_threshold must be a positive integer")

    console.print(Text("  Watching for incoming attacks...", style="bold yellow"))
    console.print(Text("  Ctrl+C to stop.\n", style="dim"))

    try:
        from scapy.all import IP, TCP, UDP, Raw, sniff
    except ImportError:
        console.print("[red]scapy not installed. Run: pip install scapy[/]")
        return

    total_alerts = 0
    attacking_ips = set()
    seen_payload_alerts = {}
    reported_anomalies = {}
    ip_alert_count = Counter()
    last_alert_by_ip = {}
    last_connection_event = {}
    state_cleanup_at = 0.0
    dedup_ttl = 300

    from netsieve.anomaly import AnomalyDetector
    anomaly = AnomalyDetector()

    def emit_alert(src_ip, dst_ip, port, threats, snippet, now):
        nonlocal total_alerts
        alert = {
            "time": time.strftime("%H:%M:%S"),
            "src": src_ip,
            "dst": dst_ip,
            "port": f":{port}" if port else "",
            "threats": threats,
            "snippet": snippet[:80],
        }
        total_alerts += 1
        attacking_ips.add(src_ip)
        last_alert_by_ip[src_ip] = now

        if auto_block:
            ip_alert_count[src_ip] += 1
            if ip_alert_count[src_ip] >= auto_block_threshold:
                from netsieve.block import block_ip
                console.print(Text(f"  [AUTO-BLOCK] {src_ip} exceeded threshold. Blocking.", style="bold red"))
                if block_ip(src_ip):
                    ip_alert_count[src_ip] = 0

        console.print()
        console.print(Text(f"  [ALERT] {alert['time']}", style="bold red"))
        console.print(Text(f"    From: {src_ip}{alert['port']} → {dst_ip}", style="red"))
        console.print(Text(f"    Threat: {', '.join(threats)}", style="bold red"))
        if alert["snippet"]:
            console.print(Text(f"    Data: {alert['snippet']}", style="dim"))
        console.print()

        if webhook_url:
            title, message = format_alert(alert)
            send_webhook(webhook_url, title, message)

    def handle_packet(pkt):
        nonlocal state_cleanup_at
        if IP not in pkt:
            return

        now = time.monotonic()
        if now - state_cleanup_at >= 60:
            for state in (last_connection_event, seen_payload_alerts, reported_anomalies):
                ttl = 180 if state is last_connection_event else dedup_ttl
                expired = [key for key, seen_at in state.items() if now - seen_at > ttl]
                for key in expired:
                    del state[key]
            expired_alert_ips = [
                ip for ip, seen_at in last_alert_by_ip.items()
                if now - seen_at > dedup_ttl
            ]
            for ip in expired_alert_ips:
                del last_alert_by_ip[ip]
                ip_alert_count.pop(ip, None)
                attacking_ips.discard(ip)
            state_cleanup_at = now

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        port = None
        transport = None

        if TCP in pkt:
            transport = pkt[TCP]
            port = int(transport.dport)
            flags = int(transport.flags)
            connection_event = bool(flags & 0x02) and not bool(flags & 0x10)
            event_interval = 2.0
        elif UDP in pkt:
            transport = pkt[UDP]
            port = int(transport.dport)
            connection_event = True
            event_interval = 2.0
        else:
            connection_event = False
            event_interval = 0

        if connection_event:
            event_key = (
                src_ip,
                dst_ip,
                transport.__class__.__name__,
                int(transport.sport),
                int(transport.dport),
            )
            if now - last_connection_event.get(event_key, float("-inf")) >= event_interval:
                anomaly.record(src_ip, port)
                last_connection_event[event_key] = now

        anomaly_flags = anomaly.check(src_ip)
        new_anomaly_flags = []
        for flag in anomaly_flags:
            category = flag.split(" (", 1)[0]
            anomaly_key = (src_ip, category)
            if now - reported_anomalies.get(anomaly_key, float("-inf")) > dedup_ttl:
                reported_anomalies[anomaly_key] = now
                new_anomaly_flags.append(flag)
        if new_anomaly_flags:
            emit_alert(src_ip, dst_ip, port, new_anomaly_flags, "", now)

        if Raw not in pkt:
            return

        raw = pkt[Raw].load
        if len(raw) < 20:
            return
        text = raw.decode("utf-8", errors="ignore")
        printable = sum(1 for char in text if char.isprintable() or char in "\n\r\t ")
        if not text or printable / len(text) < 0.8:
            return

        threats = check_payload(text)
        if not threats:
            return
        dedup_key = (src_ip, dst_ip, tuple(threats))
        if now - seen_payload_alerts.get(dedup_key, float("-inf")) <= dedup_ttl:
            return
        seen_payload_alerts[dedup_key] = now
        emit_alert(src_ip, dst_ip, port, threats, text, now)

    try:
        if duration is not None:
            sniff(iface=interface, timeout=duration, prn=handle_packet, store=0)
        else:
            sniff(iface=interface, prn=handle_packet, store=0)
    except PermissionError:
        console.print("[red]Permission denied. Run with sudo or grant CAP_NET_RAW.[/]")
        return
    except KeyboardInterrupt:
        pass

    console.print()
    if total_alerts:
        console.print(Text(f"  Total alerts: {total_alerts}", style="bold"))
        console.print(Text(f"  Attacking IPs: {', '.join(attacking_ips)}", style="bold red"))
        console.print()
        console.print(Text("  Now trace them:", style="bold cyan"))
        for ip in attacking_ips:
            console.print(Text(f"    netsieve trace {ip}", style="cyan"))
    else:
        console.print(Text("  No attacks detected.", style="green"))
